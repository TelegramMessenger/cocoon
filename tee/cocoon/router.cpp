#include "cocoon/FwdProxy.h"
#include "cocoon/CertManager.h"
#include "cocoon/AttestationCache.h"
#include "ProxyConfig.h"
#include "RevProxy.h"
#include "common/bitstring.h"
#include "td/utils/logging.h"
#include "td/utils/OptionParser.h"
#include "td/utils/as.h"
#include "td/utils/port/signals.h"
#include "tdactor/td/actor/actor.h"
#include <iostream>
#include <map>
#include <set>

using cocoon::PolicyConfig;
using cocoon::PortConfig;
using cocoon::ProxyConfig;

namespace {

// Configuration validation constants
constexpr int MIN_PORT = 1024;
constexpr int MAX_PORT = 65535;

// Validate port number
td::Status validate_port(int port) {
  if (port < MIN_PORT || port > MAX_PORT) {
    return td::Status::Error(PSLICE() << "Port must be between " << MIN_PORT << " and " << MAX_PORT << ", got "
                                      << port);
  }
  return td::Status::OK();
}

template <class T>
td::Status parse_list_of_hex(td::Slice list, std::vector<T> &hashes) {
  auto hash_parts = td::full_split(list, ',');
  for (const auto &hash_str : hash_parts) {
    TRY_RESULT(image_hash_bytes, td::hex_decode(hash_str));
    if (image_hash_bytes.size() != sizeof(T)) {
      return td::Status::Error(PSLICE() << "hash must be" << sizeof(T) * 2 << " hex chars (" << sizeof(T)
                                        << " bytes), got " << hash_str.size());
    }
    T hash = td::as<T>(image_hash_bytes.data());
    hashes.push_back(hash);
  }
  return td::Status::OK();
}

// Create policies from configuration
std::map<std::string, tdx::PolicyRef, std::less<>> create_policies_from_config(const ProxyConfig &config) {
  std::map<std::string, tdx::PolicyRef, std::less<>> policies;

  // Create shared attestation cache for all TDX policies
  auto attestation_cache = cocoon::AttestationCache::create(cocoon::AttestationCache::Config{.max_entries = 10000});
  LOG(INFO) << "Initialized attestation cache (max_entries=10000)";

  // Add custom policies from configuration
  for (const auto &policy_config : config.policies) {
    tdx::TdxInterfaceRef tdx_interface = nullptr;

    // Create appropriate TDX interface based on type
    if (policy_config.type == "any") {
      tdx_interface = nullptr;
    } else if (policy_config.type == "fake_tdx") {
      tdx_interface = tdx::TdxInterface::create_fake();
    } else if (policy_config.type == "tdx") {
      auto base_tdx = tdx::TdxInterface::create();
      // Wrap with caching layer
      tdx_interface = tdx::TdxInterface::add_cache(base_tdx, attestation_cache);
    } else {
      LOG(WARNING) << "Unknown policy type: " << policy_config.type << ", using 'any'";
      tdx_interface = nullptr;
    }

    // Create policy with full configuration
    policies[policy_config.name] = tdx::Policy::make(tdx_interface, policy_config.tdx_config);
    LOG(INFO) << "Created policy '" << policy_config.name << "' type=" << policy_config.type
              << " config=" << policy_config.tdx_config;
  }

  return policies;
}

// Command line argument parsing
struct CliArgs {
  std::string config_file;
  std::vector<PolicyConfig> cli_policies;
  std::vector<PortConfig> cli_ports;
  std::string cert_base_name;
  int threads = 0;
  bool generate_config = false;
  bool default_serialize_info = false;
  std::vector<td::UInt384> global_collateral_root_hashes;  // Applied to all policies
  td::int32 global_pow_difficulty = 20;
  td::int32 global_max_pow_difficulty = 28;
};

// Parse policy spec: NAME:TYPE[:image-hash]
td::Status parse_policy_spec(td::Slice spec, PolicyConfig &policy_config) {
  auto parts = td::full_split(spec, ':');
  if (parts.size() < 2) {
    return td::Status::Error("Policy spec must be: name:type[:image-hash]");
  }

  policy_config.name = parts[0].str();
  policy_config.type = parts[1].str();

  if (policy_config.type != "any" && policy_config.type != "fake_tdx" && policy_config.type != "tdx") {
    return td::Status::Error(PSLICE() << "Invalid policy type: " << policy_config.type);
  }

  // Optional image hashes (comma-separated)
  if (parts.size() >= 3 && !parts[2].empty()) {
    TRY_STATUS(parse_list_of_hex(parts[2], policy_config.tdx_config.allowed_image_hashes));
  }

  return td::Status::OK();
}

// Helper to parse policy[:image-hash] and create inline policy if needed
// Handles both user-defined policy names and built-in types (any/tdx/fake_tdx)
td::Status parse_policy_and_image(td::Slice policy_spec, PortConfig &port_config,
                                  std::vector<PolicyConfig> &inline_policies) {
  auto policy_parts = td::full_split(policy_spec, ':');
  std::string policy_name = policy_parts[0].str();

  // If no image hash, just use the policy name (either user-defined or built-in)
  if (policy_parts.size() < 2 || policy_parts[1].empty()) {
    port_config.policy_name = policy_name;
    return td::Status::OK();
  }

  // Determine policy type:
  // If it's a built-in name (any/tdx/fake_tdx), use it as TYPE
  // Otherwise, it's a user-defined policy name - error (can't add image hash to named policy inline)
  std::string policy_type;
  if (policy_name == "any" || policy_name == "tdx" || policy_name == "fake_tdx") {
    policy_type = policy_name;
  } else {
    return td::Status::Error(PSLICE() << "Cannot specify image hash for user-defined policy '" << policy_name
                                      << "'. Use --policy " << policy_name << ":type:hash1,hash2,... instead");
  }

  // Parse image hashes
  // Image hashes provided (comma-separated)
  std::vector<td::UInt256> hashes;
  TRY_STATUS(parse_list_of_hex(policy_parts[1], hashes));

  // Create inline policy with unique name
  std::string inline_policy_name = PSTRING() << policy_type << "_inline_" << port_config.port;
  PolicyConfig inline_policy;
  inline_policy.name = inline_policy_name;
  inline_policy.type = policy_type;
  inline_policy.tdx_config.allowed_image_hashes = std::move(hashes);
  inline_policies.push_back(inline_policy);

  port_config.policy_name = inline_policy_name;
  return td::Status::OK();
}

// Generic parser: SPEC@POLICY[:image-hash]
td::Status parse_proxy_spec(td::Slice spec, td::Slice type_name, td::CSlice expected_format, bool requires_destination,
                            PortConfig &port_config, std::vector<PolicyConfig> &inline_policies) {
  auto at_parts = td::full_split(spec, '@');
  if (at_parts.size() != 2) {
    return td::Status::Error(PSLICE() << type_name << " spec must be: " << expected_format);
  }

  auto dest_parts = td::full_split(at_parts[0], ':');

  // Validate format based on proxy type
  if (requires_destination) {
    if (dest_parts.size() != 3) {
      return td::Status::Error(PSLICE() << type_name << " spec must be: " << expected_format);
    }
  } else {
    if (dest_parts.size() != 1) {
      return td::Status::Error(PSLICE() << type_name << " spec must be: " << expected_format);
    }
  }

  // Parse listen port (always first)
  TRY_RESULT(port, td::to_integer_safe<int>(dest_parts[0]));
  TRY_STATUS(validate_port(port));
  port_config.port = port;
  port_config.type = type_name.str();

  // Parse destination if required (forward/reverse)
  if (requires_destination) {
    port_config.destination_host = dest_parts[1].str();
    TRY_RESULT(dest_port, td::to_integer_safe<int>(dest_parts[2]));
    TRY_STATUS(validate_port(dest_port));
    port_config.destination_port = dest_port;
  }

  // Parse policy and optional image hash
  TRY_STATUS(parse_policy_and_image(at_parts[1], port_config, inline_policies));
  return td::Status::OK();
}

// Parse SOCKS5 spec: PORT@POLICY[:image-hash]
td::Status parse_socks5_spec(td::Slice spec, PortConfig &port_config, std::vector<PolicyConfig> &inline_policies) {
  return parse_proxy_spec(spec, "socks5", "port@policy[:image-hash]", false, port_config, inline_policies);
}

// Parse forward spec: PORT:HOST:PORT@POLICY[:image-hash]
td::Status parse_forward_spec(td::Slice spec, PortConfig &port_config, std::vector<PolicyConfig> &inline_policies) {
  return parse_proxy_spec(spec, "forward", "port:host:port@policy[:image-hash]", true, port_config, inline_policies);
}

// Parse reverse spec: PORT:HOST:PORT@POLICY[:image-hash]
td::Status parse_reverse_spec(td::Slice spec, PortConfig &port_config, std::vector<PolicyConfig> &inline_policies) {
  return parse_proxy_spec(spec, "reverse", "port:host:port@policy[:image-hash]", true, port_config, inline_policies);
}

// Legacy port spec parser (kept for backward compatibility)
td::Status parse_port_spec(td::Slice spec, PortConfig &port_config) {
  // Format: port:type[:policy[:destination]]
  // Examples:
  //   8116:socks5:any
  //   8117:reverse:tdx:localhost:8118

  auto parts = td::full_split(spec, ':');
  if (parts.size() < 2) {
    return td::Status::Error("Port spec must be in format port:type[:policy[:destination]]");
  }

  TRY_RESULT(port, td::to_integer_safe<int>(parts[0]));
  TRY_STATUS(validate_port(port));
  port_config.port = port;

  port_config.type = parts[1].str();
  if (port_config.type != "socks5" && port_config.type != "reverse" && port_config.type != "forward") {
    return td::Status::Error("Port type must be 'socks5', 'forward', or 'reverse'");
  }

  if (parts.size() > 2) {
    port_config.policy_name = parts[2].str();
  } else {
    port_config.policy_name = "any";
  }

  if (port_config.type == "reverse" || port_config.type == "forward") {
    if (parts.size() < 5) {
      return td::Status::Error("Reverse/forward proxy spec must include destination: port:type:policy:host:dest_port");
    }
    port_config.destination_host = parts[3].str();
    TRY_RESULT(dest_port, td::to_integer_safe<int>(parts[4]));
    TRY_STATUS(validate_port(dest_port));
    port_config.destination_port = dest_port;
  }

  return td::Status::OK();
}

}  // anonymous namespace

int main(int argc, char **argv) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(INFO));
  td::set_default_failure_signal_handler().ensure();

  CliArgs args;

  td::OptionParser option_parser;
  option_parser.add_checked_option('v', "verbosity", "set verbosity level", [&](td::Slice opt) -> td::Status {
    TRY_RESULT(level, td::to_integer_safe<td::int32>(opt));
    SET_VERBOSITY_LEVEL(level);
    return td::Status::OK();
  });

  option_parser.add_checked_option('c', "config", "configuration file path", [&](td::Slice path) {
    args.config_file = path.str();
    return td::Status::OK();
  });

  option_parser.add_checked_option('P', "policy",
                                   "Define named policy: name:type[:image-hash]\n"
                                   "  type: any|fake_tdx|tdx\n"
                                   "  Examples:\n"
                                   "    strict:tdx:abc123...\n"
                                   "    relaxed:any",
                                   [&](td::Slice spec) {
                                     PolicyConfig policy_config;
                                     TRY_STATUS(parse_policy_spec(spec, policy_config));
                                     args.cli_policies.push_back(policy_config);
                                     return td::Status::OK();
                                   });

  option_parser.add_checked_option('S', "socks5",
                                   "SOCKS5 proxy: port@policy[:image-hash]\n"
                                   "  Example: 8116@tdx:abc123...",
                                   [&](td::Slice spec) {
                                     PortConfig port_config;
                                     TRY_STATUS(parse_socks5_spec(spec, port_config, args.cli_policies));
                                     args.cli_ports.push_back(port_config);
                                     return td::Status::OK();
                                   });

  option_parser.add_checked_option('F', "fwd",
                                   "Forward proxy: port:host:port@policy[:image-hash]\n"
                                   "  Example: 8117:backend.com:443@tdx:abc123...",
                                   [&](td::Slice spec) {
                                     PortConfig port_config;
                                     TRY_STATUS(parse_forward_spec(spec, port_config, args.cli_policies));
                                     args.cli_ports.push_back(port_config);
                                     return td::Status::OK();
                                   });

  option_parser.add_checked_option('R', "rev",
                                   "Reverse proxy: port:host:port@policy[:image-hash]\n"
                                   "  Example: 8118:localhost:8080@tdx:abc123...",
                                   [&](td::Slice spec) {
                                     PortConfig port_config;
                                     TRY_STATUS(parse_reverse_spec(spec, port_config, args.cli_policies));
                                     args.cli_ports.push_back(port_config);
                                     return td::Status::OK();
                                   });

  option_parser.add_option('s', "serialize-info", "enable serialization of attestation info by default",
                           [&]() { args.default_serialize_info = true; });

  td::UInt384 default_collateral_hash = td::as<td::UInt384>(
      td::hex_decode("46e403bd34f05a3f2817ab9badcaacc7ffc98e0f261008cd30dae936cace18d5dcf58eef31463613de1570d516200993")
          .move_as_ok()
          .data());
  LOG(ERROR) << "Using default Intel root key ID: " << td::hex_encode(default_collateral_hash.as_slice());
  args.global_collateral_root_hashes.push_back(default_collateral_hash);

  option_parser.add_checked_option(
      '\0', "collateral-hash", "hash1,hash2,... (Intel root key IDs, applied to all policies)", [&](td::Slice spec) {
        args.global_collateral_root_hashes.clear();
        return parse_list_of_hex(spec, args.global_collateral_root_hashes);
      });

  option_parser.add_checked_option('p', "port", "port:type:policy:host:port (legacy format)", [&](td::Slice spec) {
    PortConfig port_config;
    TRY_STATUS(parse_port_spec(spec, port_config));
    args.cli_ports.push_back(port_config);
    return td::Status::OK();
  });

  option_parser.add_checked_option('C', "cert", "base name for certificate", [&](td::Slice name) {
    args.cert_base_name = name.str();
    return td::Status::OK();
  });

  option_parser.add_checked_option('t', "threads", "number of threads (0 = auto)", [&](td::Slice threads_str) {
    TRY_RESULT(threads, td::to_integer_safe<int>(threads_str));
    if (threads < 0) {
      return td::Status::Error("Number of threads must be non-negative");
    }
    args.threads = threads;
    return td::Status::OK();
  });

  option_parser.add_checked_option('d', "pow-difficulty", "PoW difficulty (default: 20)",
                                   [&](td::Slice difficulty_str) {
                                     TRY_RESULT(difficulty, td::to_integer_safe<int>(difficulty_str));
                                     if (difficulty < 0 || difficulty > 64) {
                                       return td::Status::Error("PoW difficulty must be between 0 and 64");
                                     }
                                     args.global_pow_difficulty = static_cast<td::int32>(difficulty);
                                     return td::Status::OK();
                                   });

  option_parser.add_checked_option('m', "max-pow-difficulty", "Max PoW difficulty client will solve (default: 28)",
                                   [&](td::Slice difficulty_str) {
                                     TRY_RESULT(difficulty, td::to_integer_safe<int>(difficulty_str));
                                     if (difficulty < 0 || difficulty > 64) {
                                       return td::Status::Error("Max PoW difficulty must be between 0 and 64");
                                     }
                                     args.global_max_pow_difficulty = static_cast<td::int32>(difficulty);
                                     return td::Status::OK();
                                   });

  option_parser.add_option('g', "generate-config", "generate example configuration file",
                           [&]() { args.generate_config = true; });

  option_parser.add_option('h', "help", "Show this help message", [&]() {
    LOG(PLAIN) << option_parser;
    std::_Exit(0);
  });

  option_parser.set_description("TLS SOCKS5, forward, and reverse proxy with TDX attestation");

  auto r_args = option_parser.run(argc, argv, -1);
  if (r_args.is_error()) {
    LOG(ERROR) << r_args.error();
    LOG(ERROR) << option_parser;
    return 1;
  }

  if (args.generate_config) {
    std::cout << cocoon::generate_example_config() << std::endl;
    return 0;
  }

  // Load configuration
  ProxyConfig config;
  if (!args.config_file.empty()) {
    auto r_config = cocoon::parse_config_file(args.config_file);
    if (r_config.is_error()) {
      LOG(ERROR) << "Failed to load config file: " << r_config.error();
      return 1;
    }
    config = r_config.move_as_ok();
  }
  config.policies.emplace_back(
      PolicyConfig{.name = "tdx", .type = "tdx", .description = "default tdx", .tdx_config = {}, .parameters = {}});
  config.policies.emplace_back(
      PolicyConfig{.name = "any", .type = "any", .description = "accept any", .tdx_config = {}, .parameters = {}});
  config.policies.emplace_back(PolicyConfig{.name = "fake_tdx",
                                            .type = "fake_tdx",
                                            .description = "fake tdx for testing",
                                            .tdx_config = {},
                                            .parameters = {}});

  // Merge CLI policies with config policies
  if (!args.cli_policies.empty()) {
    config.policies.insert(config.policies.end(), args.cli_policies.begin(), args.cli_policies.end());
  }

  // Apply global collateral root hashes to all policies (if specified)
  if (!args.global_collateral_root_hashes.empty()) {
    for (auto &policy_config : config.policies) {
      if (policy_config.type != "tdx") {
        continue;
      }
      policy_config.tdx_config.allowed_collateral_root_hashes.insert(
          policy_config.tdx_config.allowed_collateral_root_hashes.end(), args.global_collateral_root_hashes.begin(),
          args.global_collateral_root_hashes.end());
    }
    LOG(INFO) << "Applied " << args.global_collateral_root_hashes.size()
              << " global collateral root hash(es) to all policies";
  }

  // Override config with CLI arguments
  if (!args.cli_ports.empty()) {
    config.ports = args.cli_ports;
  }

  // Apply global PoW difficulty to all ports (after CLI override)
  for (auto &port_config : config.ports) {
    port_config.pow_difficulty = args.global_pow_difficulty;
    port_config.max_pow_difficulty = args.global_max_pow_difficulty;
  }
  LOG(INFO) << "Applied global PoW difficulty: " << static_cast<int>(args.global_pow_difficulty)
            << ", max: " << static_cast<int>(args.global_max_pow_difficulty);
  if (!args.cert_base_name.empty()) {
    config.cert_base_name = args.cert_base_name;
  }
  if (args.threads > 0) {
    config.threads = args.threads;
  }

  // Apply default serialize_info to ports that didn't explicitly set it
  for (auto &port_config : config.ports) {
    if (!port_config.serialize_info.has_value()) {
      port_config.serialize_info = args.default_serialize_info;
    }
  }

  if (config.ports.empty()) {
    LOG(ERROR) << "No ports configured. Use --port or --config to specify ports.";
    LOG(ERROR) << "Use --generate-config to see example configuration.";
    return 1;
  }

  // Create policies
  auto policies = create_policies_from_config(config);

  // Load certificate
  tdx::CertAndKey cert_and_key;
  if (!config.cert_base_name.empty()) {
    auto r_cert = tdx::load_cert_and_key(config.cert_base_name);
    if (r_cert.is_error()) {
      LOG(ERROR) << "Failed to load certificate: " << r_cert.error();
      return 1;
    }
    cert_and_key = r_cert.move_as_ok();
  } else {
    LOG(WARNING) << "No certificate provided, generating test certificate";
    cert_and_key = tdx::generate_cert_and_key(nullptr);
  }

  td::SharedValue<tdx::CertAndKey> shared_cert(std::move(cert_and_key));

  // Start scheduler
  td::actor::Scheduler sched{{config.threads}};

  sched.run_in_context([&] {
    // Start certificate manager if cert path is provided
    if (!config.cert_base_name.empty()) {
      cocoon::CertManager::Config cert_manager_config;
      cert_manager_config.cert_base_name = config.cert_base_name;
      cert_manager_config.cert_and_key = shared_cert;
      cert_manager_config.check_interval_sec = 60.0;
      td::actor::create_actor<cocoon::CertManager>("CertManager", std::move(cert_manager_config)).release();
    }

    // Create proxy actors for each configured port
    for (const auto &port_config : config.ports) {
      auto policy_it = policies.find(port_config.policy_name);
      if (policy_it == policies.end()) {
        LOG(ERROR) << "Unknown policy: " << port_config.policy_name << " for port " << port_config.port;
        std::_Exit(1);
      }

      LOG(INFO) << "Starting " << port_config;

      if (port_config.type == "socks5") {
        cocoon::FwdProxy::Config fwd_config;
        fwd_config.port_ = port_config.port;
        fwd_config.cert_and_key_ = shared_cert;
        fwd_config.default_policy_ = port_config.policy_name;
        fwd_config.policies_ = policies;  // SOCKS5 can use multiple policies via username
        fwd_config.allow_policy_from_username_ = port_config.allow_policy_from_username;
        fwd_config.skip_socks5 = false;
        fwd_config.serialize_info = port_config.serialize_info.value_or(false);
        fwd_config.max_pow_difficulty = port_config.max_pow_difficulty;

        td::actor::create_actor<cocoon::FwdProxy>(PSLICE() << "FwdProxy:" << port_config.port, std::move(fwd_config))
            .release();

      } else if (port_config.type == "forward") {
        cocoon::FwdProxy::Config fwd_config;
        fwd_config.port_ = port_config.port;
        fwd_config.cert_and_key_ = shared_cert;
        fwd_config.default_policy_ = port_config.policy_name;
        fwd_config.policies_[port_config.policy_name] = policy_it->second;
        fwd_config.allow_policy_from_username_ = false;
        fwd_config.skip_socks5 = true;  // Forward proxy bypasses SOCKS5
        fwd_config.fixed_destination_.init_host_port(port_config.destination_host, port_config.destination_port)
            .ensure();
        fwd_config.serialize_info = port_config.serialize_info.value_or(false);
        fwd_config.max_pow_difficulty = port_config.max_pow_difficulty;

        td::actor::create_actor<cocoon::FwdProxy>(PSLICE() << "FwdProxy:" << port_config.port, std::move(fwd_config))
            .release();

      } else if (port_config.type == "reverse") {
        cocoon::RevProxy::Config rev_config;
        rev_config.src_port_ = port_config.port;
        rev_config.dst_.init_host_port(port_config.destination_host, port_config.destination_port).ensure();
        rev_config.cert_and_key_ = shared_cert;
        rev_config.policy_ = policy_it->second;
        rev_config.serialize_info = port_config.serialize_info.value_or(false);
        rev_config.pow_difficulty = port_config.pow_difficulty;

        td::actor::create_actor<cocoon::RevProxy>(PSLICE() << "RevProxy:" << port_config.port, std::move(rev_config))
            .release();
      }
    }
  });

  LOG(INFO) << "Proxies started";
  sched.start();

  while (sched.run(10)) {
    // empty
  }

  return 0;
}