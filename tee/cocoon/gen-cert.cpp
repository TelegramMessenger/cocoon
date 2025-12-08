#include "cocoon/FwdProxy.h"
#include "td/utils/filesystem.h"
#include "td/utils/logging.h"
#include "td/utils/OptionParser.h"
#include "td/utils/base64.h"
#include "td/utils/port/Stat.h"
#include "td/utils/port/signals.h"
#include "td/utils/port/user.h"

int main(int argc, char **argv) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(DEBUG));
  td::set_default_failure_signal_handler().ensure();
  int threads_n = 0;

  std::map<std::string, tdx::TdxInterfaceRef> tdxs;
  tdxs["none"] = nullptr;
  tdxs["fake_tdx"] = tdx::TdxInterface::create_fake();
  tdxs["tdx"] = tdx::TdxInterface::create();

  std::string base_name = "test";
  tdx::TdxInterfaceRef tdx;

  std::string user;
  bool force = false;
  std::optional<td::uint32> current_time;

  td::OptionParser option_parser;
  option_parser.add_checked_option('t', "tdx", "tdx mode (none, fake_tdx, tdx)", [&](td::Slice tdx_name) {
    auto it = tdxs.find(tdx_name.str());
    if (it == tdxs.end()) {
      return td::Status::Error("Unknown tdx name");
    }
    tdx = it->second;
    return td::Status::OK();
  });
  option_parser.add_checked_option('n', "name", "base name of cert", [&](td::Slice name) {
    base_name = name.str();
    return td::Status::OK();
  });
  option_parser.add_checked_option('u', "user", "save key under user", [&](td::Slice name) {
    user = name.str();
    return td::Status::OK();
  });
  option_parser.add_checked_option('f', "force", "rewrite key (for tests only)", [&]() {
    force = true;
    return td::Status::OK();
  });
  option_parser.add_checked_option('c', "current-time", "Unix timestamp to use for certificate generation", [&](td::Slice time_str) {
    TRY_RESULT(timestamp, td::to_integer_safe<td::uint32>(time_str));
    
    // Validate timestamp is not in the future (allow 60s clock skew)
    td::uint32 now = static_cast<td::uint32>(td::Clocks::system());
    if (timestamp > now + 60) {
      return td::Status::Error(PSLICE() << "Provided timestamp " << timestamp 
                                        << " is in the future (current time: " << now << ")");
    }
    
    current_time = timestamp;
    LOG(INFO) << "Using provided timestamp: " << timestamp;
    return td::Status::OK();
  });
  option_parser.add_option('h', "help", "Show this help message", [&]() {
    LOG(PLAIN) << option_parser;
    std::_Exit(0);
  });

  option_parser.set_description(
      "gen-cert: emits <name>_cert.pem, <name>_key.pem; <name>.tdx_report and <name>_image_hash.b64 if --tdx set");

  auto r_args = option_parser.run(argc, argv, -1);
  if (r_args.is_error()) {
    LOG(ERROR) << r_args.error();
    LOG(ERROR) << option_parser;
    return 1;
  }

  auto report_path = PSTRING() << base_name << ".tdx_report";
  auto hash_path = PSTRING() << base_name << "_image_hash.b64";
  auto cert_path = PSTRING() << base_name << "_cert.pem";
  auto key_path = PSTRING() << base_name << "_key.pem";

  if (tdx) {
    auto report = tdx->make_report(td::UInt512{}).move_as_ok();
    td::write_file(report_path, report.raw_report).ensure();

    // Save TDX image hash (like .tdx_report)
    auto attestation_data = tdx->get_data(report).move_as_ok();
    LOG(INFO) << "TDX: " << attestation_data;
    auto image_hash = attestation_data.image_hash();
    auto hash_base64 = td::base64_encode(image_hash.as_slice());
    td::write_file(hash_path, hash_base64).ensure();
  }

  if (!force && (td::stat(cert_path).is_ok() || td::stat(key_path).is_ok())) {
    LOG(ERROR) << "Refusing to overwrite existing files";
    return 0;
  }

  // Generate certificate with optional custom time
  tdx::CertConfig config;
  if (current_time.has_value()) {
    config.current_time = current_time;
  }
  
  auto cert_and_key = tdx::generate_cert_and_key(tdx.get(), config);
  
  // Change user after key generation (if needed)
  if (!user.empty()) {
    td::change_user(user).ensure();
  }
  
  td::atomic_write_file(cert_path, cert_and_key.cert_pem()).ensure();
  td::atomic_write_file(key_path, cert_and_key.key_pem()).ensure();

  return 0;
}
