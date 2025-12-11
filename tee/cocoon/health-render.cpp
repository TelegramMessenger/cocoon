/*
 * health-render.cpp
 * 
 * Output formatting and rendering for health monitor.
 */

#include "health-render.h"
#include "tdx-eventlog.h"
#include "td/utils/logging.h"
#include "td/utils/algorithm.h"
#include "td/utils/misc.h"
#include "td/utils/UInt.h"
#include "td/utils/base64.h"
#include "cocoon/tdx.h"
#include "git.h"
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <unistd.h>
#include <sys/wait.h>

namespace cocoon {

// ============================================================================
// Formatters
// ============================================================================

namespace fmt {

std::string bytes(uint64_t bytes) {
  static const struct {
    uint64_t threshold;
    const char* unit;
  } units[] = {{1ULL << 40, "TB"}, {1ULL << 30, "GB"}, {1ULL << 20, "MB"}, {1ULL << 10, "KB"}, {0, "B"}};

  for (const auto& [threshold, unit] : units) {
    if (bytes >= threshold) {
      std::ostringstream oss;
      if (threshold > 0) {
        double val = static_cast<double>(bytes) / threshold;
        oss << std::fixed << std::setprecision(1) << val << " " << unit;
      } else {
        oss << bytes << " " << unit;
      }
      return oss.str();
    }
  }

  return "0 B";
}

std::string uptime(uint64_t seconds) {
  static const struct {
    uint64_t divisor;
    const char* unit;
  } periods[] = {{86400, "d"}, {3600, "h"}, {60, "m"}, {1, "s"}};

  std::ostringstream oss;
  bool started = false;
  int shown = 0;

  for (const auto& [divisor, unit] : periods) {
    uint64_t value = seconds / divisor;
    seconds %= divisor;

    if (value > 0 || (started && shown < 3)) {
      if (started)
        oss << " ";
      oss << value << unit;
      started = true;
      shown++;

      if (shown >= 3)
        break;  // Show max 3 components
    }
  }

  return started ? oss.str() : "0s";
}

std::string percent(double value) {
  std::ostringstream oss;
  oss << std::fixed << std::setprecision(1) << value << "%";
  return oss.str();
}

}  // namespace fmt

// ============================================================================
// Safe Parsing Helpers
// ============================================================================

// Helper: parse int safely
static td::int32 parse_int32(td::Slice s) {
  auto r = td::to_integer_safe<td::int32>(s);
  if (r.is_error()) {
    return 0;
  }
  return r.move_as_ok();
}

static uint64_t parse_uint64(td::Slice s) {
  auto r = td::to_integer_safe<td::uint64>(s);
  if (r.is_error()) {
    return 0;
  }
  return r.move_as_ok();
}

// Helper: parse float and convert to int (for GPU power which returns decimals like "94.60")
static int parse_float_as_int(const std::string& s) {
  try {
    return static_cast<int>(std::stof(s));
  } catch (...) {
    return 0;
  }
}

// ============================================================================
// TDX Rendering
// ============================================================================

namespace render_tdx {

std::string read_image_hash() {
  auto r = metrics::read_proc_file("/etc/tdx/tdx_image_hash.b64", 4096);
  return r.is_ok() ? r.move_as_ok() : "(not available)";
}

std::string read_rtmr(int index) {
  if (index < 0 || index > 3) {
    return "(invalid index)";
  }

  std::string path = "/sys/class/misc/tdx_guest/measurements/rtmr" + std::to_string(index) + ":sha384";
  auto r = metrics::read_proc_file(path, 4096);
  if (r.is_error()) {
    return "(not available)";
  }

  std::string value = r.move_as_ok();
  value.erase(value.find_last_not_of(" \n\r\t") + 1);
  return td::hex_encode(value);
}

std::string get_event_log() {
  return tdx_eventlog::render_event_log();
}

std::string get_status() {
  std::ostringstream out;
  out << "=== TDX STATUS ===\n\n";

  out << "Build:\n";
  out << "  Commit:  " << GitMetadata::CommitSHA1() << "\n";
  out << "  Date:    " << GitMetadata::CommitDate() << "\n";
  out << "  Message: " << GitMetadata::CommitSubject() << "\n\n";

  auto image_hash = read_image_hash();
  out << "Image Hash: " << image_hash << "\n\n";

  // Try to generate TDX report and extract all attestation data
  auto tdx_interface = tdx::TdxInterface::create();
  auto report_result = tdx_interface->make_report(td::UInt512());

  if (report_result.is_error()) {
    out << "Error generating TDX report: " << (PSTRING() << report_result.error()) << "\n";

    // Fallback to sysfs RTMRs
    for (int i = 0; i < 4; i++) {
      out << "RTMR" << i << ": " << read_rtmr(i) << "\n";
    }
  } else {
    auto data_result = tdx_interface->get_data(report_result.ok());

    if (data_result.is_error()) {
      out << "Error parsing TDX report: " << (PSTRING() << data_result.error()) << "\n";
    } else if (data_result.ok().is_tdx()) {
      // Use existing operator<< to print all TDX data
      out << "Attestation Data:\n";
      out << (PSTRING() << data_result.ok());

      // Verify image hash
      auto calc_hash = data_result.ok().image_hash();
      std::string calculated = td::base64_encode(calc_hash.as_slice());

      out << "\nVerification:\n";
      if (image_hash == calculated) {
        out << "  Image hash: + VERIFIED\n";
      } else if (image_hash != "(not available)") {
        out << "  Image hash: - MISMATCH (stored != calculated) (" << image_hash << " != " << calculated << ")\n";
      }
    }
  }

  return out.str();
}

}  // namespace render_tdx

// ============================================================================
// GPU Rendering
// ============================================================================

namespace render_gpu {

struct Metrics {
  std::string name;
  int utilization_percent = 0;
  uint64_t memory_used_mb = 0;
  uint64_t memory_total_mb = 0;
  int temperature_c = 0;
  int power_w = 0;
  int power_limit_w = 0;
};

// Helper: trim and split CSV line
static std::vector<std::string> split_csv(const std::string& line) {
  std::vector<std::string> fields;
  std::istringstream iss(line);
  std::string field;

  while (std::getline(iss, field, ',')) {
    field.erase(0, field.find_first_not_of(" \t\r\n"));
    field.erase(field.find_last_not_of(" \t\r\n") + 1);
    fields.push_back(field);
  }

  return fields;
}

std::vector<Metrics> parse_nvidia_output(const std::string& output) {
  // Table-driven CSV parser
  using Parser = std::function<void(Metrics&, const std::string&)>;
  static const Parser parsers[] = {
      [](Metrics& g, const std::string& f) { g.name = f; },
      [](Metrics& g, const std::string& f) { g.utilization_percent = parse_int32(f); },
      [](Metrics& g, const std::string& f) { g.memory_used_mb = parse_uint64(f); },
      [](Metrics& g, const std::string& f) { g.memory_total_mb = parse_uint64(f); },
      [](Metrics& g, const std::string& f) { g.temperature_c = parse_int32(f); },
      [](Metrics& g, const std::string& f) { g.power_w = parse_float_as_int(f); },        // ← Parse as float!
      [](Metrics& g, const std::string& f) { g.power_limit_w = parse_float_as_int(f); },  // ← Parse as float!
  };

  std::vector<Metrics> gpus;
  std::istringstream iss(output);
  std::string line;

  while (std::getline(iss, line)) {
    if (line.empty())
      continue;

    Metrics gpu;
    auto fields = split_csv(line);

    // Debug: log raw CSV fields
    if (fields.size() >= 7) {
      LOG(INFO) << "GPU CSV: name='" << fields[0] << "' power.draw='" << fields[5] << "' power.limit='" << fields[6]
                << "'";
    }

    for (size_t i = 0; i < std::min(fields.size(), std::size(parsers)); i++) {
      parsers[i](gpu, fields[i]);
    }

    LOG(INFO) << "Parsed GPU: power_w=" << gpu.power_w << " power_limit_w=" << gpu.power_limit_w;

    gpus.push_back(gpu);
  }

  return gpus;
}

struct MemoryInfo {
  double used_gb, total_gb, percent;
};

static MemoryInfo calc_memory_info(uint64_t used_mb, uint64_t total_mb) {
  double used_gb = used_mb / 1024.0;
  double total_gb = total_mb / 1024.0;
  double percent = total_mb > 0 ? (used_mb * 100.0 / total_mb) : 0.0;
  return {used_gb, total_gb, percent};
}

std::string get_metrics() {
  auto result = exec_command_safe(
      {"nvidia-smi", "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw,power.limit",
       "--format=csv,noheader,nounits"});

  std::ostringstream out;
  out << "=== GPU METRICS ===\n";

  if (result.is_error()) {
    out << "Error: " << result.error().message().str() << "\n";
    out << "(nvidia-smi not available or no GPUs detected)\n";
    return out.str();
  }

  auto gpus = parse_nvidia_output(result.move_as_ok());

  if (gpus.empty()) {
    out << "No GPUs detected\n";
    return out.str();
  }

  for (size_t i = 0; i < gpus.size(); i++) {
    const auto& g = gpus[i];
    auto mem = calc_memory_info(g.memory_used_mb, g.memory_total_mb);

    out << "GPU " << i << ":\n";
    out << "  Model:       " << g.name << "\n";
    out << "  Utilization: " << g.utilization_percent << "%\n";
    out << "  Memory:      " << std::fixed << std::setprecision(1) << mem.used_gb << " GB / " << mem.total_gb
        << " GB  (" << std::setprecision(0) << mem.percent << "%)\n";
    out << "  Temperature: " << g.temperature_c << "°C\n";
    out << "  Power:       " << g.power_w << "W / " << g.power_limit_w << "W\n";

    if (i < gpus.size() - 1)
      out << "\n";
  }

  return out.str();
}

}  // namespace render_gpu

// ============================================================================
// Service Rendering
// ============================================================================

namespace render_service {

td::Result<std::string> get_status(const std::string& svc) {
  if (!is_valid_service(svc)) {
    return td::Status::Error("Invalid or unauthorized service name");
  }
  return exec_command_safe({"systemctl", "show", svc, "--no-pager"});
}

td::Result<std::string> get_status_human(const std::string& svc) {
  if (!is_valid_service(svc)) {
    return td::Status::Error("Invalid or unauthorized service name");
  }
  // systemctl status exit codes: 0=running, 1=dead+pidfile, 2=dead+lockfile, 3=not running, 4=unknown
  return exec_command_safe({"systemctl", "status", svc, "--no-pager"}, {0, 1, 2, 3, 4});
}

td::Result<std::string> get_logs(const std::string& svc, int lines) {
  if (!is_valid_service(svc)) {
    return td::Status::Error("Invalid or unauthorized service name");
  }
  if (lines <= 0 || lines > 1000000) {
    return td::Status::Error("Invalid line count (must be 1-1000000)");
  }
  return exec_command_safe({"journalctl", "-u", svc, "-n", std::to_string(lines), "--no-pager"});
}

std::string render_info(const std::string& service_name, const StatsCollector& stats) {
  auto result = get_status(service_name);
  if (result.is_error()) {
    return "ERROR: " + result.error().message().str();
  }

  auto m = metrics::parse_service_metrics(service_name, result.ok());

  std::ostringstream out;
  out << "=== SERVICE: " << service_name << " ===\n";
  out << "Status:   " << m.state;
  if (!m.sub_state.empty() && m.sub_state != m.state) {
    out << " (" << m.sub_state << ")";
  }
  out << "\n";

  if (m.pid > 0) {
    out << "PID:      " << m.pid << "\n";
  }

  out << "Restarts: " << m.restart_count << "\n\n";

  // Resources (cgroup accounting - includes all descendant processes)
  out << "Resources (cgroup):\n";

  // CPU (per-service) - show cumulative + rates
  auto cpu_pct = stats.get_service_cpu(service_name);

  // Convert nanoseconds to human-readable time
  double cpu_seconds = m.cpu_usage_nsec / 1e9;
  out << "  CPU:      " << std::fixed << std::setprecision(1) << cpu_seconds << "s total\n";
  out << "            " << cpu_pct[0] << "%"
      << "  (1m: " << cpu_pct[1] << "%"
      << ", 5m: " << cpu_pct[2] << "%)\n";

  // Memory
  out << "  Memory:   " << fmt::bytes(m.memory_bytes);
  if (m.memory_max > 0) {
    double pct = (static_cast<double>(m.memory_bytes) / m.memory_max) * 100.0;
    out << " / " << fmt::bytes(m.memory_max) << "  (" << std::fixed << std::setprecision(1) << pct << "%)";
  }
  out << "\n";

  // Threads
  out << "  Threads:  " << m.num_tasks << "\n";

  // Open FDs
  out << "  Open FDs: " << m.open_fds << "\n";

  // Sockets
  out << "  Sockets:  " << m.tcp_connections << "\n";

  // I/O - show cumulative + rates (cgroup includes all processes + docker)
  auto io_rates = stats.get_service_io(service_name);
  out << "\nI/O (cgroup):\n";
  out << "  Read:  " << fmt::bytes(m.io_read_bytes) << " total\n";
  out << "         " << fmt::bytes(static_cast<uint64_t>(io_rates[0].read)) << "/s"
      << "  (1m: " << fmt::bytes(static_cast<uint64_t>(io_rates[1].read)) << "/s"
      << ", 5m: " << fmt::bytes(static_cast<uint64_t>(io_rates[2].read)) << "/s)\n";
  out << "  Write: " << fmt::bytes(m.io_write_bytes) << " total\n";
  out << "         " << fmt::bytes(static_cast<uint64_t>(io_rates[0].write)) << "/s"
      << "  (1m: " << fmt::bytes(static_cast<uint64_t>(io_rates[1].write)) << "/s"
      << ", 5m: " << fmt::bytes(static_cast<uint64_t>(io_rates[2].write)) << "/s)\n";

  auto logs_result = get_logs(service_name, 10);
  if (logs_result.is_ok()) {
    out << "\nRecent logs (last 10 lines):\n";
    out << logs_result.ok();
  }

  return out.str();
}

// Helper: Collect service states
struct ServiceState {
  std::string name;
  std::string state;
  std::string error;
  bool is_critical;
};

static std::vector<ServiceState> collect_service_states() {
  std::vector<ServiceState> states;

  auto is_critical = [](const std::string& svc) { return !td::contains(NON_CRITICAL_BASELINE_SERVICES, svc); };

  for (const auto& svc : MONITORED_SERVICES) {
    ServiceState s{svc, "", "", is_critical(svc)};

    auto result = get_status(svc);
    if (result.is_error()) {
      s.error = result.error().message().str();
    } else {
      s.state = metrics::parse_service_metrics(svc, result.ok()).state;
    }

    states.push_back(s);
  }

  return states;
}

// Helper: Render status header
static std::string render_header(const std::vector<ServiceState>& states, const SystemMetrics& sys_m) {
  std::vector<std::string> errors;
  for (const auto& s : states) {
    if (s.is_critical) {
      if (!s.error.empty()) {
        errors.push_back(s.name + ": " + s.error);
      } else if (s.state != "active") {
        errors.push_back(s.name + " is " + s.state);
      }
    }
  }

  std::ostringstream out;

  // Build info
  out << "Build: " << GitMetadata::CommitSHA1() << "\n";
  out << "       " << GitMetadata::CommitDate() << " - " << GitMetadata::CommitSubject() << "\n\n";

  if (errors.empty()) {
    out << "Status: OK - All critical services active\n";
  } else {
    out << "Status: ERROR - " << errors.size() << " service(s) failing\n";
    for (const auto& err : errors) {
      out << "  - " << err << "\n";
    }
  }

  out << "TDX Image Hash: " << render_tdx::read_image_hash() << "\n";
  out << "System: Load " << std::fixed << std::setprecision(2) << sys_m.load_1m;

  if (sys_m.mem_total > 0 && sys_m.mem_available > 0) {
    double mem_pct = ((sys_m.mem_total - sys_m.mem_available) * 100.0) / sys_m.mem_total;
    out << " | Mem " << fmt::percent(mem_pct);
  }

  out << "\n===============================\n\n";
  return out.str();
}

// Helper: Render single service line
static std::string render_service_line(const ServiceState& s) {
  const char* marker = s.error.empty() ? (s.state == "active" ? "[+]" : (s.is_critical ? "[-]" : "[~]"))
                                       : (s.is_critical ? "[-]" : "[~]");

  std::ostringstream out;
  out << "  " << marker << " " << s.name << ": ";

  if (!s.error.empty()) {
    out << "ERROR - " << s.error;
  } else {
    out << s.state;

    // Add metrics for active services
    if (s.state == "active") {
      auto result = get_status(s.name);
      if (result.is_ok()) {
        auto m = metrics::parse_service_metrics(s.name, result.ok());

        std::vector<std::string> details;
        if (m.restart_count > 0)
          details.push_back(std::to_string(m.restart_count) + " restarts");
        if (m.memory_bytes > 0)
          details.push_back("Mem: " + fmt::bytes(m.memory_bytes));

        if (!details.empty()) {
          out << " (" << details[0];
          for (size_t i = 1; i < details.size(); i++)
            out << ", " << details[i];
          out << ")";
        }
      }
    }
  }

  return out.str();
}

std::string render_all_status() {
  auto states = collect_service_states();
  auto sys_m = metrics::collect_all();

  std::ostringstream out;
  out << render_header(states, sys_m);
  out << "Services:\n";

  for (const auto& s : states) {
    out << render_service_line(s) << "\n";
  }

  return out.str();
}

}  // namespace render_service

// ============================================================================
// System Metrics Rendering
// ============================================================================

std::string render_system_metrics(const SystemMetrics& m, const StatsCollector& stats) {
  std::ostringstream out;

  out << "=== SYSTEM METRICS ===\n";
  out << "Uptime: " << fmt::uptime(m.uptime_seconds) << "\n\n";

  // CPU
  out << "CPU:\n";
  out << "  Load:  " << std::fixed << std::setprecision(2) << m.load_1m << " / " << m.load_5m << " / " << m.load_15m
      << "  (1m / 5m / 15m)\n";
  if (m.cpu_cores > 0) {
    out << "  Cores: " << m.cpu_cores << "\n";
  }

  // Estimate total CPU seconds used (rough calculation)
  // This is approximate since we don't have exact tick rate
  if (m.cpu_total_ticks > m.cpu_idle_ticks && m.uptime_seconds > 0) {
    uint64_t used_ticks = m.cpu_total_ticks - m.cpu_idle_ticks;
    // Estimate: used_ticks / total_ticks * uptime * cores
    double cpu_seconds = (static_cast<double>(used_ticks) / m.cpu_total_ticks) * m.uptime_seconds * m.cpu_cores;
    out << "  Total: " << fmt::uptime(static_cast<uint64_t>(cpu_seconds)) << " CPU time\n";
  }

  auto cpu_util = stats.get_cpu_utilization();
  if (cpu_util[0] != cpu_util[1] || cpu_util[1] != cpu_util[2]) {
    // Show all windows if they differ
    out << "  Usage: " << std::fixed << std::setprecision(1) << cpu_util[0] << "%  (1m: " << cpu_util[1]
        << "%, 5m: " << cpu_util[2] << "%)\n\n";
  } else {
    // Just show one value if all the same
    out << "  Usage: " << std::fixed << std::setprecision(1) << cpu_util[0] << "%\n\n";
  }

  // Memory
  out << "Memory:\n";
  if (m.mem_available > 0 && m.mem_total > 0) {
    uint64_t mem_used = m.mem_total - m.mem_available;
    double mem_pct = (static_cast<double>(mem_used) / m.mem_total) * 100.0;
    out << "  " << fmt::bytes(mem_used) << " / " << fmt::bytes(m.mem_total) << "  (" << std::fixed
        << std::setprecision(1) << mem_pct << "%)\n";
  }

  if (m.swap_total > 0) {
    uint64_t swap_used = m.swap_total - m.swap_free;
    out << "  Swap: " << fmt::bytes(swap_used) << " / " << fmt::bytes(m.swap_total) << "\n";
  }
  out << "\n";

  // Helper to render I/O rates (used for both disk and network)
  auto render_io_line = [](const std::string& prefix, const std::array<IoRateTracker::Rates, 3>& rates, bool is_write) {
    std::ostringstream line;
    line << "  " << prefix << ": ";

    double rate_total = is_write ? rates[2].write : rates[2].read;
    double rate_10s = is_write ? rates[0].write : rates[0].read;
    double rate_10m = is_write ? rates[1].write : rates[1].read;

    line << fmt::bytes(static_cast<uint64_t>(rate_10s)) << "/s"
         << "  (1m: " << fmt::bytes(static_cast<uint64_t>(rate_total)) << "/s"
         << ", 5m: " << fmt::bytes(static_cast<uint64_t>(rate_10m)) << "/s)\n";

    return line.str();
  };

  // Disk I/O
  if (!m.disk_io.empty()) {
    out << "Disk I/O:\n";
    for (const auto& [device, io] : m.disk_io) {
      auto rates = stats.get_disk_rates(device);
      out << "  " << device << " read:  " << fmt::bytes(io.first) << " total, "
          << render_io_line(device + " read ", rates, false).substr(device.length() + 9);  // Skip device name prefix
      out << "  " << device << " write: " << fmt::bytes(io.second) << " total, "
          << render_io_line(device + " write", rates, true).substr(device.length() + 10);
    }
    out << "\n";
  }

  // Network
  if (!m.net_io.empty()) {
    out << "Network:\n";
    for (const auto& [iface, io] : m.net_io) {
      auto rates = stats.get_net_rates(iface);
      out << "  " << iface << " ↓: " << fmt::bytes(io.first) << " total, "
          << render_io_line(iface + " ↓", rates, false).substr(iface.length() + 5);
      out << "  " << iface << " ↑: " << fmt::bytes(io.second) << " total, "
          << render_io_line(iface + " ↑", rates, true).substr(iface.length() + 5);
    }
  }

  return out.str();
}

}  // namespace cocoon
