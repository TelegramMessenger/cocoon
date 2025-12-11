/*
 * health-metrics.cpp
 * 
 * Implementation of system metrics collection.
 */

#include "health-metrics.h"
#include "td/utils/logging.h"
#include "td/utils/port/FileFd.h"
#include "td/utils/ScopeGuard.h"
#include "td/utils/port/path.h"
#include "td/utils/PathView.h"
#include "td/utils/misc.h"

#include <sstream>
#include <unistd.h>

namespace cocoon {

// Forward declare from health-monitor.cpp
td::Result<std::string> exec_command_safe(const std::vector<std::string>& args,
                                          std::vector<int> allowed_exit_codes = {0});

namespace metrics {

// Read procfs/sysfs file directly (bypasses size=0 issue)
td::Result<std::string> read_proc_file(td::CSlice path, size_t buffer_size) {
#if TD_LINUX
  TRY_RESULT(fd, td::FileFd::open(path, td::FileFd::Read));
  SCOPE_EXIT {
    fd.close();
  };

  std::string buffer(buffer_size, '\0');
  TRY_RESULT(size, fd.read(td::MutableSlice(buffer.data(), buffer_size)));
  buffer.resize(size);
  return buffer;
#else
  return td::Status::Error("Not supported on non-Linux platforms");
#endif
}

// Parse /proc/loadavg
td::Status parse_loadavg(SystemMetrics& m) {
  TRY_RESULT_PREFIX(content, read_proc_file("/proc/loadavg", 1024), "loadavg: ");

  std::istringstream iss(content);
  if (!(iss >> m.load_1m >> m.load_5m >> m.load_15m)) {
    return td::Status::Error("Failed to parse load averages");
  }

  return td::Status::OK();
}

// Parse /proc/meminfo - table-driven field extraction
td::Status parse_meminfo(SystemMetrics& m) {
  TRY_RESULT_PREFIX(content, read_proc_file("/proc/meminfo", 16384), "meminfo: ");

  static const std::map<std::string, uint64_t SystemMetrics::*> fields = {
      {"MemTotal:", &SystemMetrics::mem_total},
      {"MemAvailable:", &SystemMetrics::mem_available},
      {"SwapTotal:", &SystemMetrics::swap_total},
      {"SwapFree:", &SystemMetrics::swap_free}};

  std::istringstream iss(content);
  std::string line;

  while (std::getline(iss, line)) {
    std::istringstream ls(line);
    std::string key;
    uint64_t value;
    std::string unit;

    if (ls >> key >> value >> unit) {
      auto it = fields.find(key);
      if (it != fields.end()) {
        m.*(it->second) = value * 1024;  // kB to bytes
      }
    }
  }

  return td::Status::OK();
}

// Parse /proc/uptime
td::Status parse_uptime(SystemMetrics& m) {
  TRY_RESULT(content, read_proc_file("/proc/uptime", 1024));

  std::istringstream iss(content);
  double uptime_val;
  if (!(iss >> uptime_val)) {
    return td::Status::Error("Failed to parse uptime");
  }

  m.uptime_seconds = static_cast<uint64_t>(uptime_val);
  return td::Status::OK();
}

// Parse /proc/cpuinfo (cached)
int get_cpu_cores() {
  static int cached_cores = -1;

  if (cached_cores >= 0) {
    return cached_cores;
  }

  auto r_content = read_proc_file("/proc/cpuinfo");
  if (r_content.is_error()) {
    return 0;
  }

  std::istringstream iss(r_content.move_as_ok());
  std::string line;
  int count = 0;

  while (std::getline(iss, line)) {
    if (td::begins_with(line, "processor")) {
      count++;
    }
  }

  cached_cores = count;
  return count;
}

td::Status parse_cpuinfo(SystemMetrics& m) {
  m.cpu_cores = get_cpu_cores();
  return td::Status::OK();
}

// Parse /proc/stat for CPU ticks
td::Status parse_cpu_stat(SystemMetrics& m) {
  TRY_RESULT(content, read_proc_file("/proc/stat", 16384));

  std::istringstream iss(content);
  std::string line;

  if (!std::getline(iss, line) || !td::begins_with(line, "cpu ")) {
    return td::Status::Error("Invalid /proc/stat format");
  }

  std::istringstream ls(line);
  std::string label;
  uint64_t user, nice, system, idle, iowait = 0, irq = 0, softirq = 0, steal = 0;

  ls >> label >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal;

  m.cpu_total_ticks = user + nice + system + idle + iowait + irq + softirq + steal;
  m.cpu_idle_ticks = idle + iowait;

  return td::Status::OK();
}

// Parse /proc/net/dev
td::Status parse_net_dev(SystemMetrics& m) {
  TRY_RESULT(content, read_proc_file("/proc/net/dev", 16384));

  std::istringstream iss(content);
  std::string line;
  int found = 0;

  // Skip header lines
  std::getline(iss, line);
  std::getline(iss, line);

  while (std::getline(iss, line)) {
    std::istringstream ls(line);
    std::string iface;
    uint64_t rx_bytes, rx_pkts, rx_errs, rx_drop, rx_fifo, rx_frame, rx_comp, rx_mcast;
    uint64_t tx_bytes, tx_pkts, tx_errs, tx_drop, tx_fifo, tx_colls, tx_carrier, tx_comp;

    if (ls >> iface >> rx_bytes >> rx_pkts >> rx_errs >> rx_drop >> rx_fifo >> rx_frame >> rx_comp >> rx_mcast >>
        tx_bytes >> tx_pkts >> tx_errs >> tx_drop >> tx_fifo >> tx_colls >> tx_carrier >> tx_comp) {
      // Remove trailing colon
      if (!iface.empty() && iface.back() == ':') {
        iface.pop_back();
      }

      // Skip loopback
      if (iface != "lo") {
        m.net_io[iface] = {rx_bytes, tx_bytes};
        found++;
      }
    }
  }

  return td::Status::OK();
}

// Parse /proc/diskstats
td::Status parse_diskstats(SystemMetrics& m) {
  TRY_RESULT(content, read_proc_file("/proc/diskstats"));

  std::istringstream iss(content);
  std::string line;
  int found = 0;

  while (std::getline(iss, line)) {
    std::istringstream ls(line);
    int major, minor;
    std::string device;
    uint64_t reads_comp, reads_merged, sectors_read, time_read;
    uint64_t writes_comp, writes_merged, sectors_written, time_write;

    if (ls >> major >> minor >> device >> reads_comp >> reads_merged >> sectors_read >> time_read >> writes_comp >>
        writes_merged >> sectors_written >> time_write) {
      // Only physical disks (simple heuristic: no digit after position 2)
      if ((td::begins_with(device, "sd") || td::begins_with(device, "nvme") || td::begins_with(device, "vd")) &&
          device.find_first_of("0123456789", 2) == std::string::npos) {
        m.disk_io[device] = {sectors_read * 512, sectors_written * 512};
        found++;
      }
    }
  }

  return td::Status::OK();
}

// Collect all metrics
SystemMetrics collect_all() {
  SystemMetrics m;

  auto try_parse = [&](auto parser, const char* name) {
    auto status = parser(m);
    if (status.is_error()) {
      LOG(WARNING) << "Failed to parse " << name << ": " << status.error();
    }
  };

  try_parse(parse_loadavg, "loadavg");
  try_parse(parse_meminfo, "meminfo");
  try_parse(parse_uptime, "uptime");
  try_parse(parse_cpuinfo, "cpuinfo");
  try_parse(parse_cpu_stat, "cpu_stat");
  try_parse(parse_net_dev, "net_dev");
  try_parse(parse_diskstats, "diskstats");

  return m;
}

// ============================================================================
// Per-Process Metrics
// ============================================================================

// Helper for safe integer parsing
static int safe_parse_int(const std::string& s) {
  try {
    return std::stoi(s);
  } catch (...) {
    return 0;
  }
}

static uint64_t safe_parse_uint(const std::string& s) {
  try {
    return std::stoull(s);
  } catch (...) {
    return 0;
  }
}

// Count open file descriptors for a process
int count_open_fds(int pid) {
  if (pid <= 0)
    return 0;

  std::string path = "/proc/" + std::to_string(pid) + "/fd";
  int count = 0;

  auto status = td::WalkPath::run(path, [&](td::CSlice entry_path, td::WalkPath::Type type) {
    if (type == td::WalkPath::Type::RegularFile || type == td::WalkPath::Type::Symlink) {
      count++;
    }
    return td::WalkPath::Action::Continue;
  });

  // Permission denied is normal for other users' processes
  if (status.is_error()) {
    return 0;  // Silently skip
  }

  return count;
}

// Parse /proc/<pid>/io for I/O statistics
std::pair<uint64_t, uint64_t> get_process_io(int pid) {
  if (pid <= 0)
    return {0, 0};

  std::string path = "/proc/" + std::to_string(pid) + "/io";
  auto r = read_proc_file(path, 4096);
  if (r.is_error()) {
    return {0, 0};
  }

  uint64_t read_bytes = 0, write_bytes = 0;
  std::istringstream iss(r.move_as_ok());
  std::string line;

  while (std::getline(iss, line)) {
    if (td::begins_with(line, "read_bytes: ")) {
      read_bytes = safe_parse_uint(line.substr(12));
    } else if (td::begins_with(line, "write_bytes: ")) {
      write_bytes = safe_parse_uint(line.substr(13));
    }
  }

  return {read_bytes, write_bytes};
}

// Count TCP connections for a process
int count_tcp_connections(int pid) {
  if (pid <= 0)
    return 0;

  // Count symlinks to socket:[] in /proc/<pid>/fd/
  std::string fd_path = "/proc/" + std::to_string(pid) + "/fd";
  int count = 0;

  auto status = td::WalkPath::run(fd_path, [&](td::CSlice entry_path, td::WalkPath::Type type) {
    if (type == td::WalkPath::Type::Symlink) {
      char buf[256];
      ssize_t len = readlink(entry_path.c_str(), buf, sizeof(buf) - 1);
      if (len > 0 && td::begins_with(td::Slice(buf, len), "socket:")) {
        count++;
      }
    }
    return td::WalkPath::Action::Continue;
  });

  if (status.is_error()) {
    return 0;
  }

  return count;
}

// Parse systemctl show output for service metrics
service::Metrics parse_service_metrics(const std::string& service_name, const std::string& output) {
  service::Metrics m;
  m.name = service_name;

  std::istringstream iss(output);
  std::string line;

  while (std::getline(iss, line)) {
    auto eq_pos = line.find('=');
    if (eq_pos == std::string::npos) {
      continue;
    }

    std::string key = line.substr(0, eq_pos);
    std::string value = line.substr(eq_pos + 1);

    if (key == "ActiveState") {
      m.state = value;
    } else if (key == "SubState") {
      m.sub_state = value;
    } else if (key == "NRestarts") {
      m.restart_count = static_cast<uint32_t>(safe_parse_uint(value));
    } else if (key == "MainPID") {
      m.pid = safe_parse_int(value);
    } else if (key == "MemoryCurrent" && value != "[not set]") {
      m.memory_bytes = safe_parse_uint(value);
    } else if (key == "MemoryMax" && value != "[not set]" && value != "infinity") {
      m.memory_max = safe_parse_uint(value);
    } else if (key == "MemoryHigh" && value != "[not set]" && value != "infinity" && m.memory_max == 0) {
      m.memory_max = safe_parse_uint(value);  // Use MemoryHigh if MemoryMax not set
    } else if (key == "CPUUsageNSec" && value != "[not set]") {
      m.cpu_usage_nsec = safe_parse_uint(value);
    } else if (key == "TasksCurrent" && value != "[not set]") {
      m.num_tasks = safe_parse_int(value);
    }
  }

  // Try to get CPU usage from cgroup (includes all descendants)
  uint64_t cgroup_cpu = get_cgroup_cpu_usage(service_name);
  if (cgroup_cpu > 0) {
    m.cpu_usage_nsec = cgroup_cpu;  // Override with cgroup value (more accurate)
  }

  // Try to get memory from cgroup (includes all descendants)
  uint64_t cgroup_mem = get_cgroup_memory(service_name);
  if (cgroup_mem > 0) {
    m.memory_bytes = cgroup_mem;  // Override with cgroup value (includes docker)
  }

  // Try to get I/O stats from cgroup (includes all descendants)
  auto [cgroup_io_read, cgroup_io_write] = get_cgroup_io(service_name);
  if (cgroup_io_read > 0 || cgroup_io_write > 0) {
    m.io_read_bytes = cgroup_io_read;
    m.io_write_bytes = cgroup_io_write;
  } else if (m.pid > 0) {
    // Fallback to per-process I/O if cgroup not available
    auto [io_read, io_write] = get_process_io(m.pid);
    m.io_read_bytes = io_read;
    m.io_write_bytes = io_write;
  }

  // Collect per-process metrics
  // Try cgroup-wide FD/socket count (includes all descendants)
  auto [cgroup_fds, cgroup_sockets] = count_cgroup_fds_and_sockets(service_name);
  if (cgroup_fds > 0 || cgroup_sockets > 0) {
    m.open_fds = cgroup_fds;
    m.tcp_connections = cgroup_sockets;
  } else if (m.pid > 0) {
    // Fallback to main process only
    m.open_fds = count_open_fds(m.pid);
    m.tcp_connections = count_tcp_connections(m.pid);
  }

  return m;
}

// Helper: get docker container ID for a container name
static std::string get_docker_container_id(const std::string& container_name) {
  auto result = exec_command_safe({"docker", "inspect", container_name, "--format", "{{.Id}}"});
  if (result.is_error()) {
    return "";
  }

  std::string id = result.move_as_ok();
  // Trim whitespace
  id.erase(id.find_last_not_of(" \n\r\t") + 1);
  return id;
}

// Helper: find cgroup path for a service (tries system.slice then user.slice)
static std::string find_cgroup_path(const std::string& service_name, const std::string& filename) {
  std::string paths[] = {"/sys/fs/cgroup/system.slice/" + service_name + "/" + filename,
                         "/sys/fs/cgroup/user.slice/" + service_name + "/" + filename};

  for (const auto& path : paths) {
    auto r = read_proc_file(path, 1);  // Just check if exists
    if (r.is_ok()) {
      return path;
    }
  }

  return "";
}

// Helper: get docker container cgroup paths for cocoon-vllm
static std::vector<std::string> get_docker_cgroup_paths(const std::string& service_name, const std::string& filename) {
  std::vector<std::string> paths;

  if (service_name == "cocoon-vllm.service") {
    std::string container_id = get_docker_container_id(service_name);
    if (!container_id.empty()) {
      paths.push_back("/sys/fs/cgroup/system.slice/docker-" + container_id + ".scope/" + filename);
    }
  }

  return paths;
}

// Helper: parse cpu.stat file and return usage in nanoseconds
static uint64_t parse_cpu_stat(const std::string& content) {
  std::istringstream iss(content);
  std::string line;

  while (std::getline(iss, line)) {
    if (td::begins_with(line, "usage_usec ")) {
      return safe_parse_uint(line.substr(11)) * 1000;  // usec → nsec
    }
  }

  return 0;
}

// Get CPU usage from cgroup (includes all child processes + docker for vllm)
uint64_t get_cgroup_cpu_usage(const std::string& service_name) {
  uint64_t total = 0;

  // Service cgroup
  std::string path = find_cgroup_path(service_name, "cpu.stat");
  if (!path.empty()) {
    auto r = read_proc_file(path, 4096);
    if (r.is_ok()) {
      total += parse_cpu_stat(r.ok());
    }
  }

  // Docker containers (for cocoon-vllm)
  for (const auto& docker_path : get_docker_cgroup_paths(service_name, "cpu.stat")) {
    auto r = read_proc_file(docker_path, 4096);
    if (r.is_ok()) {
      total += parse_cpu_stat(r.ok());
    }
  }

  if (total == 0 && path.empty()) {
    LOG(WARNING) << "No cgroup CPU accounting for " << service_name;
  }

  return total;
}

// Helper: parse io.stat file and sum all devices
static std::pair<uint64_t, uint64_t> parse_io_stat(const std::string& content) {
  uint64_t total_read = 0, total_write = 0;
  std::istringstream iss(content);
  std::string line;

  while (std::getline(iss, line)) {
    std::istringstream ls(line);
    std::string device_id;
    std::string kv;

    ls >> device_id;  // Skip "253:0" or similar

    while (ls >> kv) {
      if (td::begins_with(kv, "rbytes=")) {
        total_read += safe_parse_uint(kv.substr(7));
      } else if (td::begins_with(kv, "wbytes=")) {
        total_write += safe_parse_uint(kv.substr(7));
      }
    }
  }

  return {total_read, total_write};
}

// Get I/O stats from cgroup (includes all child processes + docker for vllm)
std::pair<uint64_t, uint64_t> get_cgroup_io(const std::string& service_name) {
  uint64_t total_read = 0, total_write = 0;

  // Service cgroup
  std::string path = find_cgroup_path(service_name, "io.stat");
  if (!path.empty()) {
    auto r = read_proc_file(path, 16384);
    if (r.is_ok()) {
      auto [read, write] = parse_io_stat(r.ok());
      total_read += read;
      total_write += write;
    }
  }

  // Docker containers (for cocoon-vllm)
  for (const auto& docker_path : get_docker_cgroup_paths(service_name, "io.stat")) {
    auto r = read_proc_file(docker_path, 16384);
    if (r.is_ok()) {
      auto [read, write] = parse_io_stat(r.ok());
      total_read += read;
      total_write += write;
    }
  }

  if (total_read == 0 && total_write == 0) {
    LOG(WARNING) << "No cgroup I/O accounting for " << service_name;
  }

  return {total_read, total_write};
}

// Get memory usage from cgroup (includes all child processes + docker for vllm)
uint64_t get_cgroup_memory(const std::string& service_name) {
  uint64_t total = 0;

  // Service cgroup
  std::string path = find_cgroup_path(service_name, "memory.current");
  if (!path.empty()) {
    auto r = read_proc_file(path, 1024);
    if (r.is_ok()) {
      total += safe_parse_uint(r.ok());
    }
  }

  // Docker containers (for cocoon-vllm)
  for (const auto& docker_path : get_docker_cgroup_paths(service_name, "memory.current")) {
    auto r = read_proc_file(docker_path, 1024);
    if (r.is_ok()) {
      total += safe_parse_uint(r.ok());
    }
  }

  return total;
}

// Helper: count FDs/sockets for all PIDs in a cgroup.procs file
static std::pair<int, int> count_fds_for_procs(const std::string& procs_content) {
  int total_fds = 0, total_sockets = 0;
  std::istringstream iss(procs_content);
  std::string line;

  while (std::getline(iss, line)) {
    int pid = safe_parse_int(line);
    if (pid > 0) {
      total_fds += count_open_fds(pid);
      total_sockets += count_tcp_connections(pid);
    }
  }

  return {total_fds, total_sockets};
}

// Get FDs and sockets for all processes in a cgroup + docker for vllm
std::pair<int, int> count_cgroup_fds_and_sockets(const std::string& service_name) {
  int total_fds = 0, total_sockets = 0;

  // Service cgroup
  std::string path = find_cgroup_path(service_name, "cgroup.procs");
  if (!path.empty()) {
    auto r = read_proc_file(path, 16384);
    if (r.is_ok()) {
      auto [fds, sockets] = count_fds_for_procs(r.ok());
      total_fds += fds;
      total_sockets += sockets;
    }
  }

  // Docker containers (for cocoon-vllm)
  for (const auto& docker_path : get_docker_cgroup_paths(service_name, "cgroup.procs")) {
    auto r = read_proc_file(docker_path, 16384);
    if (r.is_ok()) {
      auto [fds, sockets] = count_fds_for_procs(r.ok());
      total_fds += fds;
      total_sockets += sockets;
    }
  }

  return {total_fds, total_sockets};
}

}  // namespace metrics
}  // namespace cocoon
