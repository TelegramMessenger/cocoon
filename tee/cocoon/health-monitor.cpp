/*
 * health-monitor.cpp
 * 
 * Vsock-based health monitoring service for TDX guest VMs.
 * Listens on a vsock port and responds to health check queries.
 */

#include "health-metrics.h"
#include "health-stats.h"
#include "health-render.h"
#include "td/utils/logging.h"
#include "td/utils/OptionParser.h"
#include "td/utils/Status.h"
#include "td/utils/buffer.h"
#include "td/utils/port/SocketFd.h"
#include "td/net/TcpListener.h"
#include "td/actor/actor.h"
#include "td/net/Pipe.h"
#include "td/net/utils.h"
#include "td/utils/port/path.h"
#include "td/utils/PathView.h"
#include "utils.h"

#include <array>
#include <memory>
#include <string>
#include <sstream>
#include <vector>
#include <unistd.h>
#include <sys/wait.h>
#include <cctype>

namespace cocoon {

// ============================================================================
// Configuration
// ============================================================================

// Allowed services (whitelist)
const std::vector<std::string> ALLOWED_SERVICES = {"cocoon-router.service",
                                                   "cocoon-proxy-runner.service",
                                                   "cocoon-worker-runner.service",
                                                   "cocoon-cert-refresh.service",
                                                   "cocoon-vllm.service",
                                                   "cocoon-health.service",
                                                   "cocoon-ready.target",
                                                   "ssh.service",
                                                   "docker.service",
                                                   "nvidia-tdx.service",
                                                   "cocoon-sglang.service",
                                                   "cocoon-cert-refresh.service",
                                                   "cocoon-cert-refresh.timer",
                                                   "spec.service"};

const std::vector<std::string> CRITICAL_BASELINE_SERVICES = {"cocoon-ready.target", "cocoon-health.service"};
const std::vector<std::string> NON_CRITICAL_BASELINE_SERVICES = {
    "docker.service", "ssh.service", "nvidia-tdx.service", "cocoon-cert-refresh.service", "cocoon-cert-refresh.timer",
    "spec.service"};

std::vector<std::string> MONITORED_SERVICES;

// ============================================================================
// Service Validation & Discovery
// ============================================================================

bool is_valid_service(const std::string& service) {
  return td::contains(ALLOWED_SERVICES, service);
}

std::string normalize_service_name(const std::string& service) {
  if (td::ends_with(service, ".service") || td::ends_with(service, ".target")) {
    return service;
  }

  std::string with_service = service + ".service";
  if (is_valid_service(with_service)) {
    return with_service;
  }

  std::string with_target = service + ".target";
  if (is_valid_service(with_target)) {
    return with_target;
  }

  return service;
}

static bool is_service_file(const std::string& name) {
  return (td::ends_with(name, ".service") || td::ends_with(name, ".target")) && is_valid_service(name);
}

std::vector<std::string> discover_services() {
  std::vector<std::string> services;

  auto status = td::WalkPath::run("/mnt/spec", [&](td::CSlice path, td::WalkPath::Type type) {
    static bool first_dir = true;

    if (type == td::WalkPath::Type::EnterDir) {
      if (!first_dir)
        return td::WalkPath::Action::SkipDir;
      first_dir = false;
    } else if (type == td::WalkPath::Type::RegularFile) {
      std::string filename = td::PathView(path).file_name().str();
      if (is_service_file(filename)) {
        services.push_back(filename);
      }
    }

    return td::WalkPath::Action::Continue;
  });

  if (status.is_error()) {
    LOG(WARNING) << "Failed to scan /mnt/spec: " << status.error();
  }

  // Add baseline services if missing
  auto add_if_missing = [&](const std::vector<std::string>& baseline) {
    for (const auto& s : baseline) {
      if (!td::contains(services, s)) {
        services.push_back(s);
      }
    }
  };

  add_if_missing(CRITICAL_BASELINE_SERVICES);
  add_if_missing(NON_CRITICAL_BASELINE_SERVICES);

  return services;
}

// ============================================================================
// Safe Command Execution
// ============================================================================

td::Result<std::string> exec_command_safe(const std::vector<std::string>& args,
                                          std::vector<int> allowed_exit_codes) {
  if (args.empty()) {
    return td::Status::Error("Empty command");
  }

  std::vector<char*> argv_array;
  for (const auto& arg : args) {
    argv_array.push_back(const_cast<char*>(arg.c_str()));
  }
  argv_array.push_back(nullptr);

  int pipefd[2];
  if (pipe(pipefd) == -1) {
    return td::Status::Error(PSLICE() << "pipe: " << strerror(errno));
  }

  pid_t pid = fork();
  if (pid == -1) {
    int err = errno;
    close(pipefd[0]);
    close(pipefd[1]);
    return td::Status::Error(PSLICE() << "fork: " << strerror(err));
  }

  if (pid == 0) {
    // Child process
    close(pipefd[0]);
    dup2(pipefd[1], STDOUT_FILENO);
    dup2(pipefd[1], STDERR_FILENO);
    close(pipefd[1]);
    execvp(argv_array[0], argv_array.data());
    _exit(1);
  }

  // Parent process
  close(pipefd[1]);

  std::string result;
  std::array<char, 4096> buffer;
  ssize_t count;

  while ((count = read(pipefd[0], buffer.data(), buffer.size())) > 0) {
    result.append(buffer.data(), count);
  }

  close(pipefd[0]);

  int status;
  while (waitpid(pid, &status, 0) == -1 && errno == EINTR) {
  }

  int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  bool is_allowed = std::find(allowed_exit_codes.begin(), allowed_exit_codes.end(), exit_code) !=
                    allowed_exit_codes.end();

  if (is_allowed) {
    return result;
  }

  return td::Status::Error(PSLICE() << "Command exited with code " << exit_code);
}

// ============================================================================
// Command Handlers
// ============================================================================

namespace handlers {

td::Result<std::string> status(std::istringstream& args, const StatsCollector&) {
  std::string service;
  args >> service;

  if (service.empty()) {
    return render_service::render_all_status();
  }

  service = normalize_service_name(service);
  return render_service::get_status_human(service);
}

td::Result<std::string> logs(std::istringstream& args, const StatsCollector&) {
  std::string svc;
  int lines = 100;
  args >> svc >> lines;

  if (svc.empty()) {
    return td::Status::Error("Usage: logs <service> [lines]");
  }

  return render_service::get_logs(normalize_service_name(svc), lines);
}

td::Result<std::string> sys(std::istringstream&, const StatsCollector& stats) {
  return render_system_metrics(metrics::collect_all(), stats);
}

td::Result<std::string> svc(std::istringstream& args, const StatsCollector& stats) {
  std::string service;
  args >> service;

  if (service.empty()) {
    return td::Status::Error("Usage: svc <service>");
  }

  service = normalize_service_name(service);
  if (!is_valid_service(service)) {
    return td::Status::Error("Invalid or unauthorized service name");
  }

  return render_service::render_info(service, stats);
}

td::Result<std::string> tdx_cmd(std::istringstream&, const StatsCollector&) {
  return render_tdx::get_status();
}

td::Result<std::string> tdx_eventlog(std::istringstream&, const StatsCollector&) {
  return render_tdx::get_event_log();
}

td::Result<std::string> gpu(std::istringstream&, const StatsCollector&) {
  return render_gpu::get_metrics();
}

td::Result<std::string> all(std::istringstream&, const StatsCollector& stats) {
  auto m = metrics::collect_all();

  std::ostringstream out;
  out << render_system_metrics(m, stats) << "\n";

  auto gpu_out = render_gpu::get_metrics();
  if (gpu_out.find("Error:") == std::string::npos) {
    out << gpu_out << "\n";
  }

  out << render_tdx::get_status() << "\n";
  out << render_service::render_all_status();

  return out.str();
}

}  // namespace handlers

// ============================================================================
// Request Processing
// ============================================================================

td::Result<std::string> process_request(const std::string& request, const StatsCollector& stats) {
  std::istringstream iss(request);
  std::string command;
  iss >> command;

  // Dispatch table
  using Handler = td::Result<std::string> (*)(std::istringstream&, const StatsCollector&);
  static const std::map<std::string, Handler> dispatch = {
      {"status", handlers::status}, {"logs", handlers::logs},         {"sys", handlers::sys},
      {"svc", handlers::svc},       {"tdx", handlers::tdx_cmd},       {"gpu", handlers::gpu},
      {"all", handlers::all},       {"eventlog", handlers::tdx_eventlog}};

  auto it = dispatch.find(command);
  if (it != dispatch.end()) {
    return it->second(iss, stats);
  }

  return td::Status::Error("Unknown command. Available: status, logs, sys, svc, tdx, eventlog, gpu, all");
}

// ============================================================================
// Network Actors
// ============================================================================

class Worker final : public td::TaskActor<td::Unit> {
 public:
  Worker(td::SocketPipe pipe, std::shared_ptr<const StatsCollector> stats)
      : pipe_(std::move(pipe)), stats_(std::move(stats)) {
  }

 private:
  td::SocketPipe pipe_;
  std::shared_ptr<const StatsCollector> stats_;

  void start_up() override {
    LOG(INFO) << "New client connected";
    pipe_.subscribe();
  }

  td::Task<Action> task_loop_once() override {
    co_await pipe_.flush_read();

    td::BufferSlice request_buf;
    auto needed = co_await framed_read(pipe_.input_buffer(), request_buf);
    if (needed > 0) {
      co_return Action::KeepRunning;
    }

    std::string request = request_buf.as_slice().str();
    LOG(INFO) << "Received request: " << request;

    auto result = process_request(request, *stats_);

    std::string response;
    if (result.is_ok()) {
      response = result.move_as_ok();
    } else {
      response = "{\"error\":\"" + result.error().message().str() + "\"}";
    }

    LOG(INFO) << "Sending response (" << response.size() << " bytes)";

    co_await framed_write(pipe_.output_buffer(), response, 20 * (1 << 20));
    co_await pipe_.flush_write();
    co_return Action::KeepRunning;
  }

  td::Task<td::Unit> finish(td::Status status) override {
    if (status.is_error()) {
      LOG(INFO) << "Connection closed with error: " << status.error();
    } else {
      LOG(INFO) << "Connection closed successfully";
    }
    co_return td::Unit{};
  }
};

class Server final : public td::actor::Actor {
 public:
  struct Config {
    td::int32 port_;
  };

  explicit Server(Config config) : config_(std::make_shared<Config>(std::move(config))) {
  }

 private:
  td::actor::ActorOwn<td::TcpListener> listener_;
  std::shared_ptr<const Config> config_;

  // Stats collector (owned by server)
  StatsCollector stats_;
  std::shared_ptr<const StatsCollector> current_stats_;

  void start_up() override {
    LOG(INFO) << "health-monitor listening on vsock port " << config_->port_;
    // Initialize current stats
    current_stats_ = std::make_shared<const StatsCollector>(stats_);

    struct Callback : public td::TcpListener::Callback {
      std::shared_ptr<const StatsCollector>* stats_ptr_;  // Pointer to Server's current_stats_

      explicit Callback(std::shared_ptr<const StatsCollector>* stats_ptr) : stats_ptr_(stats_ptr) {
      }

      void accept(td::SocketFd fd) override {
        auto pipe = td::make_socket_pipe(std::move(fd));
        // Get the LATEST stats from Server
        td::spawn_task_actor<Worker>("HealthWorker", std::move(pipe), *stats_ptr_).detach("worker");
      }
    };

    auto options = td::actor::ActorOptions().with_name("Listener").with_poll(true);
    listener_ = td::actor::create_actor<td::TcpListener>(options, config_->port_,
                                                         std::make_unique<Callback>(&current_stats_), "@vsock");

    // Start background stats collection (every 1 second)
    alarm_timestamp() = td::Timestamp::in(1.0);
  }

  void alarm() override {
    // Collect metrics and update trackers
    auto m = metrics::collect_all();

    // Update system stats
    stats_.update_cpu(m.cpu_total_ticks, m.cpu_idle_ticks);

    for (const auto& [device, io] : m.disk_io) {
      stats_.update_disk(device, io.first, io.second);
    }

    for (const auto& [iface, io] : m.net_io) {
      stats_.update_network(iface, io.first, io.second);
    }

    // Update per-service stats
    for (const auto& svc : MONITORED_SERVICES) {
      auto result = render_service::get_status(svc);
      if (result.is_ok()) {
        auto svc_m = metrics::parse_service_metrics(svc, result.ok());
        if (svc_m.pid > 0) {  // Only track if service has a PID
          stats_.update_service(svc, svc_m.cpu_usage_nsec, svc_m.io_read_bytes, svc_m.io_write_bytes, svc_m.pid);
        }
      }
    }

    // Update shared pointer (copy-on-write pattern)
    current_stats_ = std::make_shared<const StatsCollector>(stats_);

    // Schedule next update
    alarm_timestamp() = td::Timestamp::in(1.0);
  }
};

}  // namespace cocoon

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(INFO));

  constexpr int SCHEDULER_THREADS = 1;
  constexpr int SCHEDULER_TIMEOUT_MS = 10;
  constexpr td::int32 DEFAULT_VSOCK_PORT = 9999;

  td::int32 vsock_port = DEFAULT_VSOCK_PORT;

  td::OptionParser option_parser;
  option_parser.add_checked_option('p', "port", "VSOCK port to listen on", [&](td::Slice port_str) {
    TRY_RESULT(port, td::to_integer_safe<td::int32>(port_str));
    if (port <= 0 || port > 65535) {
      return td::Status::Error("Invalid port number");
    }
    vsock_port = port;
    return td::Status::OK();
  });

  option_parser.add_option('h', "help", "Show this help message", [&]() {
    LOG(PLAIN) << option_parser;
    std::_Exit(0);
  });

  option_parser.set_description("health-monitor: listen on vsock and answer health check requests");

  auto r_args = option_parser.run(argc, argv, -1);
  if (r_args.is_error()) {
    LOG(ERROR) << r_args.error();
    LOG(ERROR) << option_parser;
    return 1;
  }

  LOG(INFO) << "Starting health-monitor on vsock port " << vsock_port;

  cocoon::MONITORED_SERVICES = cocoon::discover_services();

  LOG(INFO) << "Monitoring " << cocoon::MONITORED_SERVICES.size() << " services/targets";
  for (const auto& s : cocoon::MONITORED_SERVICES) {
    LOG(INFO) << "  - " << s;
  }

  td::actor::Scheduler sched({SCHEDULER_THREADS});

  sched.run_in_context([&] {
    cocoon::Server::Config config{.port_ = vsock_port};
    td::actor::create_actor<cocoon::Server>("HealthMonitor", std::move(config)).release();
  });

  sched.start();
  LOG(INFO) << "health-monitor started";

  while (sched.run(SCHEDULER_TIMEOUT_MS)) {
  }

  LOG(INFO) << "health-monitor stopped";
  return 0;
}
