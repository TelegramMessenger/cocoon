/*
 * health-render.h
 * 
 * Header for output formatting functions.
 */

#pragma once

#include "health-metrics.h"
#include "health-stats.h"
#include "td/utils/Status.h"
#include <string>

namespace cocoon {

// Service validation (from health-monitor.cpp)
extern const std::vector<std::string> ALLOWED_SERVICES;
extern const std::vector<std::string> NON_CRITICAL_BASELINE_SERVICES;
extern std::vector<std::string> MONITORED_SERVICES;
bool is_valid_service(const std::string& service);

// Forward declare exec_command_safe
// allowed_exit_codes: list of exit codes that should return output instead of error
td::Result<std::string> exec_command_safe(const std::vector<std::string>& args,
                                          std::vector<int> allowed_exit_codes = {0});

namespace render_service {
td::Result<std::string> get_status(const std::string& svc);
td::Result<std::string> get_status_human(const std::string& svc);
td::Result<std::string> get_logs(const std::string& svc, int lines);
std::string render_info(const std::string& service_name, const StatsCollector& stats);
std::string render_all_status();
}  // namespace render_service

namespace render_tdx {
std::string get_status();
std::string get_event_log();
}

namespace render_gpu {
std::string get_metrics();
}

std::string render_system_metrics(const SystemMetrics& m, const StatsCollector& stats);

}  // namespace cocoon
