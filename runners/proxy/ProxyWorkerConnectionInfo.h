#pragma once

#include "runners/BaseRunner.hpp"
#include "runners/helpers/AmortCounter.h"
#include "ProxyWorkerInfo.h"
#include <atomic>
#include <memory>

namespace cocoon {

class ProxyRunner;

struct ProxyWorkerConnectionInfo : public std::enable_shared_from_this<ProxyWorkerConnectionInfo> {
  ProxyWorkerConnectionInfo(std::shared_ptr<ProxyWorkerInfo> info, TcpClient::ConnectionId connection_id,
                            td::Bits256 worker_hash, std::string model_name, td::int64 coefficient,
                            td::int32 max_active_requests, bool is_disabled, std::string machine_description_json)
      : info(info)
      , connection_id(connection_id)
      , worker_hash(worker_hash)
      , model_name(model_name)
      , coefficient(coefficient)
      , max_active_requests(max_active_requests)
      , is_disabled(is_disabled)
      , machine_description_json_(std::move(machine_description_json)) {
    auto p = model_name.find('@');
    if (p == std::string::npos) {
      model_name_base = model_name;
    } else {
      model_name_base = model_name.substr(0, p);
    }
  }
  td::int32 weight() const {
    return 1;
  }
  auto running_queries() const {
    return running_queries_.load(std::memory_order_acquire);
  }

  std::shared_ptr<ProxyWorkerInfo> info;
  TcpClient::ConnectionId connection_id;
  td::Bits256 worker_hash;
  std::string model_name;
  std::string model_name_base;
  td::int64 coefficient;
  td::int32 max_active_requests;
  bool is_disabled;
  std::string machine_description_json_;

  void forwarded_query() {
    running_queries_++;
  }

  void forwarded_query_failed(double work_time, double worker_time) {
    running_queries_--;
    total_queries_ += 1;
    total_queries_time_ += work_time;
    total_worker_queries_time_ += work_time;
    total_queries_failed_ += 1;
  }

  void forwarded_query_success(double work_time, double worker_time) {
    running_queries_--;
    total_queries_ += 1;
    total_queries_time_ += work_time;
    total_worker_queries_time_ += work_time;
    total_queries_success_ += 1;
  }

  void store_stats(td::StringBuilder &sb);
  void store_stats(SimpleJsonSerializer &jb);

  double average_query_time() {
    auto v1 = total_queries_();
    auto v2 = total_queries_time_();

    if (v1 <= 0.1) {
      return 0;
    } else {
      return v2 / v1;
    }
  }

  // Queries finished in the last ~10 minutes (amortized). Used to share idle-time traffic fairly between workers.
  double recent_queries() {
    return total_queries_();
  }

  double average_query_overhead() {
    auto v1 = total_queries_();
    auto v2 = total_worker_queries_time_();
    auto v3 = total_queries_time_();

    if (v1 <= 0.1) {
      return 0;
    } else {
      return (v3 - v2) / v1;
    }
  }

  double queries_success_rate() {
    auto v1 = total_queries_success_();
    auto v2 = total_queries_();
    if (v2 <= 0.1) {
      return 1;
    } else {
      return v1 / v2;
    }
  }

 private:
  std::atomic<td::int32> running_queries_{0};
  AmortCounter total_queries_time_{600.0};
  AmortCounter total_worker_queries_time_{600.0};
  AmortCounter total_queries_{600.0};
  AmortCounter total_queries_success_{600.0};
  AmortCounter total_queries_failed_{600.0};
};

}  // namespace cocoon
