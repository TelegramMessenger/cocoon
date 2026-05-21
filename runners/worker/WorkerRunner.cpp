#include "WorkerRunner.h"
#include "WorkerUplinkMonitor.h"

#include "auto/tl/cocoon_api.h"
#include "checksum.h"
#include "cocoon-tl-utils/cocoon-common-utils.hpp"
#include "cocoon-tl-utils/cocoon-tl-utils.hpp"
#include "common/bitstring.h"
#include "errorcode.h"
#include "nlohmann/json_fwd.hpp"
#include "runners/helpers/HttpSender.hpp"

#include "git.h"

#include "td/actor/actor.h"
#include "td/utils/Random.h"
#include "td/utils/Time.h"
#include "td/utils/buffer.h"
#include "td/utils/common.h"
#include "td/utils/filesystem.h"
#include "td/utils/format.h"
#include "td/utils/port/Clocks.h"
#include "tl/TlObject.h"
#include "tl/tl/tl_json.h"
#include "auto/tl/cocoon_api_json.h"
#include <memory>

#if __has_include(<unistd.h>)
#include <unistd.h>
#include <sys/wait.h>
#define HAS_UNISTD 1
#else
#define HAS_UNISTD 0
#endif

namespace cocoon {

/*
 *
 * PAYOUT
 *
 */

void WorkerRunner::proxy_request_payout(WorkerProxyInfo &proxy) {
  auto msg = proxy.run_payout();
  cocoon_wallet()->send_transaction(proxy.worker_sc_address(), to_nano(0.5), {}, std::move(msg),
                                    [self_id = actor_id(this), proxy_sc_address = proxy.proxy_sc_address().rserialize(
                                                                   true)](td::Result<td::Unit> R) {});
}

/*
 *
 * REQUEST 
 *
 */

void WorkerRunner::receive_request(WorkerProxyInfo &proxy, TcpClient::ConnectionId connection_id,
                                   cocoon_api::proxy_runQueryEx &req) {
  auto conn = static_cast<WorkerProxyConnection *>(get_connection(connection_id));
  if (!conn) {
    return;
  }
  auto proto_version = conn->proto_version();
  if (active_requests_ >= max_active_requests_) {
    td::BufferSlice res = cocoon::create_serialize_tl_object<cocoon_api::proxy_queryAnswerErrorEx>(
        req.request_id_, ton::ErrorCode::error, "too many active queries", 1,
        ton::create_tl_object<cocoon_api::proxy_queryFinalInfo>(
            (proto_version >= 2 ? 2 : 0), ton::create_tl_object<cocoon_api::tokensUsed>(0, 0, 0, 0, 0), "",
            td::Clocks::system(), td::Clocks::system()));
    send_message_to_connection(connection_id, std::move(res));
    return;
  }

  if (!(req.flags_ & 2)) {
    req.private_key_ = td::Bits256::zero();
  }

  proxy.update_payment_info(std::move(req.signed_payment_));
  active_requests_++;

  td::actor::create_actor<WorkerRunningRequest>(
      PSTRING() << "request_" << req.request_id_.to_hex(), req.request_id_, connection_id, std::move(req.query_),
      req.private_key_, req.timeout_, forward_requests_to_, model_base_name(), req.coefficient_, proto_version,
      (req.flags_ & 1) && req.enable_debug_, proxy.sc()->runner_config(), actor_id(this), scheduler(), stats_)
      .release();
}

/*
 *
 * INITIALIZATION
 *
 */

void WorkerRunner::load_config(td::Promise<td::Unit> promise) {
  auto S = [&]() -> td::Status {
    TRY_RESULT_PREFIX(conf_data, td::read_file(engine_config_filename()), "failed to read: ");
    TRY_RESULT_PREFIX(conf_json, td::json_decode(conf_data.as_slice()), "failed to parse json: ");

    cocoon::cocoon_api::workerRunner_config conf;
    TRY_STATUS_PREFIX(cocoon::cocoon_api::from_json(conf, conf_json.get_object()), "json does not fit TL scheme: ");
    set_testnet(conf.is_testnet_);
    set_number_of_proxy_connections(conf.proxy_connections_, false);
    if (conf.http_port_) {
      set_http_port((td::uint16)conf.http_port_);
    }

    TRY_RESULT_PREFIX(owner_address, block::StdAddress::parse(conf.owner_address_), "failed to parse owner address: ");
    owner_address.testnet = is_testnet();
    owner_address.bounceable = false;
    set_owner_address(owner_address);

    TRY_RESULT_PREFIX(rc_address, block::StdAddress::parse(conf.root_contract_address_),
                      "cannot parse root contract address: ");
    rc_address.testnet = is_testnet();
    rc_address.bounceable = false;
    set_root_contract_address(rc_address);

    if (conf.ton_config_filename_.size() > 0) {
      set_ton_config_filename(conf.ton_config_filename_);
    }

    set_coefficient(conf.coefficient_);

    wallet_private_key_ = std::make_unique<td::Ed25519::PrivateKey>(td::SecureString(conf.node_wallet_key_.as_slice()));
    wallet_public_key_.as_slice().copy_from(wallet_private_key_->get_public_key().move_as_ok().as_octet_string());
    TRY_STATUS(connection_to_proxy_via(conf.connect_to_proxy_via_));

    local_image_hash_unverified_ = conf.image_hash_;
    set_check_image_hashes(conf.check_proxy_hashes_ || !conf.is_test_);

    TRY_STATUS(create_http_client(conf.forward_requests_to_));
    set_model_name(conf.model_name_);
    set_http_access_hash(conf.http_access_hash_);
    set_is_test(conf.is_test_);

    if (conf.max_active_requests_ > 0) {
      set_max_active_requests(conf.max_active_requests_);
    }

    change_model_script_ = conf.change_model_script_;
    machine_description_json_ = conf.machine_description_json_;

    if (machine_description_json_.size() == 0) {
      machine_description_json_ = "{}";
    }

    auto r = nlohmann::json::parse(machine_description_json_);
    CHECK(r.is_object());

    return td::Status::OK();
  }();
  if (S.is_error()) {
    promise.set_error(std::move(S));
  } else {
    promise.set_value(td::Unit());
  }
}

td::Status WorkerRunner::create_http_client(td::Slice S) {
  auto p = S.find(':');
  td::uint16 port;
  if (p != td::Slice::npos) {
    TRY_RESULT_ASSIGN(port, td::to_integer_safe<td::uint16>(S.copy().remove_prefix(p + 1)));
    S.truncate(p);
  } else {
    port = 0;
  }

  td::IPAddress addr;
  TRY_STATUS(addr.init_host_port(S.str(), port));

  class Cb : public ton::http::HttpClient::Callback {
   public:
    Cb(td::actor::ActorId<WorkerRunner> self_id) : self_id_(self_id) {
    }
    void on_ready() override {
      td::actor::send_closure(self_id_, &WorkerRunner::set_http_ready, true);
    }
    void on_stop_ready() override {
      td::actor::send_closure(self_id_, &WorkerRunner::set_http_ready, false);
    }

   private:
    td::actor::ActorId<WorkerRunner> self_id_;
  };

  forward_requests_to_ = addr;
  http_client_ = ton::http::HttpClient::create_multi("", addr, 100, 100, std::make_shared<Cb>(actor_id(this)));
  return td::Status::OK();
}

void WorkerRunner::custom_initialize(td::Promise<td::Unit> promise) {
  params_version_ = runner_config()->root_contract_config->params_version();

  register_custom_http_handler("/stats", [&](http::HttpCallback::RequestType request_type,
                                             std::vector<std::pair<std::string, std::string>> headers, std::string path,
                                             std::vector<std::pair<std::string, std::string>> args, std::string body,
                                             std::unique_ptr<http::HttpRequestCallback> answer_callback) {
    http_send_static_answer(http_generate_main(), std::move(answer_callback));
  });
  register_custom_http_handler(
      "/jsonstats",
      [&](http::HttpCallback::RequestType request_type, std::vector<std::pair<std::string, std::string>> headers,
          std::string path, std::vector<std::pair<std::string, std::string>> args, std::string body,
          std::unique_ptr<http::HttpRequestCallback> answer_callback) {
        http_send_static_answer(http_generate_json_stats(), std::move(answer_callback), "application/json");
      });
  register_custom_http_handler(
      "/request/payout",
      [&](http::HttpCallback::RequestType request_type, std::vector<std::pair<std::string, std::string>> headers,
          std::string path, std::vector<std::pair<std::string, std::string>> args, std::string body,
          std::unique_ptr<http::HttpRequestCallback> answer_callback) {
        http_send_static_answer(http_payout(get_from_sorted_list(args, "proxy")), std::move(answer_callback));
      });
  register_custom_http_handler(
      "/request/enable",
      [&](http::HttpCallback::RequestType request_type, std::vector<std::pair<std::string, std::string>> headers,
          std::string path, std::vector<std::pair<std::string, std::string>> args, std::string body,
          std::unique_ptr<http::HttpRequestCallback> answer_callback) {
        http_send_static_answer(http_worker_set_force_disabled(false), std::move(answer_callback));
      });
  register_custom_http_handler(
      "/request/disable",
      [&](http::HttpCallback::RequestType request_type, std::vector<std::pair<std::string, std::string>> headers,
          std::string path, std::vector<std::pair<std::string, std::string>> args, std::string body,
          std::unique_ptr<http::HttpRequestCallback> answer_callback) {
        http_send_static_answer(http_worker_set_force_disabled(true), std::move(answer_callback));
      });
  register_custom_http_handler(
      "/request/change_coefficient",
      [&](http::HttpCallback::RequestType request_type, std::vector<std::pair<std::string, std::string>> headers,
          std::string path, std::vector<std::pair<std::string, std::string>> args, std::string body,
          std::unique_ptr<http::HttpRequestCallback> answer_callback) {
        http_send_static_answer(http_worker_change_coefficient(get_from_sorted_list(args, "coefficient")),
                                std::move(answer_callback));
      });

  cocoon_wallet_initialize_wait_for_balance_and_get_seqno(
      wallet_private_key_->as_octet_string(), owner_address_, min_wallet_balance(),
      [self_id = actor_id(this), promise = std::move(promise)](td::Result<td::Unit> R) mutable {
        if (R.is_error()) {
          promise.set_error(R.move_as_error());
          return;
        }
        promise.set_value(td::Unit());
      });

  td::actor::create_actor<WorkerUplinkMonitor>("uplinkmonitor", forward_requests_to_, actor_id(this), scheduler())
      .release();
}

/*
 *
 * CRON
 *
 */

void WorkerRunner::alarm() {
  BaseRunner::alarm();

  if (runner_config() && runner_config()->root_contract_config->params_version() > params_version_) {
    close_all_connections();
    params_version_ = runner_config()->root_contract_config->params_version();
  }
  if (check_image_hashes()) {
    auto c = runner_config();
    if (c) {
      LOG_CHECK(c->root_contract_config->has_worker_hash(local_image_hash_unverified_))
          << "Root contract has no worker hash: " << local_image_hash_unverified_.to_hex();
      LOG_CHECK(c->root_contract_config->has_model_hash(td::sha256_bits256(model_name_)))
          << "Root contract has no model hash: " << td::sha256_bits256(model_name_).to_hex();
    }
  }
  if (next_check_all_clients_at_.is_in_past()) {
    next_check_all_clients_at_ = td::Timestamp::in(td::Random::fast(10, 20));
    iterate_check_map(proxies_);
  }
  if (next_payment_compare_at_.is_in_past()) {
    next_payment_compare_at_ = td::Timestamp::in(td::Random::fast(10, 20));
    foreach_proxy_target([&](ProxyTarget *p) {
      if (!p->is_ready()) {
        return;
      }
      auto conn_id = p->connection_id();
      auto c = static_cast<WorkerProxyConnection *>(get_connection(conn_id));
      if (!c || !c->handshake_is_completed()) {
        return;
      }

      send_query_to_connection(
          conn_id, "paymentcompare", cocoon::create_serialize_tl_object<cocoon_api::worker_updatePaymentStatus>(),
          td::Timestamp::in(60.0),
          [self_id = actor_id(this), proxy_sc_address_str = c->proxy_sc_address_str()](td::Result<td::BufferSlice> R) {
            if (R.is_ok()) {
              td::actor::send_closure(self_id, &WorkerRunner::update_proxy_payment_status, proxy_sc_address_str,
                                      R.move_as_ok());
            }
          });
    });
  }
  alarm_timestamp().relax(next_payment_compare_at_);
  alarm_timestamp().relax(next_check_all_clients_at_);
}

/*
 *
 * INBOUND MESSAGE HANDLERS
 *
 */

void WorkerRunner::receive_message(TcpClient::ConnectionId connection_id, td::BufferSlice query) {
  auto conn = static_cast<WorkerProxyConnection *>(get_connection(connection_id));
  if (!conn || !conn->is_ready()) {
    LOG(ERROR) << "dropping received message: connection not ready";
    return;
  }
  auto it = proxies_.find(conn->proxy_sc_address_str());
  if (it == proxies_.end()) {
    LOG(ERROR) << "dropping received message: unknown proxy";
    return;
  }

  auto proxy = it->second.get();

  auto magic = get_tl_magic(query);
  switch (magic) {
    case cocoon_api::proxy_signedPaymentEmpty::ID:
      break;
    case cocoon_api::proxy_signedPayment::ID: {
      auto R = fetch_tl_object<cocoon_api::proxy_signedPayment>(query, true);
      if (R.is_error()) {
        return;
      }
      auto obj = R.move_as_ok();
      proxy->update_payment_info(std::move(obj));
    } break;
    case cocoon_api::proxy_runQuery::ID: {
      proxy->received_request_from_proxy();
      auto R = fetch_tl_object<cocoon_api::proxy_runQuery>(query, true);
      if (R.is_error()) {
        LOG(ERROR) << "received malformed message from proxy: " << R.move_as_error();
        return;
      }
      auto obj = R.move_as_ok();
      auto ex_obj = ton::create_tl_object<cocoon_api::proxy_runQueryEx>(
          std::move(obj->query_), std::move(obj->signed_payment_), obj->coefficient_, obj->timeout_, obj->request_id_,
          0, false, td::Bits256::zero());
      receive_request(*proxy, connection_id, *ex_obj);
    } break;
    case cocoon_api::proxy_runQueryEx::ID: {
      proxy->received_request_from_proxy();
      auto R = fetch_tl_object<cocoon_api::proxy_runQueryEx>(query, true);
      if (R.is_error()) {
        LOG(ERROR) << "received malformed message from proxy: " << R.move_as_error();
        return;
      }
      auto obj = R.move_as_ok();
      receive_request(*proxy, connection_id, *obj);
    } break;
    case cocoon_api::proxy_workerRequestPayment::ID: {
      auto R = fetch_tl_object<cocoon_api::proxy_workerRequestPayment>(query, true);
      if (R.is_error()) {
        LOG(ERROR) << "received malformed message from proxy: " << R.move_as_error();
        return;
      }
      auto obj = R.move_as_ok();
      /* we already have newer information. This shouldn't happen, so close we close the connection
       * in order to restart a handshake to compare information*/
      if (!proxy->update_payment_info(std::move(obj->signed_payment_))) {
        close_connection(connection_id);
        return;
      }
      if (!proxy->update_tokens_committed_to_proxy_db(obj->db_tokens_)) {
        close_connection(connection_id);
        return;
      }
      if (!proxy->update_tokens_max_known(obj->max_tokens_)) {
        close_connection(connection_id);
        return;
      }

      // TODO add last transaction info
    } break;
    default:
      LOG(ERROR) << "dropping received message: received message with unknown magic " << td::format::as_hex(magic);
  }
}

void WorkerRunner::receive_query(TcpClient::ConnectionId connection_id, td::BufferSlice query,
                                 td::Promise<td::BufferSlice> promise) {
  auto conn = static_cast<WorkerProxyConnection *>(get_connection(connection_id));
  if (!conn || !conn->is_ready()) {
    return promise.set_error(td::Status::Error(ton::ErrorCode::failure, "connection is closed"));
  }
  auto it = proxies_.find(conn->proxy_sc_address_str());
  if (it == proxies_.end()) {
    return promise.set_error(td::Status::Error(ton::ErrorCode::failure, "unknown proxy"));
  }

  auto magic = get_tl_magic(query);
  switch (magic) {
    case cocoon_api::worker_changeModel::ID: {
      TRY_RESULT_PROMISE(promise, obj, cocoon::fetch_tl_object<cocoon_api::worker_changeModel>(std::move(query), true));
      TRY_STATUS_PROMISE(promise, change_model(obj->new_model_));
      promise.set_value(cocoon::create_serialize_tl_object<cocoon_api::worker_changedModel>());
      return;
    }
    default:
      LOG(ERROR) << "dropping received query: received query with unknown magic " << td::format::as_hex(magic);
  }
}

/*
 *
 * PROXY DB
 *
 */

td::Result<std::shared_ptr<WorkerProxyInfo>> WorkerRunner::register_proxy(
    TcpClient::ConnectionId connection_id, td::Bits256 proxy_public_key, block::StdAddress proxy_owner_address,
    block::StdAddress proxy_sc_address, block::StdAddress worker_sc_address,
    ton::tl_object_ptr<cocoon_api::proxy_SignedPayment> payment) {
  auto proxy_sc_address_str = proxy_sc_address.rserialize(true);
  auto it = proxies_.find(proxy_sc_address_str);
  if (it != proxies_.end()) {
    if (it->second->proxy_public_key() != proxy_public_key) {
      return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << "PROXY PUBLIC KEY CHANGED: was "
                                                                         << it->second->proxy_public_key().to_hex()
                                                                         << " now " << proxy_public_key.to_hex());
    }
    if (it->second->proxy_sc_address() != proxy_sc_address) {
      return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << "PROXY SC ADDRESS CHANGED: was "
                                                                         << it->second->proxy_sc_address() << " now "
                                                                         << proxy_sc_address);
    }
    if (it->second->worker_sc_address() != worker_sc_address) {
      return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << "WORKER SC ADDRESS CHANGED: was "
                                                                         << it->second->worker_sc_address() << " now "
                                                                         << worker_sc_address);
    }
  } else {
    auto expected_proxy_sc_address = generate_proxy_sc_address(proxy_public_key, proxy_owner_address, runner_config());
    if (expected_proxy_sc_address != proxy_sc_address) {
      return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << "PROXY SC ADDRESS IS UNEXPECTED: expected "
                                                                         << expected_proxy_sc_address << " got "
                                                                         << proxy_sc_address);
    }
    auto expected_worker_sc_address = generate_worker_sc_address(proxy_public_key, proxy_owner_address,
                                                                 proxy_sc_address, owner_address_, runner_config());
    if (expected_worker_sc_address != worker_sc_address) {
      return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << "WORKER SC ADDRESS IS UNEXPECTED: expected "
                                                                         << expected_worker_sc_address << " got "
                                                                         << worker_sc_address);
    }
    auto P = std::make_shared<WorkerProxyInfo>(this, proxy_public_key, std::move(proxy_sc_address));
    CHECK(P->worker_sc_address() == worker_sc_address);
    it = proxies_.emplace(proxy_sc_address_str, std::move(P)).first;
  }
  it->second->update_payment_info(std::move(payment));
  return it->second;
}

void WorkerRunner::update_proxy_payment_status(const std::string &proxy_sc_address_str, td::BufferSlice info) {
  auto R = cocoon::fetch_tl_object<cocoon_api::worker_paymentStatus>(std::move(info), true);
  if (R.is_error()) {
    return;
  }
  auto obj = R.move_as_ok();
  auto it = proxies_.find(proxy_sc_address_str);
  if (it == proxies_.end()) {
    return;
  }
  it->second->update_payment_info(std::move(obj->signed_payment_));
  it->second->update_tokens_committed_to_proxy_db(obj->db_tokens_);
  it->second->update_tokens_max_known(obj->max_tokens_);
}

/*
 *
 * CONTROL
 *
 */

void WorkerRunner::set_force_disabled(bool value) {
  if (is_force_disabled_ == value) {
    return;
  }

  is_force_disabled_ = value;
  send_state_update_to_proxies();
}

void WorkerRunner::send_state_update_to_proxies() {
  foreach_proxy_target([&](ProxyTarget *T) {
    auto conn_id = T->connection_id();
    if (!conn_id) {
      return;
    }
    auto conn = get_connection(conn_id);
    if (!conn) {
      return;
    }

    send_message_to_connection(conn_id,
                               cocoon::create_serialize_tl_object<cocoon_api::worker_enabledDisabled>(is_disabled()));
  });
}

void WorkerRunner::set_coefficient(td::int32 value) {
  coefficient_ = value;
  foreach_proxy_target([&](ProxyTarget *T) {
    auto conn_id = T->connection_id();
    if (!conn_id) {
      return;
    }
    auto conn = get_connection(conn_id);
    if (!conn) {
      return;
    }

    send_message_to_connection(conn_id, cocoon::create_serialize_tl_object<cocoon_api::worker_newCoefficient>(value));
  });
}

td::Status WorkerRunner::change_model(std::string new_model) {
  if (change_model_script_.size() == 0) {
    return td::Status::Error(ton::ErrorCode::error, "cannot change model: no script in config");
  } else if (!HAS_UNISTD) {
    return td::Status::Error(ton::ErrorCode::error, "cannot change model: cannot exec");
  } else {
    if (check_image_hashes()) {
      if (!runner_config() || !runner_config()->root_contract_config->has_model_hash(td::sha256_bits256(new_model))) {
        return td::Status::Error(ton::ErrorCode::error, "cannot change model: unknown model");
      }
    }
#if HAS_UNISTD
    LOG(WARNING) << "changing model to " << new_model;
    auto v = vfork();
    if (!v) {
      execl(change_model_script_.c_str(), change_model_script_.c_str(), new_model.c_str(), NULL);
      _Exit(77);  // in case execl failed. In vform we can't really handle exec errors
    } else {
      int wstatus = 0;
      auto r = waitpid(v, &wstatus, 0);
      if (r < 0 || !WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
        return td::Status::Error(ton::ErrorCode::error, "cannot change model: model change script failed");
      } else {
        return td::Status::OK();
      }
    }
#endif
  }
}

/*
 *
 * UPLINK
 *
 */

void WorkerRunner::set_uplink_is_ok(bool value) {
  if (uplink_ok_ == value) {
    return;
  }

  uplink_ok_ = value;
  send_state_update_to_proxies();
}

/* 
 *
 * HTTP HANDLING
 *
 */

std::string WorkerRunner::http_generate_main() {
  td::StringBuilder sb;
  sb << "<!DOCTYPE html>\n";
  sb << "<html><body>\n";
  {
    sb << "<h1>STATUS</h1>\n";
    sb << "<table>\n";
    if (cocoon_wallet()) {
      sb << "<tr><td>wallet</td><td>";
      if (cocoon_wallet()->balance() < min_wallet_balance()) {
        sb << "<span style=\"background-color:Crimson;\">balance too low on "
           << address_link(cocoon_wallet()->address()) << "</span>";
      } else if (cocoon_wallet()->balance() < warning_wallet_balance()) {
        sb << "<span style=\"background-color:Gold;\">balance low on " << address_link(cocoon_wallet()->address())
           << "</span>";
      } else {
        sb << "<span style=\"background-color:Green;\">balance ok on " << address_link(cocoon_wallet()->address())
           << "</span>";
      }
      sb << "</td></tr>\n";
    }
    {
      sb << "<tr><td>image</td><td>";
      bool is_valid = runner_config()->root_contract_config->has_worker_hash(local_image_hash_unverified_);
      if (is_valid) {
        sb << "<span style=\"background-color:Green;\">our hash " << local_image_hash_unverified_.to_hex()
           << " is in root contract</span>";
      } else if (check_image_hashes()) {
        sb << "<span style=\"background-color:Crimson;\">our hash " << local_image_hash_unverified_.to_hex()
           << " not found in root contract</span>";
      } else {
        sb << "<span style=\"background-color:Gold;\">cannot check our hash " << local_image_hash_unverified_.to_hex()
           << "</span>";
      }
      sb << "</td></tr>\n";
    }
    {
      sb << "<tr><td>model</td><td>";
      bool is_valid = runner_config()->root_contract_config->has_model_hash(td::sha256_bits256(model_name_));
      if (is_valid) {
        sb << "<span style=\"background-color:Green;\">our model " << model_name_ << " is in root contract</span>";
      } else if (check_image_hashes()) {
        sb << "<span style=\"background-color:Crimson;\">our model " << model_name_
           << " not found in root contract</span>";
      } else {
        sb << "<span style=\"background-color:Gold;\">cannot check our model " << model_name_ << "</span>";
      }
      sb << "</td></tr>\n";
    }
    auto r = runner_config();
    if (r) {
      auto ts = (int)std::time(0);
      sb << "<tr><td>ton</td><td>";
      if (ts - r->root_contract_ts < 600) {
        sb << "<span style=\"background-color:Green;\">synced</span>";
      } else if (ts - r->root_contract_ts < 3600) {
        sb << "<span style=\"background-color:Gold;\">late</span>";
      } else {
        sb << "<span style=\"background-color:Crimson;\">out of sync</span>";
      }
      sb << "</td></tr>\n";
    }
    sb << "<tr><td>enabled</td><td>";
    if (!is_force_disabled_) {
      sb << "<span style=\"background-color:Green;\">yes <a href=\"/request/disable\">disable</a></span>";
    } else {
      sb << "<span style=\"background-color:Crimson;\">no <a href=\"/request/enable\">enable</a></span>";
    }
    sb << "</td></tr>\n";
    sb << "<tr><td>model connection</td><td>";
    if (uplink_ok_) {
      sb << "<span style=\"background-color:Green;\">connected</a></span>";
    } else {
      sb << "<span style=\"background-color:Crimson;\">disconnected</a></span>";
    }
    sb << "</td></tr>\n";
    sb << "<tr><td>version</td><td>commit " << GitMetadata::CommitSHA1() << " at " << GitMetadata::CommitDate()
       << "</td></tr>\n";
    sb << "</table>\n";
  }
  sb << "<h1>STATS</h1>\n";
  sb << "<table>\n";
  sb << "<tr><td>name</td>" << stats_->header() << "</tr>\n";
  sb << "<tr><td>queries</td>" << stats_->requests_received.to_html_row() << "</tr>\n";
  sb << "<tr><td>success</td>" << stats_->requests_success.to_html_row() << "</tr>\n";
  sb << "<tr><td>failed</td>" << stats_->requests_failed.to_html_row() << "</tr>\n";
  sb << "<tr><td>bytes received</td>" << stats_->request_bytes_received.to_html_row() << "</tr>\n";
  sb << "<tr><td>bytes sent</td>" << stats_->answer_bytes_sent.to_html_row() << "</tr>\n";
  sb << "<tr><td>time</td>" << stats_->total_requests_time.to_html_row() << "</tr>\n";
  sb << "<tr><td>total adjusted tokens</td>" << stats_->total_adjusted_tokens_used.to_html_row() << "</tr>\n";
  sb << "<tr><td>prompt adjusted tokens</td>" << stats_->prompt_adjusted_tokens_used.to_html_row() << "</tr>\n";
  sb << "<tr><td>cached adjusted tokens</td>" << stats_->cached_adjusted_tokens_used.to_html_row() << "</tr>\n";
  sb << "<tr><td>completiom adjusted tokens</td>" << stats_->completion_adjusted_tokens_used.to_html_row() << "</tr>\n";
  sb << "<tr><td>reasoning adjusted tokens</td>" << stats_->reasoning_adjusted_tokens_used.to_html_row() << "</tr>\n";
  sb << "</table>\n";

  store_wallet_stat(sb);
  {
    sb << "<h1>LOCAL CONFIG</h1>\n";
    sb << "<table>\n";
    sb << "<tr><td>root address</td><td>" << address_link(root_contract_address()) << "</td></tr>\n";
    sb << "<tr><td>owner address</td><td>" << address_link(owner_address()) << "</td></tr>\n";
    sb << "<tr><td>model</td><td>" << model_name_ << "</td></tr>\n";
    sb << "<tr><td>model hash</td><td>" << td::sha256_bits256(model_name_).to_hex() << "</td></tr>\n";
    sb << "<tr><td>coefficient</td><td>" << (coefficient_ * 0.001)
       << " <a href=\"/request/change_coefficient\">change</a></td></tr>\n";
    sb << "<tr><td>max_active_requests</td><td>" << max_active_requests_ << "</td></tr>\n";
    sb << "<tr><td>active_requests</td><td>" << active_requests_ << "</td></tr>\n";
    sb << "<tr><td>check proxy hash</td><td>" << (check_image_hashes() ? "YES" : "NO") << "</td></tr>\n";
    sb << "</table>\n";
  }
  store_root_contract_stat(sb);

  {
    sb << "<h1>PROXY CONNECTIONS</h1>\n";
    sb << "<table>\n";
    foreach_proxy_target([&](ProxyTarget *p) {
      if (!p) {
        return;
      }
      sb << "<tr><td>" << p->address() << "</td><td>" << (p->is_ready() ? "ready" : "not ready") << "</td><td>";
      auto connection_id = p->connection_id();
      auto conn = static_cast<WorkerProxyConnection *>(get_connection(connection_id));
      if (conn) {
        sb << conn->proxy_sc_address_str();
      }
      sb << "</td></tr>";
    });
    sb << "</table>\n";
  }

  sb << "<h1>PROXIES</h1>\n";
  for (auto &p : proxies_) {
    auto &proxy = *p.second;
    sb << "<h2>PROXY " << p.first << "</h2>\n";
    proxy.store_stats(sb);
  }
  sb << "</body></html>\n";

  return sb.as_cslice().str();
}

std::string WorkerRunner::http_generate_json_stats() {
  SimpleJsonSerializer jb;

  jb.start_object();
  {
    jb.start_object("status");
    if (cocoon_wallet()) {
      jb.add_element("wallet_balance", cocoon_wallet()->balance());
    }
    if (check_image_hashes() && runner_config()) {
      jb.add_element("actual_image_hash",
                     runner_config()->root_contract_config->has_worker_hash(local_image_hash_unverified_));
    } else {
      jb.add_element("actual_image_hash", true);
    }
    if (check_image_hashes() && runner_config()) {
      jb.add_element("actual_model",
                     runner_config()->root_contract_config->has_model_hash(td::sha256_bits256(model_name_)));
    } else {
      jb.add_element("actual_model", true);
    }
    auto r = runner_config();
    if (r) {
      jb.add_element("ton_last_synced_at", r->root_contract_ts);
    }
    jb.add_element("enabled", true);
    jb.add_element("git_commit", GitMetadata::CommitSHA1());
    jb.add_element("git_commit_data", GitMetadata::CommitDate());
    jb.stop_object();
  }
  jb.start_object("stats");
  stats_->requests_received.to_jb(jb, "queries");
  stats_->requests_success.to_jb(jb, "success");
  stats_->requests_failed.to_jb(jb, "failed");
  stats_->request_bytes_received.to_jb(jb, "bytes_received");
  stats_->answer_bytes_sent.to_jb(jb, "bytes_sent");
  stats_->total_requests_time.to_jb(jb, "time");
  stats_->total_adjusted_tokens_used.to_jb(jb, "total_adjusted_tokens_used");
  stats_->prompt_adjusted_tokens_used.to_jb(jb, "prompt_adjusted_tokens_used");
  stats_->cached_adjusted_tokens_used.to_jb(jb, "cached_adjusted_tokens_used");
  stats_->completion_adjusted_tokens_used.to_jb(jb, "completion_adjusted_tokens_used");
  stats_->reasoning_adjusted_tokens_used.to_jb(jb, "reasoning_adjusted_tokens_used");
  jb.stop_object();

  store_wallet_stat(jb);

  {
    jb.start_object("localconfig");
    jb.add_element("root_address", root_contract_address().rserialize(true));
    jb.add_element("owner_address", owner_address().rserialize(true));
    jb.add_element("model", model_name_);
    jb.add_element("coefficient", coefficient_);
    jb.add_element("check_image_hashes", check_image_hashes());
    jb.stop_object();
  }
  store_root_contract_stat(jb);

  jb.start_array("proxies");
  for (auto &p : proxies_) {
    auto &proxy = *p.second;
    proxy.store_stats(jb);
  }

  jb.stop_array();
  jb.stop_object();

  return jb.as_cslice().str();
}

std::string WorkerRunner::http_payout(std::string proxy_sc_address) {
  auto it2 = proxies_.find(proxy_sc_address);
  if (it2 == proxies_.end()) {
    return wrap_short_answer_to_http("proxy not found");
  }

  auto &proxy = *it2->second;

  if (proxy.sc_request_is_running()) {
    return wrap_short_answer_to_http("request is already running");
  }

  if (!proxy.is_inited()) {
    return wrap_short_answer_to_http("proxy is not inited");
  }

  if (proxy.is_closed()) {
    return wrap_short_answer_to_http("proxy is closed");
  }

  proxy_request_payout(proxy);

  return wrap_short_answer_to_http("request sent");
}

std::string WorkerRunner::http_worker_change_coefficient() {
  td::StringBuilder sb;
  sb << "<!DOCTYPE html>\n";
  sb << "<html><body>\n";
  sb << "set new coefficient: ";
  sb << "<form method=\"GET\" action=\"/request/change_coefficient\">"
        "<input type=\"text\" name=\"coefficient\">"
        "<input type=\"submit\" value=\"Submit\">"
        "</form>";
  sb << "</body></html>\n";
  return sb.as_cslice().str();
}

}  // namespace cocoon
