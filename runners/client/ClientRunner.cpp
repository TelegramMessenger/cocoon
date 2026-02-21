#include "ClientRunner.hpp"
#include "ClientRunningRequest.h"

#include "auto/tl/cocoon_api.h"
#include "auto/tl/cocoon_api.hpp"
#include "auto/tl/cocoon_api_json.h"
#include "common/bitstring.h"
#include "errorcode.h"
#include "td/actor/actor.h"
#include "td/utils/common.h"
#include "td/utils/filesystem.h"
#include "cocoon-tl-utils/cocoon-tl-utils.hpp"
#include "git.h"
#include <memory>

namespace cocoon {

/* 
 *
 * REQUEST HANDLING
 *
 */

void ClientRunner::run_http_request(
    std::unique_ptr<ton::http::HttpRequest> request, std::shared_ptr<ton::http::HttpPayload> payload,
    td::Promise<std::pair<std::unique_ptr<ton::http::HttpResponse>, std::shared_ptr<ton::http::HttpPayload>>> promise) {
  auto proxy_target = get_ready_proxy_target();
  if (!proxy_target || !proxy_target->is_ready()) {
    return promise.set_error(td::Status::Error(ton::ErrorCode::notready, "no working proxy connections"));
  }

  auto connection = get_connection(proxy_target->connection_id());
  if (!connection || !connection->is_ready()) {
    return promise.set_error(td::Status::Error(ton::ErrorCode::notready, "no working proxy connections (2)"));
  }

  td::Bits256 request_id;
  td::Random::secure_bytes(request_id.as_slice());

  auto proxy_conn = static_cast<ClientProxyConnection *>(connection);
  auto proxy = proxy_conn->proxy();

  proxy->request_started();
  auto active_config_version = runner_config()->root_contract_config->version();
  auto req = td::actor::create_actor<ClientRunningRequest>(
                 PSTRING() << "request_" << request_id.to_hex(), request_id, std::move(request), std::move(payload),
                 std::move(promise), proxy, connection->connection_id(), proxy_conn->proto_version(),
                 active_config_version, actor_id(this))
                 .release();
  running_queries_.emplace(request_id, req);
}

void ClientRunner::run_get_models_request(
    td::Promise<std::pair<std::unique_ptr<ton::http::HttpResponse>, std::shared_ptr<ton::http::HttpPayload>>> promise) {
  auto proxy_target = get_ready_proxy_target();
  if (!proxy_target || !proxy_target->is_ready()) {
    return promise.set_error(td::Status::Error(ton::ErrorCode::notready, "no working proxy connections"));
  }

  auto connection = static_cast<ClientProxyConnection *>(get_connection(proxy_target->connection_id()));
  if (!connection || !connection->is_ready()) {
    return promise.set_error(td::Status::Error(ton::ErrorCode::notready, "no working proxy connections (2)"));
  }

  if (connection->proto_version() == 0) {
    auto request = cocoon::create_serialize_tl_object<cocoon_api::client_getWorkerTypes>();
    send_query_to_connection(
        proxy_target->connection_id(), "request", std::move(request), td::Timestamp::in(10.0),
        [promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            ton::http::answer_error(ton::http::HttpStatusCode::status_gateway_timeout, "gateway timeout",
                                    std::move(promise));
            return;
          }

          auto b = R.move_as_ok();
          auto obj = cocoon::fetch_tl_object<cocoon_api::client_workerTypes>(std::move(b), true).move_as_ok();
          SimpleJsonSerializer jb;
          jb.start_object();
          jb.add_element("object", "list");
          jb.start_array("data");
          for (size_t i = 0; i < obj->types_.size(); i++) {
            auto &e = obj->types_[i];
            jb.start_object();
            jb.add_element("id", e->name_);
            jb.add_element("object", "model");
            jb.add_element("created", 0);
            jb.add_element("owned_by", "?");
            jb.stop_object();
          }
          jb.stop_array();
          jb.add_element("object", "list");
          jb.stop_object();

          auto res = jb.as_cslice().str();
          http_send_static_answer(std::move(res), std::move(promise), "application/json");
        });
  } else {
    auto request = cocoon::create_serialize_tl_object<cocoon_api::client_getWorkerTypesV2>();
    send_query_to_connection(
        proxy_target->connection_id(), "request", std::move(request), td::Timestamp::in(10.0),
        [self = this, promise = std::move(promise)](td::Result<td::BufferSlice> R) mutable {
          if (R.is_error()) {
            self->http_send_static_answer(R.move_as_error_prefix("got error: "), std::move(promise));
            return;
          }

          auto b = R.move_as_ok();
          auto obj = cocoon::fetch_tl_object<cocoon_api::client_workerTypesV2>(std::move(b), true).move_as_ok();
          SimpleJsonSerializer jb;
          jb.start_object();
          jb.add_element("object", "list");
          jb.start_array("data");
          for (size_t i = 0; i < obj->types_.size(); i++) {
            auto &e = obj->types_[i];
            jb.start_object();
            jb.add_element("id", e->name_);
            jb.add_element("object", "model");
            jb.add_element("created", 0);
            jb.add_element("owned_by", "?");
            jb.start_array("workers");
            for (auto &w : e->workers_) {
              jb.start_object();
              jb.add_element("coefficient", w->coefficient_);
              jb.add_element("running_requests", w->active_requests_);
              jb.add_element("max_running_requests", w->max_active_requests_);
              jb.stop_object();
            }
            jb.stop_array();
            jb.stop_object();
          }
          jb.stop_array();
          jb.add_element("object", "list");
          jb.stop_object();

          auto res = jb.as_cslice().str();
          http_send_static_answer(std::move(res), std::move(promise), "application/json");
        });
  }
}

void ClientRunner::finish_request(td::Bits256 request_id, std::shared_ptr<ClientProxyInfo> proxy) {
  CHECK(running_queries_.erase(request_id));
  proxy->request_finished();
}

/*
 *
 * INITIALIZATION
 *
 */

void ClientRunner::load_config(td::Promise<td::Unit> promise) {
  auto S = [&]() -> td::Status {
    TRY_RESULT_PREFIX(conf_data, td::read_file(engine_config_filename()), "failed to read: ");
    TRY_RESULT_PREFIX(conf_json, td::json_decode(conf_data.as_slice()), "failed to parse json: ");

    cocoon::cocoon_api::clientRunner_config conf;
    TRY_STATUS_PREFIX(cocoon::cocoon_api::from_json(conf, conf_json.get_object()), "json does not fit TL scheme: ");
    set_testnet(conf.is_testnet_);
    if (conf.http_port_) {
      set_http_port((td::uint16)conf.http_port_);
    }
    TRY_RESULT_PREFIX(owner_address, block::StdAddress::parse(conf.owner_address_), "cannot parse owner address: ");
    owner_address.testnet = is_testnet();

    TRY_RESULT_PREFIX(rc_address, block::StdAddress::parse(conf.root_contract_address_),
                      "cannot parse root contract address: ");
    rc_address.testnet = is_testnet();
    set_root_contract_address(rc_address);

    if (conf.ton_config_filename_.size() > 0) {
      set_ton_config_filename(conf.ton_config_filename_);
    }

    wallet_private_key_ = std::make_unique<td::Ed25519::PrivateKey>(td::SecureString(conf.node_wallet_key_.as_slice()));
    wallet_public_key_.as_slice().copy_from(wallet_private_key_->get_public_key().move_as_ok().as_octet_string());

    if (conf.connect_to_proxy_via_.size() > 0) {
      TRY_STATUS(connection_to_proxy_via(conf.connect_to_proxy_via_));
    }
    if (conf.check_proxy_hashes_ || !conf.is_test_) {
      set_fake_tdx(false);
      enable_check_proxy_hash();
    } else {
      set_fake_tdx(true);
    }
    set_secret_string(td::SecureString(conf.secret_string_));
    set_number_of_proxy_connections(conf.proxy_connections_, true);
    set_owner_address(owner_address);
    set_http_access_hash(conf.http_access_hash_);
    set_fake_tdx(!check_proxy_hash_);
    set_is_test(conf.is_test_);
    return td::Status::OK();
  }();
  if (S.is_error()) {
    promise.set_error(std::move(S));
  } else {
    promise.set_value(td::Unit());
  }
}

void ClientRunner::custom_initialize(td::Promise<td::Unit> promise) {
  params_version_ = runner_config()->root_contract_config->params_version();
  cocoon_wallet_initialize_wait_for_balance_and_get_seqno(
      wallet_private_key_->as_octet_string(), owner_address_, min_wallet_balance(),
      [self_id = actor_id(this), promise = std::move(promise)](td::Result<td::Unit> R) mutable {
        if (R.is_error()) {
          promise.set_error(R.move_as_error());
          return;
        }
        promise.set_value(td::Unit());
      });

  register_custom_http_handler(
      "/stats",
      [&](std::string url, std::map<std::string, std::string> get_args, std::unique_ptr<ton::http::HttpRequest> request,
          std::shared_ptr<ton::http::HttpPayload> payload,
          td::Promise<std::pair<std::unique_ptr<ton::http::HttpResponse>, std::shared_ptr<ton::http::HttpPayload>>>
              promise) { http_send_static_answer(http_generate_main(), std::move(promise)); });
  register_custom_http_handler(
      "/jsonstats",
      [&](std::string url, std::map<std::string, std::string> get_args, std::unique_ptr<ton::http::HttpRequest> request,
          std::shared_ptr<ton::http::HttpPayload> payload,
          td::Promise<std::pair<std::unique_ptr<ton::http::HttpResponse>, std::shared_ptr<ton::http::HttpPayload>>>
              promise) {
        http_send_static_answer(http_generate_json_stats(), std::move(promise), "application/json");
      });
  register_custom_http_handler(
      "/request/charge",
      [&](std::string url, std::map<std::string, std::string> get_args, std::unique_ptr<ton::http::HttpRequest> request,
          std::shared_ptr<ton::http::HttpPayload> payload,
          td::Promise<std::pair<std::unique_ptr<ton::http::HttpResponse>, std::shared_ptr<ton::http::HttpPayload>>>
              promise) { http_send_static_answer(http_charge(get_args["proxy"]), std::move(promise)); });
  register_custom_http_handler(
      "/request/close",
      [&](std::string url, std::map<std::string, std::string> get_args, std::unique_ptr<ton::http::HttpRequest> request,
          std::shared_ptr<ton::http::HttpPayload> payload,
          td::Promise<std::pair<std::unique_ptr<ton::http::HttpResponse>, std::shared_ptr<ton::http::HttpPayload>>>
              promise) { http_send_static_answer(http_close(get_args["proxy"]), std::move(promise)); });
  register_custom_http_handler(
      "/request/topup",
      [&](std::string url, std::map<std::string, std::string> get_args, std::unique_ptr<ton::http::HttpRequest> request,
          std::shared_ptr<ton::http::HttpPayload> payload,
          td::Promise<std::pair<std::unique_ptr<ton::http::HttpResponse>, std::shared_ptr<ton::http::HttpPayload>>>
              promise) { http_send_static_answer(http_top_up(get_args["proxy"]), std::move(promise)); });
  register_custom_http_handler(
      "/request/withdraw",
      [&](std::string url, std::map<std::string, std::string> get_args, std::unique_ptr<ton::http::HttpRequest> request,
          std::shared_ptr<ton::http::HttpPayload> payload,
          td::Promise<std::pair<std::unique_ptr<ton::http::HttpResponse>, std::shared_ptr<ton::http::HttpPayload>>>
              promise) { http_send_static_answer(http_withdraw(get_args["proxy"]), std::move(promise)); });
  register_custom_http_handler(
      "/request/debuglogentry",
      [&](std::string url, std::map<std::string, std::string> get_args, std::unique_ptr<ton::http::HttpRequest> request,
          std::shared_ptr<ton::http::HttpPayload> payload,
          td::Promise<std::pair<std::unique_ptr<ton::http::HttpResponse>, std::shared_ptr<ton::http::HttpPayload>>>
              promise) {
        http_send_static_answer(http_get_request_debug_info(get_args["request_guid"]), std::move(promise),
                                "application/json");
      });
  register_custom_http_handler(
      "/favicon.ico",
      [&](std::string url, std::map<std::string, std::string> get_args, std::unique_ptr<ton::http::HttpRequest> request,
          std::shared_ptr<ton::http::HttpPayload> payload,
          td::Promise<std::pair<std::unique_ptr<ton::http::HttpResponse>, std::shared_ptr<ton::http::HttpPayload>>>
              promise) { promise.set_error(td::Status::Error(ton::ErrorCode::error, "not found")); });
}

/* 
 *
 * CRON 
 *
 */

void ClientRunner::alarm() {
  BaseRunner::alarm();
  if (runner_config() && runner_config()->root_contract_config->params_version() > params_version_) {
    close_all_connections();
    params_version_ = runner_config()->root_contract_config->params_version();
  }
  if (next_update_balances_at_.is_in_past()) {
    next_update_balances_at_ = td::Timestamp::in(td::Random::fast(1.0, 2.0));
    iterate_check_map(proxies_);
  }
  if (next_payment_compare_at_.is_in_past()) {
    next_payment_compare_at_ = td::Timestamp::in(td::Random::fast(10, 20));
    foreach_proxy_target([&](ProxyTarget *p) {
      if (!p->is_ready()) {
        return;
      }
      auto conn_id = p->connection_id();
      auto c = static_cast<ClientProxyConnection *>(get_connection(conn_id));
      if (!c || !c->handshake_is_completed()) {
        return;
      }

      send_query_to_connection(
          conn_id, "paymentcompare", cocoon::create_serialize_tl_object<cocoon_api::client_updatePaymentStatus>(),
          td::Timestamp::in(60.0),
          [self_id = actor_id(this),
           proxy_sc_address_str = c->proxy()->proxy_sc_address().rserialize(true)](td::Result<td::BufferSlice> R) {
            if (R.is_ok()) {
              td::actor::send_closure(self_id, &ClientRunner::update_proxy_payment_status, proxy_sc_address_str,
                                      R.move_as_ok());
            }
          });
    });
  }
  alarm_timestamp().relax(next_payment_compare_at_);
  alarm_timestamp().relax(next_update_balances_at_);
}

/* 
 *
 * INBOUND MESSAGE HANDLER
 *
 */

void ClientRunner::receive_message(TcpClient::ConnectionId connection_id, td::BufferSlice query) {
  auto magic = get_tl_magic(query);
  LOG(DEBUG) << "received message with magic = " << magic;
  switch (magic) {
    case cocoon_api::client_queryAnswerEx::ID:
    case cocoon_api::client_queryAnswerPartEx::ID:
    case cocoon_api::client_queryAnswerErrorEx::ID: {
      auto obj = cocoon::fetch_tl_object<cocoon_api::client_QueryAnswerEx>(std::move(query), true).move_as_ok();
      td::Bits256 request_id;
      cocoon_api::downcast_call(*obj, [&](auto &e) { request_id = e.request_id_; });
      auto it = running_queries_.find(request_id);
      if (it != running_queries_.end()) {
        td::actor::send_closure(it->second, &ClientRunningRequest::process_answer_ex, std::move(obj));
      }
      return;
    }
    case cocoon_api::proxy_signedPayment::ID: {
      auto R = cocoon::fetch_tl_object<cocoon_api::proxy_signedPayment>(std::move(query), true);
      if (R.is_error()) {
        return;
      }
      auto conn = static_cast<ClientProxyConnection *>(get_connection(connection_id));
      if (conn) {
        auto proxy = conn->proxy();
        proxy->process_signed_payment_data(*R.move_as_ok());
      }
      return;
    }
    case cocoon_api::proxy_clientRequestPayment::ID: {
      auto R = cocoon::fetch_tl_object<cocoon_api::proxy_clientRequestPayment>(std::move(query), true);
      if (R.is_error()) {
        return;
      }
      auto obj = R.move_as_ok();
      auto conn = static_cast<ClientProxyConnection *>(get_connection(connection_id));
      if (conn) {
        auto proxy = conn->proxy();
        proxy->update_tokens_used(obj->max_tokens_);
        proxy->update_tokens_committed_to_db(obj->db_tokens_);
        proxy->process_signed_payment_data(*obj->signed_payment_);
      }
      return;
    }
    default:
      LOG(ERROR) << "dropping received message: received message with unknown magic " << td::format::as_hex(magic);
      return;
  };
}

void ClientRunner::receive_http_request(
    std::unique_ptr<ton::http::HttpRequest> request, std::shared_ptr<ton::http::HttpPayload> payload,
    td::Promise<std::pair<std::unique_ptr<ton::http::HttpResponse>, std::shared_ptr<ton::http::HttpPayload>>> promise) {
  if (request->method() == "OPTIONS") {
    // TODO: return 204
    std::string data = "<http><body>OK</body></http>";
    http_send_static_answer(std::move(data), std::move(promise));
    return;
  }
  if (request->url() == "/v1/models") {
    if (payload->payload_type() != ton::http::HttpPayload::PayloadType::pt_empty) {
      ton::http::answer_error(ton::http::HttpStatusCode::status_bad_request, "bad request", std::move(promise));
      return;
    }
    run_get_models_request(std::move(promise));
    return;
  }

  run_http_request(std::move(request), std::move(payload), std::move(promise));
}

/*
 *
 * COMMANDS
 *
 */

td::Status ClientRunner::cmd_close(const std::string &proxy_sc_address_str) {
  auto it2 = proxies_.find(proxy_sc_address_str);
  if (it2 == proxies_.end()) {
    return td::Status::Error("proxy not found");
  }
  auto &proxy = *it2->second;
  if (proxy.sc_request_running()) {
    return td::Status::Error("request is already running");
  }

  if (!proxy.exp_sc_is_inited()) {
    return td::Status::Error("proxy is not inited");
  }

  if (proxy.exp_sc_is_closed()) {
    return td::Status::Error("proxy is closed");
  }

  auto msg = proxy.run_close();
  cocoon_wallet()->send_transaction(proxy.client_sc_address(), to_nano(0.7), {}, std::move(msg),
                                    create_proxy_sc_request_promise(it2->second));
  return td::Status::OK();
}

td::Status ClientRunner::cmd_top_up(const std::string &proxy_sc_address_str) {
  auto it2 = proxies_.find(proxy_sc_address_str);
  if (it2 == proxies_.end()) {
    return td::Status::Error("proxy not found");
  }
  auto &proxy = *it2->second;
  if (proxy.sc_request_running()) {
    return td::Status::Error("request is already running");
  }

  if (!proxy.exp_sc_is_inited()) {
    return td::Status::Error("proxy is not inited");
  }

  if (proxy.exp_sc_is_closed()) {
    return td::Status::Error("proxy is closed");
  }

  td::int64 top_up = proxy.exp_sc_stake();
  auto msg = proxy.run_top_up(top_up);
  cocoon_wallet()->send_transaction(proxy.client_sc_address(), to_nano(0.7) + top_up, {}, std::move(msg),
                                    create_proxy_sc_request_promise(it2->second));
  return td::Status::OK();
}

td::Status ClientRunner::cmd_withdraw(const std::string &proxy_sc_address_str) {
  auto it2 = proxies_.find(proxy_sc_address_str);
  if (it2 == proxies_.end()) {
    return td::Status::Error("proxy not found");
  }
  auto &proxy = *it2->second;
  if (proxy.sc_request_running()) {
    return td::Status::Error("request is already running");
  }

  if (!proxy.exp_sc_is_inited()) {
    return td::Status::Error("proxy is not inited");
  }

  if (proxy.exp_sc_is_closed()) {
    return td::Status::Error("proxy is closed");
  }

  auto msg = proxy.run_withdraw();
  cocoon_wallet()->send_transaction(proxy.client_sc_address(), to_nano(0.7), {}, std::move(msg),
                                    create_proxy_sc_request_promise(it2->second));
  return td::Status::OK();
}

/* 
 *
 * PROXY DB AND AUTH 
 *
 */

td::Result<std::shared_ptr<ClientProxyInfo>> ClientRunner::register_proxy(
    TcpClient::ConnectionId connection_id, const td::Bits256 &proxy_public_key,
    const block::StdAddress &proxy_owner_address, const block::StdAddress &proxy_sc_address,
    const block::StdAddress &client_sc_address, ton::tl_object_ptr<cocoon_api::proxy_SignedPayment> signed_payment) {
  auto proxy_sc_address_str = proxy_sc_address.rserialize(true);
  auto it = proxies_.find(proxy_sc_address_str);
  if (it == proxies_.end()) {
    auto expected_proxy_sc_address = generate_proxy_sc_address(proxy_public_key, proxy_owner_address, runner_config());
    if (expected_proxy_sc_address != proxy_sc_address) {
      return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << "proxy sc address mismatch: expected "
                                                                         << expected_proxy_sc_address << " got "
                                                                         << proxy_sc_address);
    }
    auto expected_client_sc_address = generate_client_sc_address(
        proxy_public_key, proxy_owner_address, proxy_sc_address, cocoon_wallet_address(), runner_config());
    if (expected_client_sc_address != client_sc_address) {
      return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << "client sc address mismatch: expected "
                                                                         << expected_client_sc_address << " got "
                                                                         << client_sc_address);
    }

    it = proxies_
             .emplace(proxy_sc_address_str, std::make_shared<ClientProxyInfo>(this, proxy_public_key, proxy_sc_address))
             .first;
  } else {
    if (it->second->proxy_sc_address() != proxy_sc_address) {
      return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << "proxy sc address changed: old "
                                                                         << it->second->proxy_sc_address() << " new "
                                                                         << proxy_sc_address);
    }
    if (it->second->proxy_public_key() != proxy_public_key) {
      return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << "proxy public key changed: old "
                                                                         << it->second->proxy_public_key().to_hex()
                                                                         << " new " << proxy_public_key.to_hex());
    }
    if (it->second->client_sc_address() != client_sc_address) {
      return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << "client sc address changed: old "
                                                                         << it->second->client_sc_address() << " new "
                                                                         << client_sc_address);
    }
  }

  if (signed_payment) {
    it->second->process_signed_payment_data(*signed_payment);
  }

  return it->second;
}

void ClientRunner::update_proxy_payment_status(const std::string &proxy_sc_address_str, td::BufferSlice info) {
  auto R = cocoon::fetch_tl_object<cocoon_api::client_paymentStatus>(std::move(info), true);
  if (R.is_error()) {
    return;
  }
  auto obj = R.move_as_ok();
  auto it = proxies_.find(proxy_sc_address_str);
  if (it == proxies_.end()) {
    return;
  }
  it->second->process_signed_payment_data(*obj->signed_payment_);
  it->second->update_tokens_committed_to_db(obj->db_tokens_);
  it->second->update_tokens_used(obj->max_tokens_);
}

std::string ClientRunner::http_generate_main() {
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
           << cocoon_wallet()->address().rserialize(true) << "</span>";
      } else if (cocoon_wallet()->balance() < warning_wallet_balance()) {
        sb << "<span style=\"background-color:Gold;\">balance low on " << cocoon_wallet()->address().rserialize(true)
           << "</span>";
      } else {
        sb << "<span style=\"background-color:Green;\">balance ok on " << cocoon_wallet()->address().rserialize(true)
           << "</span>";
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
    if (true) {
      sb << "<span style=\"background-color:Green;\">yes</span>";
    } else {
      sb << "<span style=\"background-color:Crimson;\">no</span>";
    }
    sb << "</td></tr>\n";
    sb << "<tr><td>version</td><td>commit " << GitMetadata::CommitSHA1() << " at " << GitMetadata::CommitDate()
       << "</td></tr>\n";
    sb << "</table>\n";
  }
  {
    sb << "<h1>STATS</h1>\n";
    sb << "<table>\n";
    sb << "<tr><td>name</td>" << stats_->header() << "</tr>\n";
    sb << "<tr><td>queries</td>" << stats_->requests_received.to_html_row() << "</tr>\n";
    sb << "<tr><td>success</td>" << stats_->requests_success.to_html_row() << "</tr>\n";
    sb << "<tr><td>failed</td>" << stats_->requests_failed.to_html_row() << "</tr>\n";
    sb << "<tr><td>bytes received</td>" << stats_->request_bytes_received.to_html_row() << "</tr>\n";
    sb << "<tr><td>bytes sent</td>" << stats_->answer_bytes_sent.to_html_row() << "</tr>\n";
    sb << "<tr><td>time</td>" << stats_->total_requests_time.to_html_row() << "</tr>\n";
    sb << "<tr><td>proxy time</td>" << stats_->total_proxy_requests_time.to_html_row() << "</tr>\n";
    sb << "<tr><td>worker time</td>" << stats_->total_worker_requests_time.to_html_row() << "</tr>\n";
    sb << "</table>\n";
  }

  store_wallet_stat(sb);

  {
    sb << "<h1>LOCAL CONFIG</h1>\n";
    sb << "<table>\n";
    sb << "<tr><td>root address</td><td>" << address_link(root_contract_address()) << "</td></tr>\n";
    sb << "<tr><td>owner address</td><td>" << address_link(owner_address()) << "</td></tr>\n";
    sb << "<tr><td>check proxy hash</td><td>" << (check_proxy_hash_ ? "YES" : "NO") << "</td></tr>\n";
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
      auto conn = static_cast<ClientProxyConnection *>(get_connection(connection_id));
      if (conn) {
        sb << conn->proxy()->proxy_sc_address().rserialize(true);
      }
      sb << "</td></tr>";
    });
    sb << "</table>\n";
  }

  {
    sb << "<h1>PROXIES</h1>\n";
    for (auto it : proxies_) {
      auto &p = *it.second;
      sb << "<h2>PROXY " << address_link(p.sc()->address()) << "</h2>\n";
      p.store_stats(sb);
    }
  }

  sb << "</body></html>\n";
  return sb.as_cslice().str();
}

std::string ClientRunner::http_generate_json_stats() {
  SimpleJsonSerializer jb;

  jb.start_object();
  {
    jb.start_object("status");
    if (cocoon_wallet()) {
      jb.add_element("wallet_balance", cocoon_wallet()->balance());
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
  {
    jb.start_object("stats");
    stats_->requests_received.to_jb(jb, "queries");
    stats_->requests_failed.to_jb(jb, "success");
    stats_->requests_failed.to_jb(jb, "failed");
    stats_->request_bytes_received.to_jb(jb, "bytes_received");
    stats_->answer_bytes_sent.to_jb(jb, "bytes_sent");
    stats_->total_requests_time.to_jb(jb, "time");
    jb.stop_object();
  }
  store_wallet_stat(jb);
  {
    jb.start_object("localconf");
    jb.add_element("root_address", root_contract_address().rserialize(true));
    jb.add_element("owner_address", owner_address().rserialize(true));
    jb.add_element("check_proxy_hash", check_proxy_hash_);
    jb.stop_object();
  }

  store_root_contract_stat(jb);

  {
    jb.start_array("proxy_connections");
    foreach_proxy_target([&](ProxyTarget *p) {
      if (!p) {
        return;
      }
      jb.start_object();
      jb.add_element("address", PSTRING() << p->address());
      jb.add_element("is_ready", p->is_ready());
      auto connection_id = p->connection_id();
      auto conn = static_cast<ClientProxyConnection *>(get_connection(connection_id));
      if (conn) {
        jb.add_element("proxy_sc_address", conn->proxy()->proxy_sc_address().rserialize(true));
      }
      jb.stop_object();
    });
    jb.stop_array();
  }

  {
    jb.start_array("proxies");
    for (auto it : proxies_) {
      jb.start_object();
      auto &p = *it.second;
      p.store_stats(jb);
      jb.stop_object();
    }
    jb.stop_array();
  }

  jb.stop_object();
  return jb.as_cslice().str();
}

std::string ClientRunner::http_charge(const std::string &proxy_sc_address) {
  auto it2 = proxies_.find(proxy_sc_address);
  if (it2 == proxies_.end()) {
    return wrap_short_answer_to_http("proxy not found");
  }

  auto &proxy = *it2->second;

  if (proxy.sc_request_running()) {
    return wrap_short_answer_to_http("request is already running");
  }

  if (!proxy.exp_sc_is_inited()) {
    return wrap_short_answer_to_http("proxy is not inited");
  }

  if (proxy.exp_sc_is_closed()) {
    return wrap_short_answer_to_http("proxy is closed");
  }

  if (!proxy.can_charge()) {
    return wrap_short_answer_to_http("nothing to charge");
  }

  auto msg = proxy.run_charge();
  cocoon_wallet()->send_transaction(proxy.client_sc_address(), to_nano(0.7), {}, std::move(msg),
                                    create_proxy_sc_request_promise(it2->second));

  return wrap_short_answer_to_http("request sent");
}

}  // namespace cocoon
