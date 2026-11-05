#include "ProxyRunner.hpp"
#include "auto/tl/cocoon_api.h"
#include "auto/tl/cocoon_api.hpp"
#include "auto/tl/cocoon_api_json.h"
#include "boost-http/http.h"
#include "checksum.h"
#include "common/bitstring.h"
#include "errorcode.h"
#include "td/actor/PromiseFuture.h"
#include "td/actor/actor.h"
#include "td/utils/Random.h"
#include "td/utils/SharedSlice.h"
#include "td/utils/Time.h"
#include "td/utils/buffer.h"
#include "td/utils/common.h"
#include "td/utils/filesystem.h"
#include "td/db/RocksDb.h"
#include "runners/smartcontracts/WorkerContract.hpp"
#include "runners/smartcontracts/ClientContract.hpp"
#include "ProxyInboundClientConnection.h"
#include "ProxyInboundWorkerConnection.h"
#include "runners/smartcontracts/Opcodes.hpp"
#include "git.h"
#include "boost-http/www-form-urlencoded.h"

#include "cocoon-tl-utils/cocoon-tl-utils.hpp"
#include "td/utils/format.h"
#include "td/utils/misc.h"
#include "td/utils/overloaded.h"
#include "tl/TlObject.h"
#include "ton/ton-types.h"
#include <limits>
#include <memory>

namespace cocoon {

/* 
 *
 * GETTERS
 *
 */

block::StdAddress ProxyRunner::sc_address(const std::shared_ptr<RunnerConfig> config) {
  if (sc_ && sc_->runner_config().get() == config.get()) {
    return sc_->address();
  }

  ProxyContract sc(owner_address_, public_key_, nullptr, this, config);
  return sc.address();
}

/* 
 *
 * WORKER 
 *
 */

td::Result<std::shared_ptr<ProxyWorkerInfo>> ProxyRunner::register_worker(
    const block::StdAddress &worker_owner_address) {
  if (is_disabled()) {
    return td::Status::Error(ton::ErrorCode::notready, "proxy is not participating in this iteration");
  }
  auto worker_owner_address_str = worker_owner_address.rserialize(true);
  auto it = workers_.find(worker_owner_address_str);
  if (it != workers_.end()) {
    return it->second;
  }

  auto worker_info = std::make_shared<ProxyWorkerInfo>(this, worker_owner_address, sc_->runner_config());
  it = workers_.emplace(worker_owner_address_str, std::move(worker_info)).first;
  return it->second;
}

td::Result<std::shared_ptr<ProxyWorkerConnectionInfo>> ProxyRunner::register_worker_connection(
    std::shared_ptr<ProxyWorkerInfo> worker, TcpClient::ConnectionId connection_id, const td::Bits256 &worker_hash,
    std::string model, td::int32 coefficient, td::int32 max_active_requests, std::string machine_description_json) {
  if (is_disabled()) {
    return td::Status::Error(ton::ErrorCode::notready, "proxy is not participating in this iteration");
  }
  if (machine_description_json == "") {
    machine_description_json = "{}";
  }
  auto worker_conn =
      std::make_shared<ProxyWorkerConnectionInfo>(worker, connection_id, worker_hash, model, coefficient,
                                                  max_active_requests, true, std::move(machine_description_json));
  models_[worker_conn->model_name_base].model_base_name = worker_conn->model_name_base;
  auto it = models_[worker_conn->model_name_base].connections.emplace(connection_id, std::move(worker_conn)).first;
  return it->second;
}

void ProxyRunner::unregister_worker_connection(std::shared_ptr<ProxyWorkerConnectionInfo> worker_connection_info) {
  auto it = models_.find(worker_connection_info->model_name_base);
  if (it == models_.end()) {
    return;
  }
  it->second.connections.erase(worker_connection_info->connection_id);
}

void ProxyRunner::sign_worker_payment(ProxyWorkerInfo &w) {
  if (w.has_signed_payment()) {
    return;
  }
  CHECK(!is_disabled());
  WorkerContract sc(w.worker_owner_address(), sc_->address(), public_key(), this, sc_->runner_config());
  auto msg = sc.create_pay_message(w.signed_payment_tokens());
  auto signed_msg = sign_and_wrap_message(msg, cocoon_wallet()->address());
  w.update_signed_payment_data(w.signed_payment_tokens(),
                               td::UniqueSlice(vm::std_boc_serialize(signed_msg).move_as_ok().as_slice()));
  sc.check_signed_pay_message(w.signed_payment_data()).ensure();
}

void ProxyRunner::on_worker_update(const block::StdAddress &worker_owner_address,
                                   const block::StdAddress &worker_sc_address, td::uint32 state, td::int64 tokens) {
  CHECK(!is_disabled());
  auto worker_owner_address_str = worker_owner_address.rserialize(true);
  auto it = workers_.find(worker_owner_address_str);
  if (it == workers_.end()) {
    auto worker_info = std::make_shared<ProxyWorkerInfo>(this, worker_owner_address, sc_->runner_config());
    it = workers_.emplace(worker_owner_address_str, std::move(worker_info)).first;
  }

  if (it != workers_.end()) {
    it->second->update_balance(tokens);
  }
}

void ProxyRunner::worker_payout(ProxyWorkerInfo &worker, bool force_close) {
  if (ton_disabled()) {
    return;
  }
  if (worker.paying_now() && !force_close) {
    return;
  }

  CHECK(!is_disabled());

  sign_worker_payment(worker);
  auto tokens = worker.signed_payment_tokens();
  worker.pay_out(tokens);

  auto signed_msg = vm::std_boc_deserialize(worker.signed_payment_data()).move_as_ok();

  cocoon_wallet()->send_transaction(
      worker.worker_sc_address(), to_nano(0.7), {}, std::move(signed_msg),
      [self_id = actor_id(this), tokens, worker = worker.shared_ptr()](td::Result<td::Unit> R) {
        R.ensure();
        td::actor::send_closure(self_id, &ProxyRunner::worker_payout_completed, worker, tokens);
      });
}

void ProxyRunner::worker_payout_completed(std::shared_ptr<ProxyWorkerInfo> worker, td::int64 tokens) {
  worker->pay_out_completed();
}

/* 
 *
 * CLIENT
 *
 */

std::shared_ptr<ProxyClientInfo> ProxyRunner::get_client(const std::string &client_owner_address_str) {
  auto it = clients_.find(client_owner_address_str);
  if (it != clients_.end()) {
    return it->second;
  } else {
    return nullptr;
  }
}

td::Result<std::shared_ptr<ProxyClientInfo>> ProxyRunner::register_client(
    const block::StdAddress &client_owner_address) {
  if (is_disabled()) {
    return td::Status::Error(ton::ErrorCode::notready, "proxy is not participating in this iteration");
  }
  auto client_owner_address_str = client_owner_address.rserialize(true);
  auto it = clients_.find(client_owner_address_str);
  if (it != clients_.end()) {
    return it->second;
  }
  auto client_info = std::make_shared<ProxyClientInfo>(this, client_owner_address, sc_->runner_config());
  it = clients_.emplace(client_owner_address_str, std::move(client_info)).first;
  return it->second;
}

td::Result<std::shared_ptr<ProxyConnectingClient>> ProxyRunner::register_connecting_client(
    const block::StdAddress &client_owner_address, TcpClient::ConnectionId connection_id) {
  if (is_disabled()) {
    return td::Status::Error(ton::ErrorCode::notready, "proxy is not participating in this iteration");
  }
  td::uint64 nonce = td::Random::fast_uint64();
  while (true) {
    if (connecting_clients_.find(nonce) == connecting_clients_.end()) {
      break;
    }
    nonce = td::Random::fast_uint64();
  }

  ClientContract cc(client_owner_address, sc_->address(), public_key(), this, sc_->runner_config());

  auto connecting_client_info =
      std::make_shared<ProxyConnectingClient>(client_owner_address, cc.address(), nonce, connection_id);

  CHECK(connecting_clients_.emplace(nonce, connecting_client_info).second);

  return connecting_client_info;
}

void ProxyRunner::unregister_connecting_client(td::uint64 nonce) {
  connecting_clients_.erase(nonce);
}

void ProxyRunner::sign_client_payment(ProxyClientInfo &c) {
  if (c.has_signed_payment()) {
    return;
  }
  CHECK(!is_disabled());
  ClientContract sc(c.client_owner_address(), sc_->address(), public_key(), this, sc_->runner_config());
  auto msg = sc.create_charge_message(c.signed_payment_tokens());
  auto signed_msg = sign_and_wrap_message(msg, cocoon_wallet()->address());
  c.update_signed_payment_data(c.signed_payment_tokens(),
                               td::UniqueSlice(vm::std_boc_serialize(signed_msg).move_as_ok().as_slice()));
  sc.check_signed_pay_message(c.signed_payment_data()).ensure();
}

void ProxyRunner::client_charge(ProxyClientInfo &client, bool force_close) {
  if (ton_disabled()) {
    return;
  }
  if (client.charging_now() && !force_close) {
    return;
  }
  CHECK(!is_disabled());

  sign_client_payment(client);

  ClientContract sc(client.client_owner_address(), sc_->address(), public_key(), this, sc_->runner_config());

  auto tokens = client.tokens_used();

  client.charge(tokens, force_close);

  auto msg = force_close ? sc.create_refund_message(tokens) : sc.create_charge_message(tokens);
  auto signed_msg = sign_and_wrap_message(msg, cocoon_wallet()->address());
  CHECK(signed_msg.not_null());

  cocoon_wallet()->send_transaction(
      client.client_sc_address(), to_nano(0.7), {}, std::move(signed_msg),
      [self_id = actor_id(this), tokens, client = client.shared_ptr()](td::Result<td::Unit> R) {
        R.ensure();
        td::actor::send_closure(self_id, &ProxyRunner::client_charge_completed, client, tokens);
      });
}

void ProxyRunner::client_charge_completed(std::shared_ptr<ProxyClientInfo> client, td::int64 tokens) {
  client->charging_completed();
}

void ProxyRunner::on_client_update(const block::StdAddress &client_owner_address,
                                   const block::StdAddress &client_sc_address, td::uint32 state, td::int64 new_balance,
                                   td::int64 new_stake, td::int64 tokens_used, const td::Bits256 &secret_hash) {
  LOG(DEBUG) << "received client update: owner=" << client_owner_address.rserialize(true) << " state=" << state
             << " new_balance=" << new_balance << " new_stake=" << new_stake << " tokens_used=" << tokens_used
             << " secret_hash=" << secret_hash.to_hex();
  CHECK(!is_disabled());
  auto client_owner_address_str = client_owner_address.rserialize(true);
  auto it = clients_.find(client_owner_address_str);
  if (it == clients_.end()) {
    auto client_info = std::make_shared<ProxyClientInfo>(this, client_owner_address, sc_->runner_config());
    it = clients_.emplace(client_owner_address_str, std::move(client_info)).first;
  }
  if (it != clients_.end()) {
    it->second->update_state(state, new_balance, new_stake, tokens_used, price_per_token(), secret_hash);
  }
}

void ProxyRunner::on_client_register(const block::StdAddress &client_owner_address,
                                     const block::StdAddress &client_sc_address, td::uint64 nonce) {
  CHECK(!is_disabled());
  auto client_owner_address_str = client_owner_address.rserialize(true);
  auto it = clients_.find(client_owner_address_str);
  if (it == clients_.end()) {
    return;
  }

  auto it2 = connecting_clients_.find(nonce);
  if (it2 == connecting_clients_.end()) {
    return;
  }

  if (it2->second->owner_address != client_owner_address) {
    return;
  }

  auto connection_id = it2->second->connection_id;
  auto conn = static_cast<ProxyInboundConnection *>(get_connection(connection_id));
  if (!conn || conn->connection_type() != ProxyInboundConnection::ConnectionType::Client) {
    connecting_clients_.erase(it2);
    return;
  }

  static_cast<ProxyInboundClientConnection *>(conn)->received_register_message(it->second);
}

/*
 *
 * ALLOCATORS
 *
 */

std::unique_ptr<BaseInboundConnection> ProxyRunner::allocate_inbound_connection(
    TcpClient::ConnectionId connection_id, TcpClient::ListeningSocketId listening_socket_id,
    const RemoteAppType &remote_app_type, const td::Bits256 &remote_app_hash, const td::Bits256 &verified_by) {
  if (!is_initialized() || is_disabled()) {
    return nullptr;
  }

  if (remote_app_type == remote_app_type_worker()) {
    return std::make_unique<ProxyInboundWorkerConnection>(this, remote_app_type, remote_app_hash, verified_by,
                                                          connection_id);
  } else {
    return std::make_unique<ProxyInboundClientConnection>(this, remote_app_type, remote_app_hash, verified_by,
                                                          connection_id);
  }
}

/* 
 *
 * INITIALIZATION
 *
 */

void ProxyRunner::load_config(td::Promise<td::Unit> promise) {
  auto S = [&]() -> td::Status {
    TRY_RESULT_PREFIX(conf_data, td::read_file(engine_config_filename()), "failed to read: ");
    TRY_RESULT_PREFIX(conf_json, td::json_decode(conf_data.as_slice()), "failed to parse json: ");

    cocoon::cocoon_api::proxyRunner_config conf;
    TRY_STATUS_PREFIX(cocoon::cocoon_api::from_json(conf, conf_json.get_object()), "json does not fit TL scheme: ");
    set_testnet(conf.is_testnet_);
    if (conf.workers_rpc_port_) {
      set_rpc_port((td::uint16)conf.workers_rpc_port_, remote_app_type_worker());
    }
    if (conf.client_rpc_port_) {
      set_rpc_port((td::uint16)conf.client_rpc_port_, remote_app_type_unknown());
    }
    if (conf.http_port_) {
      set_http_port((td::uint16)conf.http_port_);
    }
    TRY_RESULT_PREFIX(owner_address, block::StdAddress::parse(conf.owner_address_), "failed to parse owner address: ");
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

    set_number_of_proxy_connections(0, false);
    set_owner_address(std::move(owner_address));

    local_image_hash_unverified_ = conf.image_hash_;
    set_check_image_hashes(conf.check_worker_hashes_ || !conf.is_test_);
    set_http_access_hash(conf.http_access_hash_);
    set_is_test(conf.is_test_);

    if (generate_random_private_key_) {
      TRY_RESULT(p, td::Ed25519::generate_private_key());
      TRY_RESULT(pub, p.get_public_key());

      private_key_ = std::make_unique<td::Ed25519::PrivateKey>(std::move(p));
      auto pub_key_str = pub.as_octet_string();
      CHECK(pub_key_str.size() == 32);
      public_key_.as_slice().copy_from(pub_key_str.as_slice());
    } else {
      private_key_ =
          std::make_unique<td::Ed25519::PrivateKey>(td::SecureString(conf.machine_specific_private_key_.as_slice()));
      public_key_.as_slice().copy_from(private_key_->get_public_key().move_as_ok().as_octet_string());
    }

    public_key_obj_ = std::make_unique<td::Ed25519::PublicKey>(
        td::Ed25519::PublicKey::from_slice(public_key_.as_slice()).move_as_ok());

    db_path_ = conf.db_path_;

    if (!is_test()) {
      CHECK(!is_testnet());
    }

    return td::Status::OK();
  }();
  if (S.is_error()) {
    return promise.set_error(std::move(S));
  }

  promise.set_value(td::Unit());
}

void ProxyRunner::custom_initialize(td::Promise<td::Unit> promise) {
  kv_ = std::make_shared<td::RocksDb>(td::RocksDb::open(db_path_).move_as_ok());

  std::shared_ptr<RunnerConfig> snapshot_runner_config;
  ton::BlockIdExt sc_init_block_id;

  td::Random::secure_bytes(session_unique_hash_.as_slice());

  {
    td::UniqueSlice value = get_from_db("config");

    if (value.size() > 0) {
      auto obj = cocoon::fetch_tl_object<cocoon_api::proxyDb_Config>(value.as_slice(), true).move_as_ok();

      cocoon_api::downcast_call(
          *obj, td::overloaded(
                    [&](cocoon_api::proxyDb_configEmpty &c) { UNREACHABLE(); },
                    [&](cocoon_api::proxyDb_configV4 &c) {
                      auto conf = RootContractConfig::load_from_tl(*c.root_contract_state_, is_testnet()).move_as_ok();

                      if (conf->version() > runner_config()->root_contract_config->version()) {
                        set_root_contract_config(std::move(conf), c.root_contract_state_block_ts_);
                        snapshot_runner_config = runner_config();
                      } else {
                        snapshot_runner_config = std::make_shared<RunnerConfig>();
                        snapshot_runner_config->root_contract_config = std::move(conf);
                        snapshot_runner_config->root_contract_ts = c.root_contract_state_block_ts_;
                        snapshot_runner_config->is_testnet = runner_config()->is_testnet;
                        snapshot_runner_config->ton_disabled = runner_config()->ton_disabled;
                      }

                      sc_init_block_id = TonScWrapper::block_id_tl_to_obj(*c.sc_block_id_);
                      last_saved_state_seqno_ = c.last_seqno_committed_to_blockchain_;

                      for (auto &e : c.pending_blockchain_seqno_commits_) {
                        CHECK(pending_blockchain_seqno_commits_.emplace(e->seqno_, e->session_hash_).second);
                      }
                    },
                    [&](cocoon_api::proxyDb_configV4Disabled &c) {
                      auto conf = RootContractConfig::load_from_tl(*c.root_contract_state_, is_testnet()).move_as_ok();

                      if (conf->version() > runner_config()->root_contract_config->version()) {
                        set_root_contract_config(std::move(conf), c.root_contract_state_block_ts_);
                        snapshot_runner_config = runner_config();
                      } else {
                        snapshot_runner_config = std::make_shared<RunnerConfig>();
                        snapshot_runner_config->root_contract_config = std::move(conf);
                        snapshot_runner_config->root_contract_ts = c.root_contract_state_block_ts_;
                        snapshot_runner_config->is_testnet = runner_config()->is_testnet;
                        snapshot_runner_config->ton_disabled = runner_config()->ton_disabled;
                      }

                      is_disabled_until_version_ = c.disabled_until_version_;
                    }));

    } else {
      snapshot_runner_config = runner_config();
      config_to_db(snapshot_runner_config);
      flush_db();
    }
  }

  active_config_version_ = snapshot_runner_config->root_contract_config->version();
  CHECK(snapshot_runner_config);
  CHECK(snapshot_runner_config->root_contract_config);

  bool need_enable = !is_disabled_until_version_ ||
                     is_disabled_until_version_ < snapshot_runner_config->root_contract_config->params_version();
  if (need_enable) {
    is_disabled_until_version_ = 0;
    first_saved_state_seqno_ = last_saved_state_seqno_;
    last_saved_state_seqno_++;
    pending_blockchain_seqno_commits_[last_saved_state_seqno_] = session_unique_hash_;
    config_to_db(snapshot_runner_config);
    flush_db();
  } else {
    CHECK(!clients_.size());
    CHECK(!workers_.size());
    for (auto &model : models_) {
      CHECK(!model.second.connections.size());
    }
  }

  auto snap = kv_->snapshot();
  snap->for_each([&](td::Slice key, td::Slice value) -> td::Status {
    process_db_key(key, value, snapshot_runner_config);
    return td::Status::OK();
  });

  if (need_enable) {
    initialize_sc(snapshot_runner_config, sc_init_block_id, std::move(promise));
  } else {
    cocoon_wallet_initialize_wait_for_balance_and_get_seqno(
        wallet_private_key_->as_octet_string(), owner_address_, min_wallet_balance(),
        [self_id = actor_id(this), promise = std::move(promise)](td::Result<td::Unit> R) mutable {
          if (R.is_error()) {
            promise.set_error(R.move_as_error());
            return;
          }
          promise.set_value(td::Unit());
        });
  }

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
        http_send_static_answer(http_payout(get_from_sorted_list(args, "worker")), std::move(answer_callback));
      });
  register_custom_http_handler(
      "/request/withdraw",
      [&](http::HttpCallback::RequestType request_type, std::vector<std::pair<std::string, std::string>> headers,
          std::string path, std::vector<std::pair<std::string, std::string>> args, std::string body,
          std::unique_ptr<http::HttpRequestCallback> answer_callback) {
        http_send_static_answer(http_withdraw(), std::move(answer_callback));
      });
  register_custom_http_handler(
      "/request/charge",
      [&](http::HttpCallback::RequestType request_type, std::vector<std::pair<std::string, std::string>> headers,
          std::string path, std::vector<std::pair<std::string, std::string>> args, std::string body,
          std::unique_ptr<http::HttpRequestCallback> answer_callback) {
        http_send_static_answer(http_charge(get_from_sorted_list(args, "client")), std::move(answer_callback));
      });
  register_custom_http_handler(
      "/request/disable",
      [&](http::HttpCallback::RequestType request_type, std::vector<std::pair<std::string, std::string>> headers,
          std::string path, std::vector<std::pair<std::string, std::string>> args, std::string body,
          std::unique_ptr<http::HttpRequestCallback> answer_callback) {
        if (request_type == http::HttpCallback::RequestType::Post) {
          http_send_static_answer(http_enable_disable(std::numeric_limits<td::int64>::max()),
                                  std::move(answer_callback));
        } else {
          http_send_static_answer(404, "not found", std::move(answer_callback));
        }
      });
  register_custom_http_handler(
      "/request/enable",
      [&](http::HttpCallback::RequestType request_type, std::vector<std::pair<std::string, std::string>> headers,
          std::string path, std::vector<std::pair<std::string, std::string>> args, std::string body,
          std::unique_ptr<http::HttpRequestCallback> answer_callback) {
        if (request_type == http::HttpCallback::RequestType::Post) {
          http_send_static_answer(http_enable_disable(0), std::move(answer_callback));
        } else {
          http_send_static_answer(404, "not found", std::move(answer_callback));
        }
      });
  register_custom_http_handler(
      "/request/change_worker_model",
      [&](http::HttpCallback::RequestType request_type, std::vector<std::pair<std::string, std::string>> headers,
          std::string path, std::vector<std::pair<std::string, std::string>> args, std::string body,
          std::unique_ptr<http::HttpRequestCallback> answer_callback) {
        if (request_type == http::HttpCallback::RequestType::Post) {
          auto post_args = http::parse_x_www_form_urlencoded(body);
          http_send_static_answer(http_change_worker_model(get_from_sorted_list(post_args, "connection_id"),
                                                           get_from_sorted_list(post_args, "new_model_name")),
                                  std::move(answer_callback));
        } else {
          http_send_static_answer(404, "not found", std::move(answer_callback));
        }
      });
}

void ProxyRunner::initialize_sc(std::shared_ptr<RunnerConfig> snapshot_runner_config,
                                const ton::BlockIdExt &sc_init_block_id, td::Promise<td::Unit> promise) {
  sc_is_initializing_ = true;
  class Cb : public ProxyContract::Callback {
   public:
    Cb(ProxyRunner *self) : self_(self) {
    }
    void on_deploy() override {
    }
    void on_client_update(const block::StdAddress &client_owner_address, const block::StdAddress &client_sc_address,
                          td::uint32 state, td::int64 new_balance, td::int64 new_stake, td::int64 tokens_used,
                          const td::Bits256 &secret_hash) override {
      self_->on_client_update(client_owner_address, client_sc_address, state, new_balance, new_stake, tokens_used,
                              secret_hash);
    }
    void on_client_register(const block::StdAddress &client_owner_address, const block::StdAddress &client_sc_address,
                            td::uint64 nonce) override {
      self_->on_client_register(client_owner_address, client_sc_address, nonce);
    }
    void on_worker_update(const block::StdAddress &worker_owner_address, const block::StdAddress &worker_sc_address,
                          td::uint32 state, td::int64 tokens) override {
      self_->on_worker_update(worker_owner_address, worker_sc_address, state, tokens);
    }
    void on_worker_payout(const block::StdAddress &worker_owner_address, const block::StdAddress &worker_sc_address,
                          td::int64 tokens_delta) override {
    }
    void proxy_save_state(td::int32 seqno, const td::Bits256 &unique_hash) override {
      self_->on_receive_saved_state_seqno(seqno, unique_hash);
    }
    void on_transaction(const block::StdAddress &src_address, td::uint32 op, td::uint64 qid) override {
      self_->on_receive_transaction(src_address, op, qid);
    }

   private:
    ProxyRunner *self_;
  };
  sc_ = std::make_shared<ProxyContract>(owner_address_, public_key_, std::make_unique<Cb>(this), this,
                                        snapshot_runner_config);
  sc_->set_init_block_id(sc_init_block_id);
  sc_->subscribe_to_updates(sc_);

  cocoon_wallet_initialize_wait_for_balance_and_get_seqno(
      wallet_private_key_->as_octet_string(), owner_address_, min_wallet_balance(),
      [self_id = actor_id(this), addr = sc_->address().rserialize(true),
       promise = std::move(promise)](td::Result<td::Unit> R) mutable {
        if (R.is_error()) {
          promise.set_error(R.move_as_error());
          return;
        }
        td::actor::send_closure(self_id, &ProxyRunner::deploy_proxy_sc, std::move(addr), std::move(promise));
      });
}

void ProxyRunner::deploy_proxy_sc(std::string sc_address, td::Promise<td::Unit> promise) {
  if (!sc_ || sc_->address().rserialize(true) != sc_address) {
    return promise.set_error(td::Status::Error(ton::ErrorCode::cancelled, "sc was deleted"));
  }
  CHECK(sc_);
  LOG(INFO) << "deploying proxy SC on address " << sc_->address().rserialize(true);
  sc_->deploy([self_id = actor_id(this), sc_address, promise = std::move(promise)](td::Result<td::Unit> R) mutable {
    if (R.is_error()) {
      promise.set_error(R.move_as_error());
      return;
    }
    td::actor::send_closure(self_id, &ProxyRunner::wait_sync_proxy_sc, sc_address, std::move(promise));
  });
}

void ProxyRunner::wait_sync_proxy_sc(std::string sc_address, td::Promise<td::Unit> promise) {
  if (!sc_ || sc_->address().rserialize(true) != sc_address) {
    return promise.set_error(td::Status::Error(ton::ErrorCode::cancelled, "sc was deleted"));
  }
  CHECK(sc_);
  LOG(INFO) << "deployed proxy SC on address " << sc_->address().rserialize(true);
  session_start_promise_ = std::move(promise);

  sc_is_initializing_ = false;
  CHECK(pending_blockchain_seqno_commits_.size() > 0);
  auto &e = *pending_blockchain_seqno_commits_.rbegin();
  running_save_state_to_blockchain_ = true;
  auto msg = sc_->create_save_state_message(e.first, e.second);
  cocoon_wallet()->send_transaction(sc_->address(), 1, {}, std::move(msg), {});

  if (ton_disabled()) {
    on_receive_saved_state_seqno(last_saved_state_seqno_, session_unique_hash_);
  }
}

/*
 *
 * DB
 *
 */

void ProxyRunner::process_db_key(td::Slice key, td::Slice value, std::shared_ptr<RunnerConfig> runner_config) {
  auto key_parts = td::split(key, '_');
  auto key_type = key_parts.first;
  key = key_parts.second;

  CHECK(value.size() >= 64);
  auto signature = value.copy().remove_prefix(value.size() - 64);
  value.remove_suffix(64);

  public_key_obj_->verify_signature(value, signature).ensure();

  if (key_type == "client") {
    block::StdAddress client_owner_address;
    CHECK(rdeserialize(client_owner_address, key));
    auto client_owner_address_str = client_owner_address.rserialize(true);

    auto obj = cocoon::fetch_tl_object<cocoon_api::proxyDb_ClientInfo>(value, true).move_as_ok();

    auto client_info = std::make_shared<ProxyClientInfo>(this, *obj, runner_config);
    CHECK(clients_.emplace(client_owner_address_str, std::move(client_info)).second);
  } else if (key_type == "worker") {
    block::StdAddress worker_owner_address;
    CHECK(rdeserialize(worker_owner_address, key));
    auto worker_owner_address_str = worker_owner_address.rserialize(true);

    auto obj = cocoon::fetch_tl_object<cocoon_api::proxyDb_workerInfo>(value, true).move_as_ok();

    auto worker_info = std::make_shared<ProxyWorkerInfo>(this, *obj, runner_config);
    CHECK(workers_.emplace(worker_owner_address_str, std::move(worker_info)).second);
  } else if (key_type == "config") {
  } else if (key_type == "oldproxycontract") {
    block::StdAddress sc_addr;
    CHECK(rdeserialize(sc_addr, key));

    auto obj = cocoon::fetch_tl_object<cocoon_api::proxyDb_oldInstance>(value, true).move_as_ok();
    auto old_instance = std::make_shared<OldProxyContract>(*obj, this);

    CHECK(old_proxy_contracts_.emplace(sc_addr.rserialize(true), std::move(old_instance)).second);
  } else if (key_type == "oldclient") {
  } else if (key_type == "oldworker") {
  } else {
    LOG(FATAL) << "unknown key type in db: " << key;
  }
}

void ProxyRunner::client_to_db(ProxyClientInfo &client) {
  auto key = PSTRING() << "client_" << client.client_owner_address().rserialize(true);
  auto value = cocoon::serialize_tl_object(client.serialize(), true);
  set_to_db(key, value.as_slice());
  client.written_to_db();
}

void ProxyRunner::worker_to_db(ProxyWorkerInfo &worker) {
  auto key = PSTRING() << "worker_" << worker.worker_owner_address().rserialize(true);
  auto value = cocoon::serialize_tl_object(worker.serialize(), true);
  set_to_db(key, value.as_slice());
  worker.written_to_db();
}

void ProxyRunner::config_to_db(std::shared_ptr<RunnerConfig> config) {
  std::vector<ton::tl_object_ptr<cocoon_api::proxyDb_pendingBlockchainSeqnoCommit>> seq_commits;
  for (auto &e : pending_blockchain_seqno_commits_) {
    seq_commits.push_back(ton::create_tl_object<cocoon_api::proxyDb_pendingBlockchainSeqnoCommit>(e.first, e.second));
  }

  if (is_disabled_until_version_ > 0 && !sc_) {
    auto conf = cocoon::create_serialize_tl_object<cocoon_api::proxyDb_configV4Disabled>(
        root_contract_address().rserialize(true), is_testnet(), config->root_contract_config->serialize(),
        config->root_contract_ts, is_disabled_until_version_);
    set_to_db("config", conf.as_slice());
  } else {
    auto conf = cocoon::create_serialize_tl_object<cocoon_api::proxyDb_configV4>(
        root_contract_address().rserialize(true), is_testnet(), config->root_contract_config->serialize(),
        config->root_contract_ts,
        TonScWrapper::block_id_obj_to_cocoon_tl(sc_ ? sc_->state_block_id() : ton::BlockIdExt{}),
        last_saved_state_seqno_, std::move(seq_commits));
    set_to_db("config", conf.as_slice());
  }
}

void ProxyRunner::set_to_db(td::Slice key, td::Slice value) {
  td::UniqueSlice signed_value(value.size() + 64);
  auto signature = private_key_->sign(value).move_as_ok();
  auto S = signed_value.as_mutable_slice();
  S.copy_from(value);
  S.remove_prefix(value.size());
  S.copy_from(signature.as_slice());
  S.remove_prefix(signature.size());
  CHECK(!S.size());
  kv_->set(key, signed_value.as_slice()).ensure();
}

td::UniqueSlice ProxyRunner::get_from_db(td::Slice key) {
  std::string config_value;
  auto k = kv_->get(key, config_value);
  k.ensure();

  if (k.move_as_ok() == td::KeyValue::GetStatus::Ok) {
    auto value = td::Slice(config_value);
    CHECK(value.size() >= 64);
    auto signature = value.copy().remove_prefix(value.size() - 64);
    value.remove_suffix(64);

    public_key_obj_->verify_signature(value, signature).ensure();

    return td::UniqueSlice(value);
  } else {
    return td::UniqueSlice();
  }
}

void ProxyRunner::on_receive_saved_state_seqno(td::int32 seqno, const td::Bits256 &unique_hash) {
  LOG(INFO) << "received saved state from blockchain: seqno=" << seqno << " unique_hash=" << unique_hash.to_hex()
            << " cur=" << session_unique_hash_.to_hex();
  CHECK(!is_disabled());
  auto it = pending_blockchain_seqno_commits_.find(seqno);
  CHECK(it != pending_blockchain_seqno_commits_.end());
  CHECK(it->second == unique_hash);
  it++;
  pending_blockchain_seqno_commits_.erase(pending_blockchain_seqno_commits_.begin(), it);

  if (unique_hash == session_unique_hash_) {
    CHECK(running_save_state_to_blockchain_);
    running_save_state_to_blockchain_ = false;
    CHECK(seqno > last_received_saved_state_seqno_);
    last_received_saved_state_seqno_ = seqno;
    save_state_to_blockchain_completed(seqno);
    session_start_promise_.set_value(td::Unit());
  }
}

void ProxyRunner::save_state_to_blockchain_completed(td::int32 seqno) {
  for (auto &p : clients_) {
    auto &c = *p.second;
    c.committed_to_blockchain(seqno);
  }
  for (auto &p : workers_) {
    auto &w = *p.second;
    w.committed_to_blockchain(seqno);
  }
}

void ProxyRunner::close_all() {
  close_all_connections();
  for (auto &c : connecting_clients_) {
    close_connection(c.second->connection_id);
  }
  connecting_clients_.clear();

  std::string last_client = "";
  for (auto &c : clients_) {
    kv_->erase(PSTRING() << "client_" << c.second->client_owner_address().rserialize(true)).ensure();

    if (c.second->is_closed()) {
      continue;
    }

    /* we close using balance on client's contract */

    //proxyDb.oldClient owner_address:string tokens:long next_client:string = proxyDb.OldClient;
    auto value = cocoon::create_serialize_tl_object<cocoon_api::proxyDb_oldClient>(
        c.second->client_owner_address().rserialize(true), c.second->tokens_used(), last_client);

    std::string key = PSTRING() << "oldclient_" << sc_->address().rserialize(true) << "-"
                                << c.second->client_owner_address().rserialize(true);

    set_to_db(key, value.as_slice());

    last_client = key;
  }

  clients_.clear();

  std::string last_worker = "";

  for (auto &w : workers_) {
    del_from_db(PSTRING() << "worker_" << w.second->worker_owner_address().rserialize(true));
    if (w.second->is_closed()) {
      continue;
    }

    auto value = cocoon::create_serialize_tl_object<cocoon_api::proxyDb_oldWorker>(
        w.second->worker_owner_address().rserialize(true), w.second->tokens(), last_worker);

    std::string key = PSTRING() << "oldworker_" << sc_->address().rserialize(true) << "-"
                                << w.second->worker_owner_address().rserialize(true);

    set_to_db(key, value.as_slice());

    last_worker = key;
  }

  workers_.clear();

  pending_blockchain_seqno_commits_.clear();
  running_save_state_to_blockchain_ = false;
  running_withdraw_ = false;

  if (sc_) {
    auto old_instance = std::make_unique<OldProxyContract>(sc_->address(), OldProxyContract::ClosingState::NotStarted,
                                                           0, last_client, last_worker, sc_->runner_config(), this);
    set_to_db(PSTRING() << "oldproxycontract_" << sc_->address().rserialize(true),
              cocoon::serialize_tl_object(old_instance->serialize(), true).as_slice());

    CHECK(old_proxy_contracts_.emplace(sc_->address().rserialize(true), std::move(old_instance)).second);
    sc_->unsubscribe_from_updates();
    sc_ = nullptr;
  }
}

void ProxyRunner::on_root_contract_config_update(std::shared_ptr<RunnerConfig> config) {
  LOG(INFO) << "updated root contract: new_version=" << config->root_contract_config->version()
            << " new_params_version=" << config->root_contract_config->params_version();
  if (is_disabled() && is_disabled_until_version_ > config->root_contract_config->params_version()) {
    active_config_version_ = config->root_contract_config->version();
    return;
  }
  auto nc = config->root_contract_config.get();

  bool need_redeploy;
  if (is_disabled()) {
    need_redeploy = true;
    is_disabled_until_version_ = 0;
  } else {
    auto cur_config = sc_->runner_config();
    auto cc = cur_config->root_contract_config.get();
    CHECK(cc->params_version() <= nc->params_version());
    need_redeploy = cc->params_version() < nc->params_version();
  }

  if (!need_redeploy) {
    sc_->update_runner_config(config);
    config_to_db(config);
  } else {
    LOG(WARNING) << "redeploying main contract, closing old instance";

    kv_->begin_transaction().ensure();

    close_all();
    pending_blockchain_seqno_commits_[last_saved_state_seqno_] = session_unique_hash_;
    config_to_db(config);

    kv_->commit_transaction().ensure();

    initialize_sc(config, ton::BlockIdExt{}, {});
  }

  if (check_image_hashes()) {
    for (auto &t : models_) {
      auto it = t.second.connections.begin();
      while (it != t.second.connections.end()) {
        if (!nc->has_worker_hash(it->second->worker_hash) ||
            !nc->has_model_hash(td::sha256_bits256(it->second->model_name))) {
          it = t.second.connections.erase(it);
        } else {
          it++;
        }
      }
    }
  }

  active_config_version_ = config->root_contract_config->version();
  flush_db();
}

void ProxyRunner::all_to_db() {
  bool will_send_transaction =
      sc_ && next_db_save_to_blockchain_at_.is_in_past() && !running_save_state_to_blockchain_ && !sc_is_initializing_;

  last_saved_state_seqno_++;
  if (will_send_transaction) {
    pending_blockchain_seqno_commits_[last_saved_state_seqno_] = session_unique_hash_;
  }
  db_transaction([&]() {
    for (auto &p : clients_) {
      auto &c = *p.second;
      c.committed_to_db(last_saved_state_seqno_);
      if (c.need_to_write()) {
        client_to_db(c);
      }
    }

    for (auto &p : workers_) {
      auto &w = *p.second;
      w.committed_to_db(last_saved_state_seqno_);
      if (w.need_to_write()) {
        worker_to_db(w);
      }
    }

    config_to_db(sc_ ? sc_->runner_config() : runner_config());
  });
  flush_db();

  if (will_send_transaction) {
    next_db_save_to_blockchain_at_ = td::Timestamp::in(td::Random::fast(30.0, 60.0));
    running_save_state_to_blockchain_ = true;

    auto msg = sc_->create_save_state_message(last_saved_state_seqno_, session_unique_hash_);
    cocoon_wallet()->send_transaction(
        sc_->address(), 1, {}, std::move(msg),
        [self_id = actor_id(this), seqno = last_saved_state_seqno_](td::Result<td::Unit> R) {
          R.ensure();
          td::actor::send_closure(self_id, &ProxyRunner::save_state_to_blockchain_completed, seqno);
        });
    if (ton_disabled()) {
      on_receive_saved_state_seqno(last_saved_state_seqno_, session_unique_hash_);
    }
  }
}

/*
 *
 * CRON
 *
 */

void ProxyRunner::alarm() {
  BaseRunner::alarm();

  if (!is_initialized()) {
    return;
  }

  if (next_db_flush_at_.is_in_past()) {
    all_to_db();
    next_db_flush_at_ = td::Timestamp::in(td::Random::fast(1.0, 2.0));
  }

  iterate_check_map(clients_);
  iterate_check_map(workers_);

  auto r = runner_config();
  if (r->root_contract_ts < (td::int32)std::time(0) - 7200 && !ton_disabled()) {
    if (check_image_hashes()) {
      LOG(FATAL) << "cannot download new config for 7200 seconds: ts=" << r->root_contract_ts;
    } else {
      LOG(WARNING) << "cannot download new config for 7200 seconds: ts=" << r->root_contract_ts;
    }
  }

  if (r->root_contract_config->version() > active_config_version_) {
    on_root_contract_config_update(r);
  }

  iterate_check_map(old_proxy_contracts_);

  if (sc_ && !running_withdraw_ && sc_->ready_for_withdraw() >= min_withdraw_amount()) {
    run_withdraw();
  }
  if (sc_ && (sc_->is_closing() || sc_->is_closed())) {
    proxy_enable_disable(r->root_contract_config->params_version() + 1);
  }
}

/*
 *
 * INBOUND MESSAGE HANDLERS
 *
 */

void ProxyRunner::receive_message(TcpClient::ConnectionId connection_id, td::BufferSlice query) {
  auto magic = get_tl_magic(query);
  switch (magic) {
    case cocoon_api::proxy_queryAnswerPart::ID: {
      auto conn = static_cast<ProxyInboundConnection *>(get_connection(connection_id));
      if (!conn || conn->connection_type() != ProxyInboundConnection::ConnectionType::Worker ||
          !conn->handshake_is_completed()) {
        LOG(ERROR) << "received message part from unknown connection";
        return;
      }

      auto R = fetch_tl_object<cocoon_api::proxy_queryAnswerPart>(std::move(query), true);
      if (R.is_error()) {
        LOG(ERROR) << "received malformed message from worker: " << R.move_as_error();
        return;
      }
      auto obj = R.move_as_ok();
      auto it = running_queries_.find(obj->request_id_);
      if (it != running_queries_.end()) {
        td::actor::send_closure(it->second, &ProxyRunningRequest::receive_answer_part, std::move(obj));
      } else {
        LOG(WARNING) << "received answer to unknown query " << obj->request_id_.to_hex();
      }
      return;
    };
    case cocoon_api::proxy_queryAnswerPartError::ID: {
      auto conn = static_cast<ProxyInboundConnection *>(get_connection(connection_id));
      if (!conn || conn->connection_type() != ProxyInboundConnection::ConnectionType::Worker ||
          !conn->handshake_is_completed()) {
        LOG(ERROR) << "received message part from unknown connection";
        return;
      }

      auto R = fetch_tl_object<cocoon_api::proxy_queryAnswerPartError>(std::move(query), true);
      if (R.is_error()) {
        LOG(ERROR) << "received malformed message from worker: " << R.move_as_error();
        return;
      }
      auto obj = R.move_as_ok();
      auto it = running_queries_.find(obj->request_id_);
      if (it != running_queries_.end()) {
        td::actor::send_closure(it->second, &ProxyRunningRequest::receive_answer_part_error, std::move(obj));
      } else {
        LOG(WARNING) << "received answer to unknown query " << obj->request_id_.to_hex();
      }
      return;
    };
    case cocoon_api::proxy_queryAnswer::ID: {
      auto conn = static_cast<ProxyInboundConnection *>(get_connection(connection_id));
      if (!conn || conn->connection_type() != ProxyInboundConnection::ConnectionType::Worker ||
          !conn->handshake_is_completed()) {
        LOG(ERROR) << "received message part from unknown connection";
        return;
      }

      auto R = fetch_tl_object<cocoon_api::proxy_queryAnswer>(std::move(query), true);
      if (R.is_error()) {
        LOG(ERROR) << "received malformed message from worker: " << R.move_as_error();
        return;
      }
      auto obj = R.move_as_ok();
      auto it = running_queries_.find(obj->request_id_);
      if (it != running_queries_.end()) {
        td::actor::send_closure(it->second, &ProxyRunningRequest::receive_answer, std::move(obj));
      } else {
        LOG(WARNING) << "received answer to unknown query " << obj->request_id_.to_hex();
      }
      return;
    };
    case cocoon_api::proxy_queryAnswerError::ID: {
      auto conn = static_cast<ProxyInboundConnection *>(get_connection(connection_id));
      if (!conn || conn->connection_type() != ProxyInboundConnection::ConnectionType::Worker ||
          !conn->handshake_is_completed()) {
        LOG(ERROR) << "received message part from unknown connection";
        return;
      }

      auto R = fetch_tl_object<cocoon_api::proxy_queryAnswerError>(std::move(query), true);
      if (R.is_error()) {
        LOG(ERROR) << "received malformed message from worker: " << R.move_as_error();
        return;
      }
      auto obj = R.move_as_ok();
      auto it = running_queries_.find(obj->request_id_);
      if (it != running_queries_.end()) {
        td::actor::send_closure(it->second, &ProxyRunningRequest::receive_answer_error, std::move(obj));
      } else {
        LOG(WARNING) << "received answer to unknown query " << obj->request_id_.to_hex();
      }
      return;
    };
    case cocoon_api::proxy_queryAnswerEx::ID:
    case cocoon_api::proxy_queryAnswerErrorEx::ID:
    case cocoon_api::proxy_queryAnswerPartEx::ID: {
      auto conn = static_cast<ProxyInboundConnection *>(get_connection(connection_id));
      if (!conn || conn->connection_type() != ProxyInboundConnection::ConnectionType::Worker ||
          !conn->handshake_is_completed()) {
        LOG(ERROR) << "received message part from unknown connection";
        return;
      }

      auto R = fetch_tl_object<cocoon_api::proxy_QueryAnswerEx>(std::move(query), true);
      if (R.is_error()) {
        LOG(ERROR) << "received malformed message from worker: " << R.move_as_error();
        return;
      }
      auto obj = R.move_as_ok();
      td::Bits256 request_id;
      cocoon_api::downcast_call(*obj, [&](auto &e) { request_id = e.request_id_; });

      auto it = running_queries_.find(request_id);
      if (it != running_queries_.end()) {
        td::actor::send_closure(it->second, &ProxyRunningRequest::receive_answer_ex, std::move(obj));
      } else {
        LOG(WARNING) << "received answer to unknown query " << request_id.to_hex();
      }
      return;
    }
    case cocoon_api::client_runQuery::ID: {
      auto conn = static_cast<ProxyInboundConnection *>(get_connection(connection_id));
      if (!conn || conn->connection_type() != ProxyInboundConnection::ConnectionType::Client ||
          !conn->handshake_is_completed()) {
        LOG(ERROR) << "client is not ready";
        return;
      }

      auto R = fetch_tl_object<cocoon_api::client_runQuery>(std::move(query), true);
      if (R.is_error()) {
        LOG(ERROR) << "received malformed message from client: " << R.move_as_error();
        return;
      }
      auto obj = R.move_as_ok();

      auto ex_obj = ton::create_tl_object<cocoon_api::client_runQueryEx>(
          std::move(obj->model_name_), std::move(obj->query_), obj->max_coefficient_, obj->max_tokens_, obj->timeout_,
          obj->request_id_, obj->min_config_version_, 0, false, td::Bits256::zero());
      forward_query(connection_id, std::move(ex_obj));
      return;
    };
    case cocoon_api::client_runQueryEx::ID: {
      auto conn = static_cast<ProxyInboundConnection *>(get_connection(connection_id));
      if (!conn || conn->connection_type() != ProxyInboundConnection::ConnectionType::Client ||
          !conn->handshake_is_completed()) {
        LOG(ERROR) << "client is not ready";
        return;
      }

      auto R = fetch_tl_object<cocoon_api::client_runQueryEx>(std::move(query), true);
      if (R.is_error()) {
        LOG(ERROR) << "received malformed message from client: " << R.move_as_error();
        return;
      }
      auto obj = R.move_as_ok();

      forward_query(connection_id, std::move(obj));
      return;
    };
    case cocoon_api::worker_enabledDisabled::ID: {
      auto conn = static_cast<ProxyInboundConnection *>(get_connection(connection_id));
      if (!conn || conn->connection_type() != ProxyInboundConnection::ConnectionType::Worker ||
          !conn->handshake_is_completed()) {
        LOG(ERROR) << "received worker message from unknown connection";
        return;
      }

      auto R = fetch_tl_object<cocoon_api::worker_enabledDisabled>(std::move(query), true);
      if (R.is_error()) {
        LOG(ERROR) << "received malformed message from worker: " << R.move_as_error();
        return;
      }
      auto obj = R.move_as_ok();
      static_cast<ProxyInboundWorkerConnection *>(conn)->worker_connection_info()->is_disabled = obj->disabled_;
      return;
    };
    case cocoon_api::worker_newCoefficient::ID: {
      auto conn = static_cast<ProxyInboundConnection *>(get_connection(connection_id));
      if (!conn || conn->connection_type() != ProxyInboundConnection::ConnectionType::Worker ||
          !conn->handshake_is_completed()) {
        LOG(ERROR) << "received worker message from unknown connection";
        return;
      }

      auto R = fetch_tl_object<cocoon_api::worker_newCoefficient>(std::move(query), true);
      if (R.is_error()) {
        LOG(ERROR) << "received malformed message from worker: " << R.move_as_error();
        return;
      }
      auto obj = R.move_as_ok();
      if (obj->new_coefficient_ < 0) {
        fail_connection(connection_id, td::Status::Error(ton::ErrorCode::protoviolation, "bad coefficient value"));
        return;
      }
      static_cast<ProxyInboundWorkerConnection *>(conn)->worker_connection_info()->coefficient = obj->new_coefficient_;
      return;
    };
    default:
      LOG(ERROR) << "received proxy message with unknown magic " << td::format::as_hex(magic);
  }
}

void ProxyRunner::receive_query(TcpClient::ConnectionId connection_id, td::BufferSlice query,
                                td::Promise<td::BufferSlice> promise) {
  auto magic = get_tl_magic(query);
  switch (magic) {
    case cocoon_api::client_connectToProxy::ID:
    case cocoon_api::client_authorizeWithProxyShort::ID:
    case cocoon_api::client_authorizeWithProxyLong::ID: {
      auto conn = static_cast<ProxyInboundConnection *>(get_connection(connection_id));
      if (!conn || conn->connection_type() != ProxyInboundConnection::ConnectionType::Client) {
        return promise.set_error(td::Status::Error(ton::ErrorCode::protoviolation, "client connect() from non client"));
      }
      auto client_conn = static_cast<ProxyInboundClientConnection *>(conn);
      client_conn->receive_handshake_query(std::move(query), std::move(promise));
    } break;
    case cocoon_api::client_updatePaymentStatus::ID: {
      auto conn = static_cast<ProxyInboundConnection *>(get_connection(connection_id));
      if (!conn || conn->connection_type() != ProxyInboundConnection::ConnectionType::Client) {
        return promise.set_error(td::Status::Error(ton::ErrorCode::protoviolation, "client request from non client"));
      }
      if (!conn->handshake_is_completed()) {
        return promise.set_error(
            td::Status::Error(ton::ErrorCode::protoviolation, "client request from non-ready connection"));
      }
      promise.set_value(cocoon::serialize_tl_object(
          static_cast<ProxyInboundClientConnection *>(conn)->client_info()->serialize_payment_status(), true));
    } break;
    case cocoon_api::worker_connectToProxy::ID:
    case cocoon_api::worker_compareBalanceWithProxy::ID:
    case cocoon_api::worker_extendedCompareBalanceWithProxy::ID:
    case cocoon_api::worker_proxyHandshakeComplete::ID: {
      auto conn = static_cast<ProxyInboundConnection *>(get_connection(connection_id));
      if (!conn || conn->connection_type() != ProxyInboundConnection::ConnectionType::Worker) {
        return promise.set_error(td::Status::Error(ton::ErrorCode::protoviolation, "worker connect() from non worker"));
      }
      auto worker_conn = static_cast<ProxyInboundWorkerConnection *>(conn);
      worker_conn->receive_handshake_query(std::move(query), std::move(promise));
    } break;
    case cocoon_api::worker_updatePaymentStatus::ID: {
      auto conn = static_cast<ProxyInboundConnection *>(get_connection(connection_id));
      if (!conn || conn->connection_type() != ProxyInboundConnection::ConnectionType::Worker) {
        return promise.set_error(td::Status::Error(ton::ErrorCode::protoviolation, "worker request from non worker"));
      }
      if (!conn->handshake_is_completed()) {
        return promise.set_error(
            td::Status::Error(ton::ErrorCode::protoviolation, "worker request from non-ready connection"));
      }
      promise.set_value(cocoon::serialize_tl_object(
          static_cast<ProxyInboundWorkerConnection *>(conn)->worker_info()->serialize_payment_status(), true));
    } break;
    case cocoon_api::client_getWorkerTypes::ID: {
      auto conn = static_cast<ProxyInboundConnection *>(get_connection(connection_id));
      if (!conn || conn->connection_type() != ProxyInboundConnection::ConnectionType::Client ||
          !conn->handshake_is_completed()) {
        return promise.set_error(td::Status::Error(ton::ErrorCode::protoviolation, "expected client connection"));
      }
      TRY_RESULT_PROMISE(promise, obj, fetch_tl_object<cocoon_api::client_getWorkerTypes>(std::move(query), true));

      std::vector<ton::tl_object_ptr<cocoon_api::client_workerType>> r;
      for (auto &x : models_) {
        r.emplace_back(ton::create_tl_object<cocoon_api::client_workerType>(
            x.second.model_base_name, (td::int32)x.second.connections.size(), 0, 0, 0));

        std::vector<td::int64> coef;
        coef.push_back(std::numeric_limits<td::int32>::max());
        for (auto &c : x.second.connections) {
          coef.push_back(c.second->coefficient);
        }

        std::sort(coef.begin(), coef.end());

        r.back()->coefficient_min_ = (td::int32)coef[0];
        r.back()->coefficient_max_ = (td::int32)coef.back();
        r.back()->coefficient_bucket50_ = (td::int32)coef[coef.size() / 2];
      }

      promise.set_value(cocoon::create_serialize_tl_object<cocoon_api::client_workerTypes>(std::move(r)));
    } break;
    case cocoon_api::client_getWorkerTypesV2::ID: {
      auto conn = static_cast<ProxyInboundConnection *>(get_connection(connection_id));
      if (!conn || conn->connection_type() != ProxyInboundConnection::ConnectionType::Client ||
          !conn->handshake_is_completed()) {
        return promise.set_error(td::Status::Error(ton::ErrorCode::protoviolation, "expected client connection"));
      }
      TRY_RESULT_PROMISE(promise, obj, fetch_tl_object<cocoon_api::client_getWorkerTypesV2>(std::move(query), true));

      std::vector<ton::tl_object_ptr<cocoon_api::client_workerTypeV2>> r;
      for (auto &x : models_) {
        std::vector<ton::tl_object_ptr<cocoon_api::client_workerInstanceV2>> e;

        for (auto &c : x.second.connections) {
          if (c.second->is_disabled) {
            continue;
          }
          e.push_back(ton::create_tl_object<cocoon_api::client_workerInstanceV2>(
              /* flags */ 0, (td::int32)c.second->coefficient, c.second->running_queries(),
              c.second->max_active_requests));
        }

        std::sort(e.begin(), e.end(), [](const auto &l, const auto &r) { return l->coefficient_ < r->coefficient_; });

        r.push_back(ton::create_tl_object<cocoon_api::client_workerTypeV2>(x.second.model_base_name, std::move(e)));
      }

      promise.set_value(cocoon::create_serialize_tl_object<cocoon_api::client_workerTypesV2>(std::move(r)));
    } break;
    default:
      LOG(ERROR) << "received proxy query with unknown magic " << td::format::as_hex(magic);
  }
}

/* CONTROL */

void ProxyRunner::on_receive_transaction(const block::StdAddress &src_address, td::uint32 op, td::uint64 qid) {
  if (src_address.workchain == cocoon_wallet()->address().workchain &&
      src_address.addr == cocoon_wallet()->address().addr && op == opcodes::ext_proxy_payout_request &&
      qid == withdraw_request_id_ && running_withdraw_) {
    running_withdraw_ = false;
  }
}

void ProxyRunner::proxy_enable_disable(td::int64 value) {
  if (!is_initialized()) {
    return;
  }
  if (is_disabled_until_version_ > 0) {
    if (is_disabled_until_version_ < value) {
      is_disabled_until_version_ = value;
    } else {
      is_disabled_until_version_ =
          std::max<td::int64>(value, runner_config()->root_contract_config->params_version() + 1);
    }
  } else {
    if (value <= runner_config()->root_contract_config->params_version()) {
      return;
    } else {
      is_disabled_until_version_ = value;
      kv_->begin_transaction().ensure();

      close_all();
      config_to_db(runner_config());

      kv_->commit_transaction().ensure();
      CHECK(is_disabled());
    }
  }
}

void ProxyRunner::run_withdraw() {
  if (running_withdraw_) {
    return;
  }
  withdraw_request_id_ = td::Random::fast_uint64();

  auto msg = sc_->create_withdraw_message(withdraw_request_id_);
  cocoon_wallet()->send_transaction(sc_->address(), to_nano(0.2), {}, std::move(msg), {});
  running_withdraw_ = true;
}

/*
 *
 * REQUEST HANDING
 *
 */

td::Result<std::shared_ptr<ProxyWorkerConnectionInfo>> ProxyRunner::choose_connection(const std::string &model_name,
                                                                                      td::int64 tokens_available,
                                                                                      td::int64 max_coefficient,
                                                                                      td::int64 max_tokens,
                                                                                      td::int32 min_proto_version) {
  LOG(DEBUG) << " max_coefficient=" << max_coefficient << " max_tokens=" << max_tokens
             << " tokens_available=" << tokens_available;
  if (is_disabled()) {
    return td::Status::Error(ton::ErrorCode::notready, PSTRING() << "proxy is disabled");
  }
  if (max_tokens > tokens_available) {
    return td::Status::Error(ton::ErrorCode::notready, PSTRING() << "balance is too low");
  }
  auto it = models_.find(model_name);
  if (it == models_.end()) {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << "unknown model " << model_name);
  }
  if (it->second.connections.size() == 0) {
    return td::Status::Error(ton::ErrorCode::notready, PSTRING() << "no workers for model " << model_name);
  }

  td::int64 min_coefficient = std::numeric_limits<td::int64>::max();
  std::shared_ptr<ProxyWorkerConnectionInfo> best_conn;

  double best_worker_connection_weight = 1e100;
  double best_worker_recent_queries = 1e100;

  for (auto &x : it->second.connections) {
    if (x.second->is_disabled) {
      continue;
    }

    auto conn = static_cast<ProxyInboundWorkerConnection *>(get_connection(x.first));
    if (!conn || conn->proto_version() < min_proto_version) {
      continue;
    }

    if (x.second->running_queries() >= x.second->max_active_requests) {
      continue;
    }
    if (x.second->coefficient <= max_coefficient) {
      // Load = in-flight queries x their average time. A worker with no timing history yet counts each in-flight
      // query as one second, so it is not seen as idle while busy. Equal load (typically several idle workers) goes
      // to the worker that served fewer queries recently, so a newly joined worker gets traffic instead of the
      // first connection taking every request.
      auto avg = x.second->average_query_time();
      double weight = x.second->running_queries() * (avg > 0 ? avg : 1.0);
      double recent = x.second->recent_queries();
      if (weight < best_worker_connection_weight ||
          (weight == best_worker_connection_weight && recent < best_worker_recent_queries)) {
        best_conn = x.second;
        best_worker_connection_weight = weight;
        best_worker_recent_queries = recent;
      }
    } else {
      if (min_coefficient > x.second->coefficient) {
        min_coefficient = x.second->coefficient;
      }
    }
  }

  if (best_conn) {
    return best_conn;
  } else {
    if (min_coefficient == std::numeric_limits<td::int64>::max()) {
      return td::Status::Error(ton::ErrorCode::notready, PSTRING() << "no ready workers for model" << model_name);
    } else {
      return td::Status::Error(ton::ErrorCode::notready,
                               PSTRING() << "can run this query with coefficient=" << min_coefficient);
    }
  }
}

void ProxyRunner::forward_query(TcpClient::ConnectionId client_connection_id,
                                ton::tl_object_ptr<cocoon_api::client_runQueryEx> req) {
  auto client_tcp_connection = static_cast<ProxyInboundClientConnection *>(get_connection(client_connection_id));
  auto client = static_cast<ProxyInboundClientConnection *>(client_tcp_connection)->client_info();

  auto client_request_id = req->request_id_;
  auto fail = [&](td::Status S) {
    td::BufferSlice res;
    auto client_proto_version = client_tcp_connection->proto_version();
    if (client_proto_version > 0) {
      res = cocoon::create_serialize_tl_object<cocoon_api::client_queryAnswerErrorEx>(
          client_request_id, S.code(), S.message().str(), 1,
          ton::create_tl_object<cocoon_api::client_queryFinalInfo>(
              (client_proto_version >= 2 ? 2 : 0), ton::create_tl_object<cocoon_api::tokensUsed>(0, 0, 0, 0, 0), "", "",
              td::Clocks::system(), td::Clocks::system(), td::Clocks::system(), td::Clocks::system()));
    } else {
      res = cocoon::create_serialize_tl_object<cocoon_api::client_queryAnswerError>(
          S.code(), S.message().str(), client_request_id, ton::create_tl_object<cocoon_api::tokensUsed>(0, 0, 0, 0, 0));
    }
    send_message_to_connection(client_connection_id, std::move(res));
    stats_->requests_rejected++;
  };

  if (client->tokens_available() < req->max_tokens_) {
    return fail(td::Status::Error(
        ton::ErrorCode::error,
        PSTRING() << "client balance is too low: max_tokens=" << req->max_tokens_
                  << " tokens_payed=" << client->tokens_payed() << " tokens_used=" << client->tokens_used()
                  << " tokens_reserved=" << client->tokens_reserved() << " tokens_stake=" << client->tokens_stake()));
  }

  if ((td::uint32)req->min_config_version_ > active_config_version_) {
    return fail(td::Status::Error(ton::ErrorCode::error, "active config version is too low"));
  }
  if (!client->allow_queries()) {
    return fail(td::Status::Error(ton::ErrorCode::notready, "client is closing"));
  }

  td::Bits256 encrypted_with = td::Bits256::zero();
  if ((req->flags_ & 2) && !req->public_key_.is_zero()) {
    if (!get_private_key(req->public_key_, encrypted_with)) {
      return fail(
          td::Status::Error(ton::ErrorCode::error, PSTRING() << "unknown public key " << req->public_key_.to_hex()));
    }
  }

  auto to_reserve = adjust_tokens(req->max_tokens_ + req->query_.size(), req->max_coefficient_, 10000);
  auto R_worker_connection_id =
      choose_connection(req->model_name_, client->tokens_available(), (td::uint32)req->max_coefficient_, to_reserve,
                        encrypted_with.is_zero() ? 0 : 3);
  if (R_worker_connection_id.is_error()) {
    return fail(R_worker_connection_id.move_as_error());
  }
  auto worker_connection = R_worker_connection_id.move_as_ok();

  if (!client->reserve(to_reserve)) {
    return fail(td::Status::Error(
        ton::ErrorCode::error,
        PSTRING() << "client balance is too low: to_reserve=" << to_reserve
                  << " tokens_payed=" << client->tokens_payed() << " tokens_used=" << client->tokens_used()
                  << " tokens_reserved=" << client->tokens_reserved() << " tokens_stake=" << client->tokens_stake()));
  }

  td::Bits256 request_id;
  td::Random::secure_bytes(request_id.as_slice());

  client->start_query();
  worker_connection->forwarded_query();
  worker_connection->info->forwarded_query();

  auto worker_tcp_connection =
      static_cast<ProxyInboundWorkerConnection *>(get_connection(worker_connection->connection_id));

  if (!client_tcp_connection || !worker_tcp_connection) {
    return fail(td::Status::Error(ton::ErrorCode::error, PSTRING() << "connection is dead"));
  }

  auto request = td::actor::create_actor<ProxyRunningRequest>(
                     PSTRING() << "request_" << client_request_id.to_hex() << "_" << request_id.to_hex(), request_id,
                     client_request_id, client_connection_id, client_tcp_connection->proto_version(), client,
                     worker_tcp_connection->proto_version(), worker_connection, std::move(req->query_), encrypted_with,
                     req->timeout_, req->enable_debug_, to_reserve, actor_id(this), stats_)
                     .release();
  CHECK(running_queries_.emplace(request_id, request).second);
}

void ProxyRunner::finish_request(const td::Bits256 &worker_request_id, const td::Bits256 &client_request_id,
                                 std::shared_ptr<ProxyClientInfo> client, TcpClient::ConnectionId client_connection_id,
                                 std::shared_ptr<ProxyWorkerInfo> worker,
                                 std::shared_ptr<ProxyWorkerConnectionInfo> worker_connection,
                                 ton::tl_object_ptr<cocoon_api::tokensUsed> tokens_used, td::int64 to_unlock,
                                 bool is_success, double work_time, double worker_run_time) {
  auto to_deduct = tokens_used->total_tokens_used_;
  worker->adjust_balance(to_deduct);
  client->deduct(to_deduct);
  client->release_reserve(to_unlock);
  if (is_success) {
    worker->forwarded_query_success(work_time);
    worker_connection->forwarded_query_success(work_time, worker_run_time);
    client->stop_query();
  } else {
    worker->forwarded_query_failed(work_time);
    worker_connection->forwarded_query_failed(work_time, worker_run_time);
    client->stop_query();
  }
  CHECK(running_queries_.erase(worker_request_id));

  stats_->total_adjusted_tokens_used += (double)tokens_used->total_tokens_used_;
  stats_->prompt_adjusted_tokens_used += (double)tokens_used->prompt_tokens_used_;
  stats_->cached_adjusted_tokens_used += (double)tokens_used->cached_tokens_used_;
  stats_->completion_adjusted_tokens_used += (double)tokens_used->completion_tokens_used_;
  stats_->reasoning_adjusted_tokens_used += (double)tokens_used->reasoning_tokens_used_;

  sign_worker_payment(*worker);
  //proxy.workerRequestPayment signed_payment:proxy.SignedPayment db_tokens:long max_tokens:long last_request_tokens:long last_request_client:string =
  //proxy.WorkerRequestPayment;
  auto req = cocoon::create_serialize_tl_object<cocoon_api::proxy_workerRequestPayment>(
      worker_request_id, worker->signed_payment(), worker->tokens_committed_to_db(), worker->tokens_max(), to_deduct,
      client->client_owner_address().rserialize(true));
  send_message_to_connection(worker_connection->connection_id, std::move(req));

  sign_client_payment(*client);
  auto req2 = cocoon::create_serialize_tl_object<cocoon_api::proxy_clientRequestPayment>(
      client_request_id, client->signed_payment(), client->tokens_committed_to_db(), client->tokens_max(), to_deduct);
  send_message_to_connection(client_connection_id, std::move(req2));
}

/*
 *
 * HTTP HANDLING
 *
 */

std::string ProxyRunner::http_payout(std::string worker_sc_address) {
  auto it2 = workers_.find(worker_sc_address);
  if (it2 == workers_.end()) {
    return wrap_short_answer_to_http("worker not found");
  }
  auto &worker = *it2->second;
  if (worker.paying_now()) {
    return wrap_short_answer_to_http("request already running");
  }
  if (is_initialized()) {
    all_to_db();
  }
  if (!worker.tokens_ready_to_pay()) {
    return wrap_short_answer_to_http("nothing to pay");
  }
  worker_payout(worker, false);
  return wrap_short_answer_to_http("request sent");
}

std::string ProxyRunner::http_charge(std::string client_owner_address_str) {
  auto it2 = clients_.find(client_owner_address_str);
  if (it2 == clients_.end()) {
    return wrap_short_answer_to_http("client not found");
  }

  auto &client = *it2->second;

  if (client.charging_now()) {
    return wrap_short_answer_to_http("request already running");
  }
  if (!client.tokens_ready_to_charge()) {
    return wrap_short_answer_to_http("nothing to charge");
  }

  client_charge(client, false);
  return wrap_short_answer_to_http("request sent");
}

std::string ProxyRunner::http_enable_disable(td::int64 disable_up_to_version) {
  proxy_enable_disable(disable_up_to_version);
  return wrap_short_answer_to_http("disabled");
}

std::string ProxyRunner::http_withdraw() {
  if (!sc_) {
    return wrap_short_answer_to_http("proxy is disabled");
  }

  if (!sc_->ready_for_withdraw()) {
    return wrap_short_answer_to_http("nothing to withdraw");
  }

  if (running_withdraw_) {
    return wrap_short_answer_to_http("withdraw already running");
  }

  run_withdraw();

  return wrap_short_answer_to_http("request sent");
}

std::string ProxyRunner::http_change_worker_model(std::string worker_connection_id, std::string new_model_name) {
  auto R = td::to_integer_safe<td::int64>(worker_connection_id);
  if (R.is_error()) {
    return wrap_short_answer_to_http("worker_connection_id not an integer");
  }
  auto conn_id = R.move_as_ok();
  auto conn = get_connection(conn_id);
  if (!conn) {
    return wrap_short_answer_to_http("connection not found");
  }
  if (conn->remote_app_type() != remote_app_type_worker()) {
    return wrap_short_answer_to_http("connection not from worker");
  }
  auto w_conn = static_cast<ProxyInboundWorkerConnection *>(conn);
  if (!w_conn->handshake_is_completed()) {
    return wrap_short_answer_to_http("connection is not ready");
  }
  auto req = create_serialize_tl_object<cocoon_api::worker_changeModel>(new_model_name);
  send_query_to_connection(conn_id, "changeworkermodel", std::move(req), td::Timestamp::in(60.0), {});
  return wrap_short_answer_to_http("request sent");
}

std::string ProxyRunner::http_generate_main() {
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
      bool is_valid = runner_config()->root_contract_config->has_proxy_hash(local_image_hash_unverified_);
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
    if (is_disabled_until_version_ == 0) {
      sb << "<span style=\"background-color:Green;\">yes</span>";
      sb << "<form method=\"post\" action=\"/request/disable\">"
         << "<button type=\"submit\" name=\"disable\" value=\"yes I am sure\">disable</button></form>\n";
    } else {
      sb << "<span style=\"background-color:Crimson;\">no until config version " << is_disabled_until_version_
         << "</span>";
      sb << "<form method=\"post\" action=\"/request/enable\">"
         << "<button type=\"submit\" name=\"enable\" value=\"yes I am sure\">enable from the next "
            "version</button></form>\n";
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
    sb << "<tr><td>rejected</td>" << stats_->requests_rejected.to_html_row() << "</tr>\n";
    sb << "<tr><td>bytes received</td>" << stats_->request_bytes_received.to_html_row() << "</tr>\n";
    sb << "<tr><td>bytes sent</td>" << stats_->answer_bytes_sent.to_html_row() << "</tr>\n";
    sb << "<tr><td>time</td>" << stats_->total_requests_time.to_html_row() << "</tr>\n";
    sb << "<tr><td>total adjusted tokens</td>" << stats_->total_adjusted_tokens_used.to_html_row() << "</tr>\n";
    sb << "<tr><td>prompt adjusted tokens</td>" << stats_->prompt_adjusted_tokens_used.to_html_row() << "</tr>\n";
    sb << "<tr><td>cached adjusted tokens</td>" << stats_->cached_adjusted_tokens_used.to_html_row() << "</tr>\n";
    sb << "<tr><td>completiom adjusted tokens</td>" << stats_->completion_adjusted_tokens_used.to_html_row()
       << "</tr>\n";
    sb << "<tr><td>reasoning adjusted tokens</td>" << stats_->reasoning_adjusted_tokens_used.to_html_row() << "</tr>\n";
    sb << "</table>\n";
  }

  store_wallet_stat(sb);
  store_known_private_keys(sb);

  {
    sb << "<h1>LOCAL CONFIG</h1>\n";
    sb << "<table>\n";
    sb << "<tr><td>root address</td><td>" << address_link(root_contract_address()) << "</td></tr>\n";
    sb << "<tr><td>owner address</td><td>" << address_link(owner_address()) << "</td></tr>\n";
    sb << "<tr><td>check image hashes</td><td>" << (check_image_hashes() ? "YES" : "NO") << "</td></tr>\n";
    sb << "</table>\n";
  }

  auto sc = sc_;
  if (sc) {
    sb << "<h1>SMARTCONTRACT</h1>\n";
    sb << "<table>\n";
    sb << "<tr><td>address</td><td>" << address_link(sc->address()) << "</td></tr>\n";
    sb << "<tr><td>params version</td><td>" << sc->runner_config()->root_contract_config->params_version()
       << "</td></tr>\n";
    sb << "<tr><td>balance</td><td>" << to_ton(sc->balance()) << "</td></tr>\n";
    sb << "<tr><td>running withdraw</td><td>" << (running_withdraw_ ? "YES" : "NO") << "</td></tr>\n";
    sb << "<tr><td>ready to withdraw</td><td>" << to_ton(sc->ready_for_withdraw());
    if (sc->ready_for_withdraw() > 0) {
      sb << " <a href=\"/request/withdraw\">get now </a>";
    }
    sb << "</td></tr>\n";
    sb << "</table>\n";
  }

  {
    sb << "<h1>OLD INSTANCES</h1>\n";
    for (auto &it : old_proxy_contracts_) {
      auto &s = *it.second;
      sb << "<h2>OLD SC " << it.first << "</h2>\n";
      s.store_stats(sb);
    }
  }

  store_root_contract_stat(sb);

  {
    sb << "<h1>WORKERS</h1>\n";
    for (auto &it : workers_) {
      auto &w = *it.second;
      sb << "<h2>WORKER " << address_link(w.worker_owner_address()) << "</h2>\n";
      w.store_stats(sb, sc_->runner_config()->root_contract_config->worker_fee_per_token());
    }
  }

  {
    sb << "<h1>WORKERS CONNECTIONS</h1>\n";
    for (auto &it : models_) {
      td::Slice model_base_name = it.second.model_base_name;
      for (auto &it2 : it.second.connections) {
        auto &w = *it2.second;
        sb << "<h2>WORKER CONNECTION " << address_link(w.info->worker_owner_address()) << "</h2>\n";
        w.store_stats(sb);
        sb << "change model: <form method=\"post\" action=\"/request/change_worker_model\">\n"
           << "<input type=\"text\" id=\"new_model_name\" name=\"new_model_name\">\n"
           << "<input type=\"hidden\" id=\"connection_id\" name=\"connection_id\" value=\"" << it2.first << "\">\n"
           << "<input type=\"submit\" id=\"change_worker_model\" name=\"change_worker_model\" value=\"change model\">\n"
           << "</form></br>\n";
      }
    }
  }

  {
    sb << "<h1>CLIENTS</h1>\n";
    for (auto &it : clients_) {
      auto &c = *it.second;
      sb << "<h2>CLIENT " << address_link(c.client_owner_address()) << "</h2>\n";
      c.store_stats(sb, sc_->runner_config()->root_contract_config->price_per_token());
    }
  }

  sb << "</body></html>\n";
  return sb.as_cslice().str();
}

std::string ProxyRunner::http_generate_json_stats() {
  SimpleJsonSerializer jb;

  jb.start_object();
  {
    jb.start_object("status");
    if (cocoon_wallet()) {
      jb.add_element("wallet_balance", cocoon_wallet()->balance());
    }
    if (check_image_hashes() && sc_) {
      jb.add_element("actual_image_hash",
                     sc_->runner_config()->root_contract_config->has_proxy_hash(local_image_hash_unverified_));
    } else {
      jb.add_element("actual_image_hash", true);
    }
    auto r = runner_config();
    if (r) {
      jb.add_element("ton_last_synced_at", r->root_contract_ts);
    }
    jb.add_element("enabled", is_disabled_until_version_ == 0);
    jb.add_element("git_commit", GitMetadata::CommitSHA1());
    jb.add_element("git_commit_data", GitMetadata::CommitDate());
    jb.stop_object();
  }
  jb.start_object("stats");
  stats_->requests_received.to_jb(jb, "queries");
  stats_->requests_success.to_jb(jb, "success");
  stats_->requests_failed.to_jb(jb, "failed");
  stats_->requests_rejected.to_jb(jb, "rejected");
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
    jb.add_element("check_image_hashes", check_image_hashes());
    jb.stop_object();
  }

  auto sc = sc_;
  if (sc) {
    jb.start_object("smartcontract");
    jb.add_element("address", sc->address().rserialize(true));
    jb.add_element("params_version", sc->runner_config()->root_contract_config->params_version());
    jb.add_element("balance", sc->balance());
    jb.add_element("ready_for_withdraw", sc->ready_for_withdraw());
    jb.stop_object();
  }

  {
    jb.start_array("old_instances");
    for (auto &it : old_proxy_contracts_) {
      auto &s = *it.second;
      s.store_stats(jb);
    }
    jb.stop_array();
  }

  store_root_contract_stat(jb);

  {
    jb.start_array("workers");
    for (auto &it : workers_) {
      auto &w = *it.second;
      w.store_stats(jb);
    }
    jb.stop_array();
  }

  {
    jb.start_array("worker_connections");
    for (auto &it : models_) {
      td::Slice model_base_name = it.second.model_base_name;
      for (auto &it2 : it.second.connections) {
        auto &w = *it2.second;
        w.store_stats(jb);
      }
    }
    jb.stop_array();
  }

  {
    jb.start_array("clients");
    for (auto &it : clients_) {
      auto &c = *it.second;
      c.store_stats(jb);
    }
    jb.stop_array();
  }

  jb.stop_object();

  return jb.as_cslice().str();
}

}  // namespace cocoon
