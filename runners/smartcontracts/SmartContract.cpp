#include "SmartContract.hpp"
#include "auto/tl/tonlib_api.h"
#include "runners/BaseRunner.hpp"
#include "errorcode.h"
#include "td/actor/PromiseFuture.h"
#include "td/actor/actor.h"
#include "tl/TlObject.h"
#include "ton/ton-types.h"

#define CHECK_SC_ALIVE()                                                          \
  if (!sc_is_alive(runner, self_id)) {                                            \
    promise.set_error(td::Status::Error(ton::ErrorCode::cancelled, "cancelled")); \
    return;                                                                       \
  }

#define CHECK_SC_ALIVE_NOPROMISE()     \
  if (!sc_is_alive(runner, self_id)) { \
    return;                            \
  }

namespace cocoon {

static std::atomic<td::int64> unique_id;

bool TonScWrapper::sc_is_alive(BaseRunner *runner, td::int64 sc_id) {
  return runner->sc_is_alive(sc_id);
}

td::int64 TonScWrapper::deploy_balance() const {
  return to_nano(0.3);
}

TonScWrapper::TonScWrapper(block::StdAddress addr, td::Ref<vm::Cell> code, BaseRunner *runner,
                           std::shared_ptr<RunnerConfig> runner_config)
    : id_(++unique_id), addr_(addr), code_(code), runner_(runner), runner_config_(std::move(runner_config)) {
}

void TonScWrapper::request_updates(td::Promise<td::Unit> promise) {
  auto P =
      td::PromiseCreator::lambda([self = this, self_id = id(), runner = runner_, promise = std::move(promise)](
                                     td::Result<ton::tl_object_ptr<ton::tonlib_api::raw_fullAccountState>> R) mutable {
        CHECK_SC_ALIVE();
        if (R.is_error()) {
          promise.set_error(R.move_as_error());
        } else {
          self->process_new_state(R.move_as_ok(), std::move(promise));
        }
      });
  if (is_inited_ || !init_block_id_.is_valid()) {
    auto req = ton::tonlib_api::make_object<ton::tonlib_api::raw_getAccountState>(
        ton::tonlib_api::make_object<ton::tonlib_api::accountAddress>(addr_.rserialize(true)));
    runner_->tonlib_send_request(std::move(req), std::move(P));
  } else {
    auto P_wrap = [P = std::move(P)](td::Result<ton::tl_object_ptr<ton::tonlib_api::Object>> R) mutable {
      if (R.is_error()) {
        P.set_error(R.move_as_error());
      } else {
        P.set_value(ton::move_tl_object_as<tonlib_api::raw_fullAccountState>(R.move_as_ok()));
      }
    };

    auto req = ton::create_tl_object<tonlib_api::withBlock>(
        block_id_obj_to_tl(init_block_id_),
        ton::tonlib_api::make_object<ton::tonlib_api::raw_getAccountState>(
            ton::tonlib_api::make_object<ton::tonlib_api::accountAddress>(addr_.rserialize(true))));
    runner_->tonlib_send_request(std::move(req), std::move(P_wrap));
  }
}

void TonScWrapper::process_new_state(ton::tl_object_ptr<ton::tonlib_api::raw_fullAccountState> state,
                                     td::Promise<td::Unit> promise) {
  if (!started_) {
    LOG(INFO) << "downloaded smartcontract state: block_id=" << state->block_id_->seqno_
              << " init=" << init_block_id_.seqno() << " addr=" << address();
    balance_ = state->balance_;
    started_ = true;
    lt_lt_ = state->last_transaction_id_->lt_;
    lt_hash_ = state->last_transaction_id_->hash_;
    state_sync_utime_ = state->sync_utime_;
    is_inited_ = state->data_.size() > 0;
    state_block_id_ = block_id_tl_to_obj(*state->block_id_);
    on_init(std::move(state));
    promise.set_value(td::Unit());
    on_state_update();
    return;
  }
  if (state->last_transaction_id_->lt_ <= lt_lt_) {
    auto id = block_id_tl_to_obj(*state->block_id_);
    if (!state_block_id_.is_valid() || id.seqno() > state_block_id_.seqno()) {
      state_block_id_ = id;
    }

    promise.set_value(td::Unit());
    return;
  }

  transactions_.clear();
  request_transactions(state->last_transaction_id_->lt_, state->last_transaction_id_->hash_, std::move(promise));
  next_state_ = std::move(state);
}

void TonScWrapper::request_transactions(td::int64 lt_lt, std::string lt_hash, td::Promise<td::Unit> promise) {
  auto req = ton::tonlib_api::make_object<ton::tonlib_api::raw_getTransactionsV2>(
      ton::tonlib_api::make_object<ton::tonlib_api::inputKeyFake>(),
      ton::tonlib_api::make_object<ton::tonlib_api::accountAddress>(addr_.rserialize(true)),
      ton::tonlib_api::make_object<ton::tonlib_api::internal_transactionId>(lt_lt, lt_hash), 1, false);
  runner_->tonlib_send_request(std::move(req),
                               [self = this, self_id = id(), runner = runner_, promise = std::move(promise)](
                                   td::Result<ton::tl_object_ptr<ton::tonlib_api::raw_transactions>> R) mutable {
                                 CHECK_SC_ALIVE();
                                 if (R.is_error()) {
                                   promise.set_error(R.move_as_error());
                                 } else {
                                   self->process_new_transactions(R.move_as_ok(), std::move(promise));
                                 }
                               });
}

void TonScWrapper::process_new_transactions(ton::tl_object_ptr<tonlib_api::raw_transactions> state,
                                            td::Promise<td::Unit> promise) {
  if (state->transactions_.size() == 0) {
    run_callbacks();
    promise.set_value(td::Unit());
    return;
  }
  /* newest to oldest */
  std::sort(state->transactions_.begin(), state->transactions_.end(),
            [](const ton::tl_object_ptr<tonlib_api::raw_transaction> &l,
               const ton::tl_object_ptr<tonlib_api::raw_transaction> &r) {
              return l->transaction_id_->lt_ > r->transaction_id_->lt_;
            });

  for (auto &t : state->transactions_) {
    if (t->transaction_id_->lt_ <= lt_lt_) {
      run_callbacks();
      promise.set_value(td::Unit());
      return;
    }
    transactions_.push_back(std::move(t));
  }

  request_transactions(state->previous_transaction_id_->lt_, state->previous_transaction_id_->hash_,
                       std::move(promise));
}

void TonScWrapper::run_callbacks() {
  for (auto it = transactions_.rbegin(); it != transactions_.rend(); it++) {
    lt_lt_ = (*it)->transaction_id_->lt_;
    lt_hash_ = (*it)->transaction_id_->hash_;

    on_transaction(std::move(*it));
  }

  LOG_CHECK(lt_lt_ == next_state_->last_transaction_id_->lt_ && lt_hash_ == next_state_->last_transaction_id_->hash_)
      << "missed transaction on " << address().rserialize(true) << ": reached lt=" << lt_lt_
      << " expected lt=" << next_state_->last_transaction_id_->lt_;

  transactions_.clear();
  balance_ = next_state_->balance_;
  state_block_id_ = block_id_tl_to_obj(*next_state_->block_id_);
  state_sync_utime_ = next_state_->sync_utime_;
  is_inited_ = next_state_->data_.size() > 0;
  LOG(DEBUG) << "downloaded next state: block_id=" << next_state_->block_id_->seqno_;
  on_state_update(std::move(next_state_));
  on_state_update();
}

block::StdAddress TonScWrapper::generate_address(td::Ref<vm::Cell> code, td::Ref<vm::Cell> data, bool is_testnet) {
  auto c = generate_sc_init_data(code, data);
  return block::StdAddress{0, c->get_hash().as_bitslice().bits(), false, is_testnet};
}

block::StdAddress TonScWrapper::generate_address() {
  return generate_address(code_, init_data_cell(), runner_config_->is_testnet);
}

void TonScWrapper::subscribe_to_updates(std::shared_ptr<TonScWrapper> self) {
  if (subscribed_) {
    return;
  }
  subscribed_ = true;
  runner_->add_smartcontract(self);
}

void TonScWrapper::unsubscribe_from_updates() {
  if (!subscribed_) {
    return;
  }
  subscribed_ = false;
  runner_->del_smartcontract(this);
}

void TonScWrapper::update_state(td::Promise<td::Unit> promise, td::int32 min_ts) {
  if (state_sync_utime_ >= min_ts || runner_config_->ton_disabled) {
    return promise.set_value(td::Unit());
  }
  state_update_promises_.push_back(std::move(promise));

  auto P =
      td::PromiseCreator::lambda([self = this, self_id = id(), runner = runner_, root_id = actor_id(runner_), min_ts](
                                     td::Result<ton::tl_object_ptr<ton::tonlib_api::raw_fullAccountState>> R) mutable {
        CHECK_SC_ALIVE_NOPROMISE();
        if (R.is_error()) {
          td::actor::send_lambda(root_id, [self, min_ts]() { self->update_state({}, min_ts); });
        } else {
          auto res = R.move_as_ok();
          if (self->is_started()) {
            if (self->subscribed_) {
              // do nothing
            } else {
              auto seqno = self->state_block_id_.is_valid() ? self->state_block_id_.seqno() : 0;
              if ((td::uint32)res->block_id_->seqno_ > seqno ||
                  ((td::uint32)res->block_id_->seqno_ == seqno && res->sync_utime_ > self->state_sync_utime_)) {
                self->process_new_state(std::move(res), {});
              }
            }
          } else {
            self->process_new_state(std::move(res), {});
          }
        }
      });

  if (is_started() || !init_block_id_.is_valid()) {
    auto req = ton::tonlib_api::make_object<ton::tonlib_api::raw_getAccountState>(
        ton::tonlib_api::make_object<ton::tonlib_api::accountAddress>(addr_.rserialize(true)));
    runner_->tonlib_send_request(std::move(req), std::move(P));
  } else {
    auto P_wrap = [P = std::move(P)](td::Result<ton::tl_object_ptr<ton::tonlib_api::Object>> R) mutable {
      if (R.is_error()) {
        P.set_error(R.move_as_error());
      } else {
        P.set_value(ton::move_tl_object_as<tonlib_api::raw_fullAccountState>(R.move_as_ok()));
      }
    };

    auto req = ton::create_tl_object<tonlib_api::withBlock>(
        block_id_obj_to_tl(init_block_id_),
        ton::tonlib_api::make_object<ton::tonlib_api::raw_getAccountState>(
            ton::tonlib_api::make_object<ton::tonlib_api::accountAddress>(addr_.rserialize(true))));
    runner_->tonlib_send_request(std::move(req), std::move(P_wrap));
  }
}

void TonScWrapper::deploy(td::Promise<td::Unit> promise) {
  LOG(INFO) << "deploying contract " << address().rserialize(true);
  if (!runner_config_->ton_disabled && !is_started()) {
    update_state(
        [self = this, self_id = id(), runner = runner_, promise = std::move(promise)](td::Result<td::Unit> R) mutable {
          CHECK_SC_ALIVE();
          if (R.is_error()) {
            promise.set_error(R.move_as_error());
          } else {
            self->deploy(std::move(promise));
          }
        },
        1);
    return;
  }

  if (is_inited_) {
    LOG(DEBUG) << "adready deployed";
    promise.set_value(td::Unit());
    return;
  }

  if (runner_config_->ton_disabled) {
    LOG(DEBUG) << "pseudo deploying...";
    init_pseudo_state();
    is_inited_ = true;
    started_ = true;
    balance_ = to_nano(100);
    promise.set_value(td::Unit());
    return;
  }

  LOG(DEBUG) << "sending ext message";
  runner_->cocoon_wallet()->send_transaction(address(), deploy_balance(), generate_sc_init_data(), {},
                                             std::move(promise));
}

}  // namespace cocoon
