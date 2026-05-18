#pragma once

#include "SmartContract.hpp"
#include "block.h"
#include "common/bitstring.h"
#include "crypto/Ed25519.h"
#include "td/actor/PromiseFuture.h"
#include "td/utils/Time.h"
#include "td/utils/common.h"
#include "vm/cells/Cell.h"

#include <list>
#include <memory>

namespace cocoon {

class BaseRunner;

class CocoonWallet : public TonScWrapper {
 public:
  CocoonWallet(td::SecureString wallet_private_key, block::StdAddress wallet_owner, td::int64 low_balance,
               BaseRunner *runner, std::shared_ptr<RunnerConfig> runner_config);

  static td::Ref<vm::Cell> init_data_cell(const block::StdAddress &owner_address, const td::Bits256 &public_key);
  td::Ref<vm::Cell> init_data_cell() override;
  void on_state_update(ton::tl_object_ptr<ton::tonlib_api::raw_fullAccountState> state) override;
  void on_transaction(ton::tl_object_ptr<ton::tonlib_api::raw_transaction> state) override;

  void send_transaction(block::StdAddress destination, td::int64 coins, td::Ref<vm::Cell> payload,
                        td::Promise<td::Unit> promise) {
    return send_transaction(std::move(destination), coins, {}, std::move(payload), std::move(promise));
  }
  void send_transaction(block::StdAddress destination, td::int64 coins, td::Ref<vm::Cell> code,
                        td::Ref<vm::Cell> payload, td::Promise<td::Unit> promise);

  void send_pending_transactions();

  void alarm() override;

  auto min_balance() const {
    return low_balance_;
  }

  void init_pseudo_state() override {
    cocoon_wallet_seqno_ = 7;
  }

  td::int64 coins_reserve() const;

  auto seqno() const {
    return cocoon_wallet_seqno_;
  }
  auto pending_transactions_cnt() const {
    return transactions_.size();
  }
  td::uint32 active_transactions_cnt() const {
    return in_flight_count_;
  }

  static td::Ref<vm::Cell> code_boc();

 private:
  static const std::string &code_str();

  std::unique_ptr<td::Ed25519::PrivateKey> cocoon_wallet_private_key_;
  block::StdAddress cocoon_wallet_owner_address_;
  td::Bits256 cocoon_wallet_public_key_;
  td::uint32 cocoon_wallet_seqno_{0};
  td::int64 low_balance_;

  struct PendingTransaction {
    PendingTransaction(block::StdAddress destination, td::int64 coins, td::Ref<vm::Cell> code,
                       td::Ref<vm::Cell> payload, td::Promise<td::Unit> promise)
        : destination(std::move(destination))
        , coins(coins)
        , code(std::move(code))
        , payload(std::move(payload))
        , promise(std::move(promise)) {
    }
    block::StdAddress destination;
    td::int64 coins;
    td::Ref<vm::Cell> code;
    td::Ref<vm::Cell> payload;
    td::Promise<td::Unit> promise;
  };

  std::list<PendingTransaction> transactions_;

  struct InFlightMessage {
    td::Ref<vm::Cell> body;
    td::int64 valid_until;
  };
  std::list<InFlightMessage> in_flight_;
  td::uint32 in_flight_count_{0};
  td::Timestamp next_resend_;

  void resend_latest_in_flight();
};

}  // namespace cocoon
