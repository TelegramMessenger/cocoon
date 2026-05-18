#include "CocoonWallet.hpp"
#include "td/utils/Status.h"
#include "vm/boc.h"
#include "vm/cells/Cell.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/db/StaticBagOfCellsDb.h"
#include "runners/BaseRunner.hpp"
#include "cocoon-tl-utils/parsers.hpp"

#include <algorithm>

namespace cocoon {

td::int64 CocoonWallet::coins_reserve() const {
  return to_nano(0.1);
}

const std::string &CocoonWallet::code_str() {
  static const std::string boc_hex =
      "b5ee9c724102110100024b000114ff00f4a413f4bcf2c80b010201200210020148030b0202ca040a020120050701f5d3b68bb7edb088831c"
      "02456f8007434c0c05c6c2456f83e900c0074c7c86084095964d32e88a08431669f34eeac48a084268491f02eac6497c0f83b513434c7f4c"
      "7f4fff4c7fe903454dc31c17cb90409a084271a7cddaea78415d7c1f4cfcc74c1f50c007ec03801b0003cb9044134c1f448301dc8701880b"
      "01d60600ea5312b121b1f2e411018e295f07820898968072fb0280777080185410337003c8cb0558cf1601fa02cb6a12cb1fcb07c98306fb"
      "00e0378e19350271b101c8cb1f12cb1f13cbff12cb1f01cf16c9ed54db31e0058e1d028210fffffffeb001c8cb1f12cb1f13cbff12cb1f01"
      "cf16c9ed54db31e05f05020276080900691cf232c1c044440072c7c7b2c7c732c01402be8094023e8085b2c7c532c7c4b2c7f2c7f2c7f2c7"
      "c07e80807e80bd003d003d00326000553434c1c07000fcb8fc34c7f4c7f4c03e803e8034c7f4c7f4c7f4c7f4c7f4c7fe803e803d013d013d"
      "010c200049a9f21402b3c5940233c585b2fff2413232c05400fe80807e80b2cfc4b2c7c4b2fff33332600201200c0f0201200d0e0017bb39"
      "ced44d0d33f31d70bff80011b8c97ed44d0d70b1f8001bbdfddf6a2684080b06b90fd2018400e0f28308d71820d31fd31fd31f02f823bbf2"
      "d406ed44d0d31fd31fd3ffd31ffa40d12171b0f2d4075154baf2e4085162baf2e40906f901541076f910f2e40af8276f2230821077359400"
      "b9f2d40bf800029320d74a96d307d402fb00e83001a4c8cb1f14cb1f12cbffcb1f01cf16c9ed545d2b2126";
  return boc_hex;
}

CocoonWallet::CocoonWallet(td::SecureString wallet_private_key, block::StdAddress wallet_owner, td::int64 low_balance,
                           BaseRunner *runner, std::shared_ptr<RunnerConfig> runner_config)
    : TonScWrapper(block::StdAddress{}, {}, runner, std::move(runner_config)), low_balance_(low_balance) {
  cocoon_wallet_private_key_ = std::make_unique<td::Ed25519::PrivateKey>(std::move(wallet_private_key));
  auto pub = cocoon_wallet_private_key_->get_public_key().move_as_ok();
  auto pub_key_str = pub.as_octet_string();
  CHECK(pub_key_str.size() == 32);
  cocoon_wallet_public_key_.as_slice().copy_from(pub_key_str.as_slice());
  cocoon_wallet_owner_address_ = wallet_owner;

  set_code(code_boc());
  sc_update_address();
}

td::Ref<vm::Cell> CocoonWallet::code_boc() {
  std::string boc = td::hex_decode(code_str()).move_as_ok();
  return vm::std_boc_deserialize(std::move(boc)).move_as_ok();
}

void CocoonWallet::on_state_update(ton::tl_object_ptr<ton::tonlib_api::raw_fullAccountState> state) {
  if (state->data_.size() == 0) {
    cocoon_wallet_seqno_ = 0;
    return;
  }
  auto R = vm::std_boc_deserialize(state->data_);
  R.ensure();

  vm::CellSlice cs{vm::NoVm{}, R.move_as_ok()};
  auto seqno = (td::uint32)cs.fetch_long(32);
  LOG(DEBUG) << "cocoon wallet: state update: seqno=" << seqno << " balance=" << balance();
  CHECK(cocoon_wallet_seqno_ <= seqno);
  if (cocoon_wallet_seqno_ < seqno) {
    in_flight_.clear();
  }
  cocoon_wallet_seqno_ = seqno;

  if (!transactions_.empty() && in_flight_.empty()) {
    send_pending_transactions();
  }
}

void CocoonWallet::on_transaction(ton::tl_object_ptr<ton::tonlib_api::raw_transaction> tr) {
  auto it = std::find_if(in_flight_.begin(), in_flight_.end(), [&](const InFlightMessage &m) {
    return m.body->get_hash().as_slice() == tr->in_msg_->body_hash_;
  });
  if (it == in_flight_.end()) {
    LOG(WARNING) << "cocoon wallet: received unknown transaction";
    return;
  }

  LOG(INFO) << "cocoon wallet: successfully sent " << in_flight_count_ << " messages";

  CHECK(in_flight_count_ <= transactions_.size());
  auto tx_it = transactions_.begin();
  for (td::uint32 i = 0; i < in_flight_count_; i++) {
    tx_it->promise.set_value(td::Unit());
    tx_it++;
  }
  transactions_.erase(transactions_.begin(), tx_it);
  in_flight_.clear();
  in_flight_count_ = 0;
}

void CocoonWallet::send_transaction(block::StdAddress destination, td::int64 coins, td::Ref<vm::Cell> code,
                                    td::Ref<vm::Cell> payload, td::Promise<td::Unit> promise) {
  LOG(DEBUG) << "cocoon wallet: queueing a transaction";
  transactions_.emplace_back(std::move(destination), coins, std::move(code), std::move(payload), std::move(promise));

  if (in_flight_.empty()) {
    send_pending_transactions();
  }
}

void CocoonWallet::send_pending_transactions() {
  if (balance() < low_balance_) {
    LOG(WARNING) << "ACTION REQUIRED: BALANCE ON CONTRACT " << address().rserialize(true) << " IS TOO LOW: MINIMUM "
                 << low_balance_ << " CURRENT " << balance();
    return;
  }
  if (transactions_.empty()) {
    return;
  }

  const bool rebuilding = in_flight_count_ > 0;
  if (rebuilding) {
    CHECK(in_flight_count_ <= transactions_.size());
  }

  const td::int64 ttl = (td::int64)time(0) + 3600;
  vm::CellBuilder cb0;
  // subwallet, valid_until, seqno
  cb0.store_long(0, 32).store_long(ttl, 32).store_long(cocoon_wallet_seqno_, 32);

  td::int64 total_balance = 0;
  td::uint32 total = 0;
  const td::int64 coins_limit = std::min(to_nano(1000), balance());

  for (auto &tr : transactions_) {
    if (rebuilding ? total == in_flight_count_ : total == 4) {
      break;
    }
    if (!rebuilding && total_balance + tr.coins + coins_reserve() > coins_limit) {
      if (total == 0) {
        LOG(WARNING) << "ACTION REQUIRED: BALANCE ON CONTRACT " << address().rserialize(true)
                     << " IS TOO LOW: SENDING MESSAGE OF VALUE " << tr.coins << " CURRENT " << balance();
        return;
      } else {
        break;
      }
    }

    if (tr.coins > 1) {
      cb0.store_long(0, 8);
    } else {
      cb0.store_long(1, 8);  // pay fees separatly
    }

    vm::CellBuilder cb;
    if (tr.code.is_null()) {
      cb.store_long(0x18, 6);  // magic, DISABLE_IHT, BOUNCABLE, bounced, no src address
    } else {
      cb.store_long(0x10, 6);  // magic, DISABLE_IHT, bouncable, bounced, no src address
    }
    store_address(cb, tr.destination);     // destination
    store_coins(cb, tr.coins);             // 0
    cb.store_zeroes(1 + 4 + 4 + 64 + 32);  // empty value, no ihr fee, no fwd fee, empty LT, empty created at
    if (tr.code.is_null()) {
      cb.store_bool_bool(false);
    } else {
      cb.store_bool_bool(true);
      cb.store_bool_bool(true);  // as ref
      cb.store_ref(tr.code);
    }
    if (tr.payload.not_null()) {
      cb.store_bool_bool(true);  // data as ref
      cb.store_ref(tr.payload);  // ref
    } else {
      cb.store_bool_bool(false);  // (empty) data inlined
    }
    cb0.store_ref(cb.finalize());

    total_balance += tr.coins;
    total++;
  }

  auto msg = BaseRunner::sign_message(*cocoon_wallet_private_key_, cb0.finalize());
  in_flight_.push_back({msg, ttl});
  if (!rebuilding) {
    in_flight_count_ = total;
  }

  td::Ref<vm::Cell> code;
  if (cocoon_wallet_seqno_ == 0) {
    code = generate_sc_init_data();
  }
  next_resend_ = td::Timestamp::in(30);

  runner()->send_external_message(address(), code, msg, [](td::Result<td::Unit> R) {
    if (R.is_error()) {
      LOG(ERROR) << "cocoon wallet: failed to send external message: " << R.move_as_error();
    }
  });
}

void CocoonWallet::resend_latest_in_flight() {
  td::Ref<vm::Cell> code;
  if (cocoon_wallet_seqno_ == 0) {
    code = generate_sc_init_data();
  }
  next_resend_ = td::Timestamp::in(30);
  LOG(INFO) << "cocoon wallet: resending last transaction because of the timeout";
  runner()->send_external_message(address(), code, in_flight_.back().body, [](td::Result<td::Unit> R) {
    if (R.is_error()) {
      LOG(ERROR) << "cocoon wallet: failed to send external message: " << R.move_as_error();
    }
  });
}

void CocoonWallet::alarm() {
  if (runner_config()->ton_disabled) {
    return;
  }

  if (in_flight_.empty() || in_flight_.back().valid_until < time(0)) {
    if (!transactions_.empty()) {
      send_pending_transactions();
    }
    return;
  }

  if (next_resend_.is_in_past()) {
    resend_latest_in_flight();
  }
}

td::Ref<vm::Cell> CocoonWallet::init_data_cell(const block::StdAddress &owner_address, const td::Bits256 &public_key) {
  vm::CellBuilder cb;
  cb.store_long(0, 32).store_long(0, 32).store_bytes(public_key.as_slice()).store_long(0, 32);
  store_address(cb, owner_address);

  return cb.finalize();
}

td::Ref<vm::Cell> CocoonWallet::init_data_cell() {
  return init_data_cell(cocoon_wallet_owner_address_, cocoon_wallet_public_key_);
}

}  // namespace cocoon
