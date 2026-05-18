#pragma once

#include "td/actor/PromiseFuture.h"
#include "crypto/block/block.h"
#include "auto/tl/tonlib_api.h"
#include "auto/tl/cocoon_api.h"
#include "td/utils/buffer.h"
#include "tl/TlObject.h"
#include "ton/ton-types.h"
#include "vm/cells/Cell.h"
#include <memory>

namespace cocoon {

struct RunnerConfig;
class BaseRunner;

class TonScWrapper {
 public:
  static ton::BlockIdExt block_id_tl_to_obj(const ton::tonlib_api::ton_blockIdExt &id) {
    ton::BlockIdExt r;
    r.id.workchain = id.workchain_;
    r.id.shard = id.shard_;
    r.id.seqno = id.seqno_;
    r.root_hash.as_slice().copy_from(id.root_hash_);
    r.file_hash.as_slice().copy_from(id.file_hash_);
    return r;
  }
  static ton::BlockIdExt block_id_tl_to_obj(const cocoon_api::ton_blockIdExt &id) {
    ton::BlockIdExt r;
    r.id.workchain = id.workchain_;
    r.id.shard = id.shard_;
    r.id.seqno = id.seqno_;
    r.root_hash.as_slice().copy_from(id.root_hash_.as_slice());
    r.file_hash.as_slice().copy_from(id.file_hash_.as_slice());
    return r;
  }
  static ton::tl_object_ptr<ton::tonlib_api::ton_blockIdExt> block_id_obj_to_tl(const ton::BlockIdExt &id) {
    return ton::create_tl_object<ton::tonlib_api::ton_blockIdExt>(
        id.id.workchain, id.id.shard, id.id.seqno, id.root_hash.as_slice().str(), id.file_hash.as_slice().str());
  }
  static ton::tl_object_ptr<cocoon_api::ton_blockIdExt> block_id_obj_to_cocoon_tl(const ton::BlockIdExt &id) {
    return ton::create_tl_object<cocoon_api::ton_blockIdExt>(id.id.workchain, id.id.shard, id.id.seqno,
                                                             td::BufferSlice(id.root_hash.as_slice()),
                                                             td::BufferSlice(id.file_hash.as_slice()));
  }

  TonScWrapper(block::StdAddress addr, td::Ref<vm::Cell> code, BaseRunner *runner,
               std::shared_ptr<RunnerConfig> runner_config);
  virtual ~TonScWrapper() = default;
  virtual td::int64 deploy_balance() const;
  const auto &address() const {
    return addr_;
  }
  virtual td::Ref<vm::Cell> init_data_cell() = 0;

  void subscribe_to_updates(std::shared_ptr<TonScWrapper> self);
  void unsubscribe_from_updates();
  void request_updates(td::Promise<td::Unit> promise);

  virtual void on_init(ton::tl_object_ptr<ton::tonlib_api::raw_fullAccountState> state) {
    on_state_update(std::move(state));
  }
  virtual void on_state_update(ton::tl_object_ptr<ton::tonlib_api::raw_fullAccountState> state) = 0;
  virtual void on_transaction(ton::tl_object_ptr<ton::tonlib_api::raw_transaction> transaction) = 0;
  virtual void alarm() {
  }

  void set_address(const block::StdAddress &addr) {
    addr_ = addr;
  }

  auto balance() const {
    return balance_;
  }

  const auto &runner_config() const {
    return runner_config_;
  }

  bool is_started() const {
    return started_;
  }

  bool is_inited() const {
    return is_inited_;
  }

  auto code() const {
    return code_;
  }

  void set_code(td::Ref<vm::Cell> code) {
    code_ = code;
  }

  static td::Ref<vm::Cell> generate_sc_init_data(td::Ref<vm::Cell> code, td::Ref<vm::Cell> data) {
    vm::CellBuilder cb;
    cb.store_long(0, 2).store_long(3, 2).store_ref(code).store_ref(data).store_long(0, 1);
    return cb.finalize();
  }

  td::Ref<vm::Cell> generate_sc_init_data() {
    return generate_sc_init_data(code_, init_data_cell());
  }

  static block::StdAddress generate_address(td::Ref<vm::Cell> code, td::Ref<vm::Cell> data, bool is_testnet);
  block::StdAddress generate_address();

  void sc_update_address() {
    addr_ = generate_address();
  }

  void update_state(td::Promise<td::Unit> promise, td::int32 min_ts);
  void deploy(td::Promise<td::Unit> promise);

  void on_state_update() {
    for (auto &p : state_update_promises_) {
      p.set_value(td::Unit());
    }
    state_update_promises_.clear();
  }

  virtual void init_pseudo_state() = 0;

  auto runner() const {
    return runner_;
  }

  void update_runner_config(std::shared_ptr<RunnerConfig> config) {
    runner_config_ = std::move(config);
  }

  static bool sc_is_alive(BaseRunner *runner, td::int64 sc_id);

  auto id() const {
    return id_;
  }

  const auto &state_block_id() const {
    return state_block_id_;
  }

  auto state_sync_utime() const {
    return state_sync_utime_;
  }

  void set_init_block_id(const ton::BlockIdExt &id) {
    init_block_id_ = id;
  }

 private:
  void process_new_state(ton::tl_object_ptr<ton::tonlib_api::raw_fullAccountState> state,
                         td::Promise<td::Unit> promise);
  void process_new_transactions(ton::tl_object_ptr<ton::tonlib_api::raw_transactions> state,
                                td::Promise<td::Unit> promise);
  void request_transactions(td::int64 lt_lt, std::string lt_hash, td::Promise<td::Unit> promise);
  void run_callbacks();

  td::int64 id_;
  block::StdAddress addr_;
  td::Ref<vm::Cell> code_;
  bool started_{false};
  td::int64 lt_lt_{0};
  std::string lt_hash_;
  BaseRunner *runner_;
  std::shared_ptr<RunnerConfig> runner_config_;

  bool subscribed_{false};
  bool is_inited_{false};
  ton::BlockIdExt state_block_id_;
  ton::BlockIdExt init_block_id_;

  td::int64 state_sync_utime_{0};

  std::vector<ton::tl_object_ptr<ton::tonlib_api::raw_transaction>> transactions_;
  ton::tl_object_ptr<ton::tonlib_api::raw_fullAccountState> next_state_;

  td::int64 balance_{-2};

  std::vector<td::Promise<td::Unit>> state_update_promises_;
};

}  // namespace cocoon
