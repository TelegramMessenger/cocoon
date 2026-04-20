#include "RootContractConfig.hpp"
#include "SmartContract.hpp"
#include "runners/BaseRunner.hpp"
#include "auto/tl/cocoon_api.hpp"
#include "checksum.h"
#include "common/bitstring.h"
#include "td/utils/Slice-decl.h"
#include "td/utils/Status.h"
#include "td/utils/UInt.h"
#include "td/utils/common.h"
#include "td/utils/misc.h"
#include "td/utils/overloaded.h"
#include "td/utils/port/IPAddress.h"
#include "td/utils/filesystem.h"
#include "tl/TlObject.h"
#include "tl/tl_json.h"
#include "auto/tl/cocoon_api.h"
#include "auto/tl/cocoon_api_json.h"
#include "crypto/vm/dict.h"
#include "vm/boc.h"
#include "vm/cells/CellSlice.h"
#include <algorithm>
#include <iostream>
#include <memory>
#include <vector>
#include "cocoon-tl-utils/parsers.hpp"
#include "runners/helpers/Ton.h"

namespace cocoon {

static bool fetch_net_addr(vm::CellSlice &cs, std::string &r) {
  bool v;
  if (!cs.fetch_bool_to(v) || v) {
    return false;
  }
  td::uint32 bytes;
  if (!cs.fetch_uint_to(7, bytes)) {
    return false;
  }

  auto old_r = std::move(r);
  r.resize(bytes);
  if (!cs.fetch_bytes(td::MutableSlice(r))) {
    r = std::move(old_r);
    return false;
  }

  return true;
}

static bool parse_address(td::Slice host_port, td::IPAddress &dst) {
  if (host_port.size() == 0) {
    LOG(ERROR) << "failed to parse '" << host_port << "' as address";
    return false;
  }

  if (host_port[0] == '[' && host_port.back() == ']') {
    host_port.remove_prefix(1);
    host_port.remove_suffix(1);
  }

  auto x = host_port.find(':');
  if (x == td::Slice::npos) {
    LOG(ERROR) << "failed to parse '" << host_port << "' as address";
    return false;
  }

  auto R = td::to_integer_safe<td::uint16>(host_port.copy().remove_prefix(x + 1));
  if (R.is_error()) {
    LOG(ERROR) << "failed to parse '" << host_port << "' as address: bad port: " << R.move_as_error();
    return false;
  }

  auto port = R.move_as_ok();

  auto R2 = dst.init_ipv4_port(host_port.copy().truncate(x).str(), port);
  if (R2.is_error()) {
    LOG(ERROR) << "failed to parse '" << host_port << "' as address: bad ip: " << R2.move_as_error();
    return false;
  }

  return true;
}

td::Result<std::unique_ptr<RootContractConfig>> RootContractConfig::load_from_state(vm::CellSlice &cell_slice,
                                                                                    bool is_testnet) {
  std::unique_ptr<RootContractConfig> config = std::make_unique<RootContractConfig>();
  try {
    block::StdAddress owner_address;
    if (!fetch_address(cell_slice, owner_address, is_testnet, false)) {
      return td::Status::Error("cannot fetch root contract owner");
    }

    bool exist_bit;

    auto data_cell = cell_slice.fetch_ref();

    /*
     * Parsing params_cell first to get struct_version. Because of the history-related reasons
     * we use struct_version as the struct version of the whole smartcontract data format
     */
    auto params_cell = cell_slice.fetch_ref();
    vm::CellSlice params_cs{vm::NoVm{}, params_cell};

    td::uint32 struct_version;
    if (!params_cs.fetch_uint_to(8, struct_version)) {
      return td::Status::Error("cannot fetch struct_version");
    }

    if (struct_version > 5) {
      return td::Status::Error(PSTRING() << "unexpected params struct version: " << struct_version);
    }

    td::uint32 params_version;
    if (!params_cs.fetch_uint_to(32, params_version)) {
      return td::Status::Error("cannot fetch params_version");
    }

    td::uint32 unique_id;
    if (!params_cs.fetch_uint_to(32, unique_id)) {
      return td::Status::Error("cannot fetch unique_id");
    }

    bool is_test;
    if (!params_cs.fetch_bool_to(is_test)) {
      return td::Status::Error("cannot fetch is_test");
    }

    td::uint64 price_per_token;
    if (!fetch_coins(params_cs, price_per_token)) {
      return td::Status::Error("cannot fetch price per token");
    }

    td::uint64 worker_fee_per_token;
    if (!fetch_coins(params_cs, worker_fee_per_token)) {
      return td::Status::Error("cannot fetch worker fee per token");
    }

    td::int32 prompt_tokens_price_multiplier = 10000;
    if (struct_version >= 3) {
      if (!params_cs.fetch_uint_to(32, prompt_tokens_price_multiplier)) {
        return td::Status::Error("cannot fetch prompt tokens price multiplier");
      }
    }
    td::int32 cached_tokens_price_multiplier = 10000;
    if (struct_version >= 2) {
      if (!params_cs.fetch_uint_to(32, cached_tokens_price_multiplier)) {
        return td::Status::Error("cannot fetch cached tokens price multiplier");
      }
    }
    td::int32 completion_tokens_price_multiplier = 10000;
    if (struct_version >= 3) {
      if (!params_cs.fetch_uint_to(32, completion_tokens_price_multiplier)) {
        return td::Status::Error("cannot fetch completion tokens price multiplier");
      }
    }
    td::int32 reasoning_tokens_price_multiplier = 10000;
    if (struct_version >= 2) {
      if (!params_cs.fetch_uint_to(32, reasoning_tokens_price_multiplier)) {
        return td::Status::Error("cannot fetch reasoning tokens price multiplier");
      }
    }

    td::uint32 proxy_delay_before_close;
    if (!params_cs.fetch_uint_to(32, proxy_delay_before_close)) {
      return td::Status::Error("cannot fetch proxy delay before close");
    }

    td::uint32 client_delay_before_close;
    if (!params_cs.fetch_uint_to(32, client_delay_before_close)) {
      return td::Status::Error("cannot fetch client delay before close");
    }

    td::uint64 min_proxy_stake = to_nano(1.0);
    if (struct_version >= 1) {
      if (!fetch_coins(params_cs, min_proxy_stake)) {
        return td::Status::Error("cannot fetch min proxy stake");
      }
    }

    td::uint64 min_client_stake = to_nano(1.0);
    if (struct_version >= 1) {
      if (!fetch_coins(params_cs, min_client_stake)) {
        return td::Status::Error("cannot fetch min client stake");
      }
    }

    if (!params_cs.fetch_bool_to(exist_bit)) {
      return td::Status::Error("failed to get dict exist bit");
    }
    if (exist_bit) {
      config->proxy_sc_code_ = params_cs.fetch_ref();
    }

    if (!params_cs.fetch_bool_to(exist_bit)) {
      return td::Status::Error("failed to get dict exist bit");
    }
    if (exist_bit) {
      config->worker_sc_code_ = params_cs.fetch_ref();
    }

    if (!params_cs.fetch_bool_to(exist_bit)) {
      return td::Status::Error("failed to get dict exist bit");
    }
    if (exist_bit) {
      config->client_sc_code_ = params_cs.fetch_ref();
    }

    if (!params_cs.empty_ext()) {
      return td::Status::Error("extra data in params in root contract");
    }

    vm::CellSlice data{vm::NoVm{}, data_cell};

    if (!data.fetch_bool_to(exist_bit)) {
      return td::Status::Error("failed to get dict exist bit");
    }

    if (exist_bit) {
      vm::Dictionary accepted_proxy_hashes_dict(data.fetch_ref(), 256);
      if (!accepted_proxy_hashes_dict.check_for_each(
              [&](td::Ref<vm::CellSlice> value, td::ConstBitPtr key, int key_len) {
                CHECK(key_len == 256);
                td::Bits256 x(key);
                config->accepted_proxy_hashes_.push_back(x);
                return true;
              })) {
        return td::Status::Error("failed to iterate accepted proxy hashes");
      }
      std::sort(config->accepted_proxy_hashes_.begin(),
                config->accepted_proxy_hashes_.end());  // should be sorted, but...
    }

    if (!data.fetch_bool_to(exist_bit)) {
      return td::Status::Error("failed to get dict exist bit");
    }
    if (exist_bit) {
      vm::Dictionary proxies_dict(data.fetch_ref(), 32);
      if (!proxies_dict.check_for_each([&](td::Ref<vm::CellSlice> value, td::ConstBitPtr key, int key_len) {
            std::string buf;
            if (!fetch_net_addr(value.write(), buf)) {
              LOG(ERROR) << "cannot parse addr";
              return true;  // only support ipv4 for now
            }

            ProxyInfo w;
            w.seqno = (td::uint32)key.get_uint(32);

            auto addr = td::Slice(buf);
            auto x = addr.find(' ');
            if (x == td::Slice::npos) {
              if (!parse_address(addr, w.address_for_workers)) {
                return true;
              }
              w.address_for_clients = w.address_for_workers;
            } else {
              if (!parse_address(addr.copy().truncate(x), w.address_for_workers)) {
                return true;
              }
              if (!parse_address(addr.copy().remove_prefix(x + 1), w.address_for_clients)) {
                return true;
              }
            }

            LOG(DEBUG) << "adding proxy at addresses " << w.address_for_workers << " and " << w.address_for_clients;
            config->proxies_.push_back(std::move(w));
            return true;
          })) {
        return td::Status::Error("failed to iterate proxies list");
      }
    }

    td::uint32 last_proxy_seqno;
    if (!data.fetch_uint_to(32, last_proxy_seqno)) {
      return td::Status::Error("cannot fetch last proxy seqno");
    }

    if (!data.fetch_bool_to(exist_bit)) {
      return td::Status::Error("failed to get dict exist bit");
    }
    if (exist_bit) {
      vm::Dictionary worker_hashes_dict(data.fetch_ref(), 256);
      if (!worker_hashes_dict.check_for_each([&](td::Ref<vm::CellSlice> value, td::ConstBitPtr key, int key_len) {
            CHECK(key_len == 256);
            td::Bits256 worker_hash(key);
            config->workers_.emplace_back(worker_hash);
            return true;
          })) {
        return td::Status::Error("failed to iterate worker types");
      }
      std::sort(config->workers_.begin(), config->workers_.end());
    }

    if (!data.fetch_bool_to(exist_bit)) {
      return td::Status::Error("failed to get dict exist bit");
    }
    if (exist_bit) {
      vm::Dictionary model_hashes_dict(data.fetch_ref(), 256);
      if (!model_hashes_dict.check_for_each([&](td::Ref<vm::CellSlice> value, td::ConstBitPtr key, int key_len) {
            CHECK(key_len == 256);
            td::Bits256 model_hash(key);
            config->models_.emplace_back(model_hash);
            return true;
          })) {
        return td::Status::Error("failed to iterate worker types");
      }
      std::sort(config->models_.begin(), config->models_.end());
    }

    if (!data.empty_ext()) {
      return td::Status::Error("extra data in data cell in root contract");
    }

    td::uint32 version;
    if (!cell_slice.fetch_uint_to(32, version)) {
      return td::Status::Error("cannot fetch version");
    }

    std::map<td::Bits256, RootContractPublicKeyInfo> public_keys;
    td::Bits256 key_manager_public_key = td::Bits256::zero();
    td::Bits256 key_manager_image_hash = td::Bits256::zero();
    std::string key_manager_addr_str = "";
    td::IPAddress key_manager_addr;
    if (struct_version >= 4) {
      auto key_manager_cell = cell_slice.fetch_ref();
      vm::CellSlice km_cs{vm::NoVm{}, key_manager_cell};
      if (!km_cs.fetch_bool_to(exist_bit)) {
        return td::Status::Error("failed to get dict exist bit");
      }
      if (exist_bit) {
        vm::Dictionary public_keys_dict(km_cs.fetch_ref(), 256);
        if (!public_keys_dict.check_for_each([&](td::Ref<vm::CellSlice> value, td::ConstBitPtr key, int key_len) {
              CHECK(key_len == 256);
              td::Bits256 public_key(key);
              RootContractPublicKeyInfo v;
              td::uint32 key_type;
              if (!value.write().fetch_uint_to(8, key_type)) {
                return false;
              }
              v.key_type = (td::uint8)key_type;
              if (!value.write().fetch_uint_to(32, v.expire_at)) {
                return false;
              }
              if (!value.write().empty_ext()) {
                return false;
              }
              CHECK(public_keys.emplace(public_key, std::move(v)).second);
              return true;
            })) {
          return td::Status::Error("failed to iterate public keys dict");
        }
      }
      if (!km_cs.fetch_bytes(key_manager_public_key.as_slice())) {
        return td::Status::Error("failed to get key manager public key");
      }
      if (!km_cs.fetch_bytes(key_manager_image_hash.as_slice())) {
        return td::Status::Error("failed to get key manager image hash");
      }
      if (!fetch_net_addr(km_cs, key_manager_addr_str)) {
        return td::Status::Error("failed to get key manager addr");
      }
      if (key_manager_addr_str.size() == 0) {
        key_manager_addr = td::IPAddress();
      } else {
        if (!parse_address(key_manager_addr_str, key_manager_addr)) {
          return td::Status::Error(PSTRING() << "failed to parse '" << key_manager_addr_str << " as IP address");
        }
      }
      if (!km_cs.empty_ext()) {
        return td::Status::Error("extra data in key manager data");
      }
    }

    std::vector<td::Bits256> verified_proxy_keys;
    std::vector<td::Bits256> verified_worker_keys;
    std::vector<td::Bits256> verified_key_manager_keys;

    if (struct_version >= 5) {
      auto verified_keys_cell = cell_slice.fetch_ref();
      vm::CellSlice cs{vm::NoVm{}, verified_keys_cell};
      if (!cs.fetch_bool_to(exist_bit)) {
        return td::Status::Error("failed to get dict exist bit");
      }
      if (exist_bit) {
        vm::Dictionary dict(cs.fetch_ref(), 256);
        if (!dict.check_for_each([&](td::Ref<vm::CellSlice> value, td::ConstBitPtr key, int key_len) {
              CHECK(key_len == 256);
              td::Bits256 public_key(key);
              verified_proxy_keys.push_back(public_key);
              return true;
            })) {
          return td::Status::Error("failed to iterate proxy verified keys dict");
        }
        std::sort(verified_proxy_keys.begin(), verified_proxy_keys.end());
      }
      if (!cs.fetch_bool_to(exist_bit)) {
        return td::Status::Error("failed to get dict exist bit");
      }
      if (exist_bit) {
        vm::Dictionary dict(cs.fetch_ref(), 256);
        if (!dict.check_for_each([&](td::Ref<vm::CellSlice> value, td::ConstBitPtr key, int key_len) {
              CHECK(key_len == 256);
              td::Bits256 public_key(key);
              verified_worker_keys.push_back(public_key);
              return true;
            })) {
          return td::Status::Error("failed to iterate worker verified keys dict");
        }
        std::sort(verified_worker_keys.begin(), verified_worker_keys.end());
      }
      if (!cs.fetch_bool_to(exist_bit)) {
        return td::Status::Error("failed to get dict exist bit");
      }
      if (exist_bit) {
        vm::Dictionary dict(cs.fetch_ref(), 256);
        if (!dict.check_for_each([&](td::Ref<vm::CellSlice> value, td::ConstBitPtr key, int key_len) {
              CHECK(key_len == 256);
              td::Bits256 public_key(key);
              verified_key_manager_keys.push_back(public_key);
              return true;
            })) {
          return td::Status::Error("failed to iterate key manager verified keys dict");
        }
        std::sort(verified_key_manager_keys.begin(), verified_key_manager_keys.end());
      }
      if (!cs.empty_ext()) {
        return td::Status::Error("extra data in verified keys cell");
      }
    }

    if (!cell_slice.empty_ext()) {
      return td::Status::Error("extra data in root contract");
    }

    LOG(INFO) << "parse root contract state: owner=" << owner_address.rserialize(true) << " unique_id=" << unique_id
              << " is_test=" << (is_test ? "YES" : "NO")
              << " proxy_hashes_size=" << config->accepted_proxy_hashes_.size()
              << " registered_proxies_count=" << config->proxies_.size() << " last_proxy_seqno=" << last_proxy_seqno
              << " workers_hashes_count=" << config->workers_.size() << " price_per_token=" << price_per_token
              << " worker_fee_per_token=" << worker_fee_per_token << " version=" << version << " " << params_version
              << " min_proxy_stake=" << min_proxy_stake << " min_client_stake=" << min_client_stake
              << " prompt_tokens_price_multiplier=" << prompt_tokens_price_multiplier
              << " cached_tokens_price_multiplier=" << cached_tokens_price_multiplier
              << " completion_tokens_price_multiplier=" << completion_tokens_price_multiplier
              << " reasoning_tokens_price_multiplier=" << reasoning_tokens_price_multiplier;

    config->owner_ = owner_address;
    //config->accepted_proxy_hashes_;
    //config->proxies_;
    config->last_proxy_seqno_ = last_proxy_seqno;
    //config->workers_
    config->version_ = version;

    config->struct_version_ = (td::uint8)struct_version;
    config->params_version_ = params_version;
    config->unique_id_ = unique_id;
    config->is_test_ = is_test;
    config->price_per_token_ = price_per_token;
    config->worker_fee_per_token_ = worker_fee_per_token;
    config->prompt_tokens_price_multiplier_ = prompt_tokens_price_multiplier;
    config->cached_tokens_price_multiplier_ = cached_tokens_price_multiplier;
    config->completion_tokens_price_multiplier_ = completion_tokens_price_multiplier;
    config->reasoning_tokens_price_multiplier_ = reasoning_tokens_price_multiplier;
    config->proxy_delay_before_close_ = proxy_delay_before_close;
    config->client_delay_before_close_ = client_delay_before_close;
    config->min_proxy_stake_ = min_proxy_stake;
    config->min_client_stake_ = min_client_stake;
    config->public_keys_ = std::move(public_keys);
    config->key_manager_public_key_ = key_manager_public_key;
    config->key_manager_image_hash_ = key_manager_image_hash;
    config->key_manager_addr_ = key_manager_addr;
    config->verified_proxy_keys_ = std::move(verified_proxy_keys);
    config->verified_worker_keys_ = std::move(verified_worker_keys);
    config->verified_key_manager_keys_ = std::move(verified_key_manager_keys);
    //config->proxy_contract_info_;
    //config->worker_contract_info_;
    //config->client_contract_info_;

  } catch (...) {
    return td::Status::Error("failed to parse");
  }

  return config;
}

td::Result<std::unique_ptr<RootContractConfig>> RootContractConfig::load_from_tl(
    const cocoon_api::rootConfig_pseudo &conf, bool is_testnet) {
  std::unique_ptr<RootContractConfig> config = std::make_unique<RootContractConfig>();
  for (auto &h : conf.proxy_hashes_) {
    config->accepted_proxy_hashes_.push_back(h);
  }
  std::sort(config->accepted_proxy_hashes_.begin(),
            config->accepted_proxy_hashes_.end());  // should be sorted, but...

  for (auto &w : conf.worker_hashes_) {
    config->workers_.emplace_back(w);
  }
  std::sort(config->workers_.begin(), config->workers_.end());

  for (auto &w : conf.model_hashes_) {
    config->models_.emplace_back(w);
  }
  for (auto &w : conf.model_types_) {
    auto v = td::Slice(w);
    auto p = v.find('@');
    if (p != td::Slice::npos) {
      v.truncate(p);
    }
    config->models_.emplace_back(td::sha256_bits256(v));
  }
  std::sort(config->models_.begin(), config->models_.end());

  for (auto &p : conf.registered_proxies_) {
    ProxyInfo w;
    w.seqno = (td::uint32)p->seqno_;
    auto addr = td::Slice(p->address_);
    auto x = addr.find(' ');
    if (x == td::Slice::npos) {
      if (!parse_address(addr, w.address_for_workers)) {
        return td::Status::Error("cannot parse address");
      }
      w.address_for_clients = w.address_for_workers;
    } else {
      if (!parse_address(addr.copy().truncate(x), w.address_for_workers)) {
        return td::Status::Error("cannot parse address");
      }
      if (!parse_address(addr.copy().remove_prefix(x + 1), w.address_for_clients)) {
        return td::Status::Error("cannot parse address");
      }
    }
    config->proxies_.push_back(std::move(w));
  }

  auto deserialize_boc = [](td::Slice data) -> td::Result<td::Ref<vm::Cell>> {
    if (data.size() == 0) {
      return vm::CellBuilder().finalize_novm();
    }
    TRY_RESULT(s, td::hex_decode(data));
    return vm::std_boc_deserialize(s);
  };

  TRY_RESULT_ASSIGN(config->proxy_sc_code_, deserialize_boc(conf.proxy_sc_code_));
  TRY_RESULT_ASSIGN(config->worker_sc_code_, deserialize_boc(conf.worker_sc_code_));
  TRY_RESULT_ASSIGN(config->client_sc_code_, deserialize_boc(conf.client_sc_code_));
  config->last_proxy_seqno_ = conf.last_proxy_seqno_;
  config->version_ = conf.version_;

  config->struct_version_ = 1;
  config->params_version_ = conf.params_version_;
  config->unique_id_ = 13;
  config->is_test_ = true;
  config->price_per_token_ = conf.price_per_token_;
  config->worker_fee_per_token_ = conf.worker_fee_per_token_;
  config->proxy_delay_before_close_ = 600;
  config->client_delay_before_close_ = 300;
  config->min_proxy_stake_ = to_nano(1);
  config->min_client_stake_ = to_nano(1);
  for (auto &p : conf.registered_public_keys_) {
    struct RootContractPublicKeyInfo info;
    info.expire_at = p->expire_at_;
    info.key_type = (td::uint8)p->key_type_;
    config->public_keys_.emplace(p->public_key_, std::move(info));
  }
  if (conf.key_manager_address_.size() == 0) {
    config->key_manager_addr_ = td::IPAddress();
  } else {
    if (!parse_address(conf.key_manager_address_, config->key_manager_addr_)) {
      return td::Status::Error("cannot deserialize key manager address");
    }
  }
  if (!rdeserialize(config->owner_, conf.root_owner_address_, is_testnet)) {
    return td::Status::Error("cannot deserialize root owner address");
  }

  return config;
}

td::Result<std::unique_ptr<RootContractConfig>> RootContractConfig::load_from_tl(
    const cocoon_api::rootConfig_configV7 &conf, bool is_testnet) {
  std::unique_ptr<RootContractConfig> config = std::make_unique<RootContractConfig>();

  if (!rdeserialize(config->owner_, conf.root_owner_address_, is_testnet)) {
    return td::Status::Error("cannot deserialize root owner address");
  }

  for (auto &h : conf.proxy_hashes_) {
    config->accepted_proxy_hashes_.push_back(h);
  }
  std::sort(config->accepted_proxy_hashes_.begin(),
            config->accepted_proxy_hashes_.end());  // should be sorted, but...

  for (auto &p : conf.registered_proxies_) {
    ProxyInfo w;
    w.seqno = (td::uint32)p->seqno_;
    auto addr = td::Slice(p->address_);
    auto x = addr.find(' ');
    if (x == td::Slice::npos) {
      if (!parse_address(addr, w.address_for_workers)) {
        return td::Status::Error("cannot parse address");
      }
      w.address_for_clients = w.address_for_workers;
    } else {
      if (!parse_address(addr.copy().truncate(x), w.address_for_workers)) {
        return td::Status::Error("cannot parse address");
      }
      if (!parse_address(addr.copy().remove_prefix(x + 1), w.address_for_clients)) {
        return td::Status::Error("cannot parse address");
      }
    }
    config->proxies_.push_back(std::move(w));
  }

  config->last_proxy_seqno_ = conf.last_proxy_seqno_;

  for (auto &w : conf.worker_hashes_) {
    config->workers_.emplace_back(w);
  }
  std::sort(config->workers_.begin(), config->workers_.end());

  for (auto &w : conf.model_hashes_) {
    config->models_.emplace_back(w);
  }
  std::sort(config->models_.begin(), config->models_.end());

  config->version_ = conf.version_;

  config->struct_version_ = (td::uint8)conf.struct_version_;
  config->params_version_ = conf.params_version_;
  config->unique_id_ = conf.unique_id_;
  config->is_test_ = (bool)conf.is_test_;
  config->price_per_token_ = conf.price_per_token_;
  config->worker_fee_per_token_ = conf.worker_fee_per_token_;
  config->prompt_tokens_price_multiplier_ = conf.prompt_tokens_price_multiplier_;
  config->cached_tokens_price_multiplier_ = conf.cached_tokens_price_multiplier_;
  config->completion_tokens_price_multiplier_ = conf.completion_tokens_price_multiplier_;
  config->reasoning_tokens_price_multiplier_ = conf.reasoning_tokens_price_multiplier_;
  config->proxy_delay_before_close_ = conf.proxy_delay_before_close_;
  config->client_delay_before_close_ = conf.client_delay_before_close_;
  config->min_proxy_stake_ = conf.min_proxy_stake_;
  config->min_client_stake_ = conf.min_client_stake_;
  for (auto &p : conf.registered_public_keys_) {
    struct RootContractPublicKeyInfo info;
    info.expire_at = p->expire_at_;
    info.key_type = (td::uint8)p->key_type_;
    config->public_keys_.emplace(p->public_key_, std::move(info));
  }
  config->key_manager_public_key_ = conf.key_manager_public_key_;
  config->key_manager_image_hash_ = conf.key_manager_image_hash_;
  if (conf.key_manager_address_.size() == 0) {
    config->key_manager_addr_ = td::IPAddress();
  } else {
    if (!parse_address(conf.key_manager_address_, config->key_manager_addr_)) {
      return td::Status::Error("cannot deserialize key manager address");
    }
  }

  config->verified_proxy_keys_ = conf.verified_proxy_keys_;
  config->verified_worker_keys_ = conf.verified_worker_keys_;
  config->verified_key_manager_keys_ = conf.verified_proxy_keys_;

  auto deserialize_boc = [](td::Slice data) -> td::Result<td::Ref<vm::Cell>> {
    if (data.size() == 0) {
      return vm::CellBuilder().finalize_novm();
    }
    TRY_RESULT(s, td::hex_decode(data));
    return vm::std_boc_deserialize(s);
  };

  TRY_RESULT_ASSIGN(config->proxy_sc_code_, deserialize_boc(conf.proxy_sc_code_));
  TRY_RESULT_ASSIGN(config->worker_sc_code_, deserialize_boc(conf.worker_sc_code_));
  TRY_RESULT_ASSIGN(config->client_sc_code_, deserialize_boc(conf.client_sc_code_));

  return config;
}

td::Result<std::unique_ptr<RootContractConfig>> RootContractConfig::load_from_tl(
    const cocoon_api::rootConfig_Config &tl_config, bool is_testnet) {
  td::Result<std::unique_ptr<RootContractConfig>> R;
  cocoon_api::downcast_call(const_cast<cocoon_api::rootConfig_Config &>(tl_config),
                            [&](const auto &obj) { R = load_from_tl(obj, is_testnet); });
  return R;
}

td::Result<std::unique_ptr<RootContractConfig>> RootContractConfig::load_from_json(td::CSlice file_name,
                                                                                   bool is_testnet) {
  TRY_RESULT_PREFIX(conf_data, td::read_file(file_name), "failed to read: ");
  TRY_RESULT_PREFIX(conf_json, td::json_decode(conf_data.as_slice()), "failed to parse json: ");

  cocoon::cocoon_api::rootConfig_pseudo conf;
  TRY_STATUS_PREFIX(cocoon::cocoon_api::from_json(conf, conf_json.get_object()), "json does not fit TL scheme: ");

  return load_from_tl(conf, is_testnet);
}

ton::tl_object_ptr<cocoon_api::rootConfig_Config> RootContractConfig::serialize() const {
  auto accepted_proxy_hashes = accepted_proxy_hashes_;

  std::vector<ton::tl_object_ptr<cocoon_api::rootConfig_registeredProxy>> proxies;
  for (auto &p : proxies_) {
    //rootConfig.registeredProxy seqno : int address : string proxy_hash : int256 = rootConfig.RegisteredProxy;
    proxies.push_back(cocoon::create_tl_object<cocoon_api::rootConfig_registeredProxy>(
        p.seqno, PSTRING() << p.address_for_workers << " " << p.address_for_clients));
  }

  auto workers = workers_;
  auto models = models_;

  std::vector<ton::tl_object_ptr<cocoon_api::rootConfig_registeredPublicKey>> pub_keys;
  for (auto &k : public_keys_) {
    pub_keys.push_back(ton::create_tl_object<cocoon_api::rootConfig_registeredPublicKey>(k.first, k.second.key_type,
                                                                                         k.second.expire_at));
  }

  auto verified_proxy_keys = verified_proxy_keys_;
  auto verified_worker_keys = verified_worker_keys_;
  auto verified_key_manager_keys = verified_key_manager_keys_;

  std::string key_manager_addr_str = key_manager_addr_.is_valid() ? (PSTRING() << key_manager_addr_) : "";

  return cocoon::create_tl_object<cocoon_api::rootConfig_configV7>(
      owner_.rserialize(true), std::move(accepted_proxy_hashes), std::move(proxies), last_proxy_seqno_,
      std::move(workers), std::move(models), version_, struct_version_, params_version_, unique_id_, is_test_ ? 1 : 0,
      (int)price_per_token_, (int)worker_fee_per_token_, prompt_tokens_price_multiplier_,
      cached_tokens_price_multiplier_, completion_tokens_price_multiplier_, reasoning_tokens_price_multiplier_,
      proxy_delay_before_close_, client_delay_before_close_, min_proxy_stake_, min_client_stake_, std::move(pub_keys),
      key_manager_public_key_, key_manager_image_hash_, std::move(key_manager_addr_str), std::move(verified_proxy_keys),
      std::move(verified_worker_keys), std::move(verified_key_manager_keys),
      td::hex_encode(vm::std_boc_serialize(proxy_sc_code_).move_as_ok().as_slice()),
      td::hex_encode(vm::std_boc_serialize(worker_sc_code_).move_as_ok().as_slice()),
      td::hex_encode(vm::std_boc_serialize(client_sc_code_).move_as_ok().as_slice()));
}

td::Ref<vm::Cell> RootContractConfig::serialize_params_cell(td::int32 value) {
  LOG(DEBUG) << "params_version=" << params_version_ << " unique_id=" << unique_id_
             << " is_test=" << (is_test_ ? "YES" : "NO") << " price_per_token=" << price_per_token_
             << " worker_fee_per_token=" << worker_fee_per_token_
             << " proxy_delay_before_close=" << proxy_delay_before_close_
             << " client_delay_before_close=" << client_delay_before_close_
             << " proxy_sc_code=" << ((value & 1) ? proxy_sc_code_->get_hash().to_hex() : "<NONE>")
             << " worker_sc_code=" << ((value & 2) ? worker_sc_code_->get_hash().to_hex() : "<NONE>")
             << " client_sc_code=" << ((value & 4) ? client_sc_code_->get_hash().to_hex() : "<NONE>");

  vm::CellBuilder cb;
  cb.store_long(struct_version_, 8).store_long(params_version_, 32).store_long(unique_id_, 32);
  cb.store_bool_bool(is_test_);
  store_coins(cb, price_per_token_);
  store_coins(cb, worker_fee_per_token_);
  if (struct_version_ >= 2) {
    if (struct_version_ >= 3) {
      cb.store_long(prompt_tokens_price_multiplier_, 32);
    }
    cb.store_long(cached_tokens_price_multiplier_, 32);
    if (struct_version_ >= 3) {
      cb.store_long(completion_tokens_price_multiplier_, 32);
    }
    cb.store_long(reasoning_tokens_price_multiplier_, 32);
  }
  cb.store_long(proxy_delay_before_close_, 32);
  cb.store_long(client_delay_before_close_, 32);
  if (struct_version_ >= 1) {
    store_coins(cb, min_proxy_stake_);
    store_coins(cb, min_client_stake_);
  }

  cb.store_maybe_ref((value & 1) ? proxy_sc_code_ : td::Ref<vm::Cell>{});
  cb.store_maybe_ref((value & 2) ? worker_sc_code_ : td::Ref<vm::Cell>{});
  cb.store_maybe_ref((value & 4) ? client_sc_code_ : td::Ref<vm::Cell>{});

  return cb.finalize();
}

void RootContractConfig::store_stat(BaseRunner *runner, td::StringBuilder &sb) {
  sb << "<table>\n";
  sb << "<tr><td>root owner address</td><td>" << runner->address_link(owner_address()) << "</td></tr>\n";
  sb << "<tr><td>proxy hashes</td><td><table>\n";
  for (auto &h : accepted_proxy_hashes_) {
    sb << "<tr><td>" << h.to_hex() << "</td></tr>\n";
  }
  sb << "</table></td></tr>\n";
  sb << "<tr><td>registered proxies</td><td><table>\n";
  sb << "<tr><td>seqno</td><td>for clients</td><td>for workers</td><td>hash</td></tr>\n";
  for (auto &c : proxies_) {
    sb << "<tr><td>" << c.seqno << "</td><td>" << c.address_for_clients << "</td><td>" << c.address_for_workers
       << "</td></tr>\n";
  }
  sb << "</table></td></tr>\n";
  sb << "<tr><td>last proxy seqno</td><td>" << last_proxy_seqno_ << "</td></tr>\n";
  sb << "<tr><td>worker hashes</td><td><table>\n";
  for (auto &h : workers_) {
    sb << "<tr><td>" << h.to_hex() << "</td></tr>\n";
  }
  sb << "</table></td></tr>\n";
  sb << "<tr><td>model hashes</td><td><table>\n";
  for (auto &h : models_) {
    sb << "<tr><td>" << h.to_hex() << "</td></tr>\n";
  }
  sb << "</table></td></tr>\n";
  sb << "<tr><td>version</td><td>" << version_ << "</td></tr>\n";
  sb << "<tr><td>struct version</td><td>" << struct_version_ << "</td></tr>\n";
  sb << "<tr><td>params version</td><td>" << params_version_ << "</td></tr>\n";
  sb << "<tr><td>unique id</td><td>" << unique_id_ << "</td></tr>\n";
  sb << "<tr><td>test</td><td>" << (is_test_ ? "YES" : "NO") << "</td></tr>\n";
  sb << "<tr><td>price per token</td><td>" << price_per_token_ << "</td></tr>\n";
  sb << "<tr><td>worker fee per token</td><td>" << worker_fee_per_token_ << "</td></tr>\n";
  sb << "<tr><td>prompt tokens price multiplier</td><td>" << (double)(prompt_tokens_price_multiplier_ * 0.0001)
     << "</td></tr>\n";
  sb << "<tr><td>cached tokens price multiplier</td><td>" << (double)(cached_tokens_price_multiplier_ * 0.0001)
     << "</td></tr>\n";
  sb << "<tr><td>completion tokens price multiplier</td><td>" << (double)(completion_tokens_price_multiplier_ * 0.0001)
     << "</td></tr>\n";
  sb << "<tr><td>reasoning tokens price multiplier</td><td>" << (double)(reasoning_tokens_price_multiplier_ * 0.0001)
     << "</td></tr>\n";
  sb << "<tr><td>proxy delay before close</td><td>" << proxy_delay_before_close_ << "</td></tr>\n";
  sb << "<tr><td>client delay before close</td><td>" << client_delay_before_close_ << "</td></tr>\n";
  sb << "<tr><td>proxy min stake</td><td>" << to_ton(min_proxy_stake_) << "</td></tr>\n";
  sb << "<tr><td>client min stake</td><td>" << to_ton(min_client_stake_) << "</td></tr>\n";
  sb << "<tr><td>registered public keys</td><td><table>";
  for (auto &k : public_keys_) {
    sb << "<tr><td>" << k.first.to_hex() << "</td><td>" << k.second.key_type << "</td><td>" << k.second.expire_at
       << "</td></tr>\n";
  }
  sb << "</table></td></tr>\n";
  sb << "<tr><td>key manager addr</td><td>" << key_manager_addr_ << "</td></tr>\n";
  sb << "<tr><td>proxy code hash</td><td>" << proxy_sc_code()->get_hash().to_hex() << "</td></tr>\n";
  sb << "<tr><td>worker code hash</td><td>" << worker_sc_code()->get_hash().to_hex() << "</td></tr>\n";
  sb << "<tr><td>client code hash</td><td>" << client_sc_code()->get_hash().to_hex() << "</td></tr>\n";
  sb << "</table>\n";
}

void RootContractConfig::store_stat(BaseRunner *runner, SimpleJsonSerializer &jb) {
  jb.start_object("root_contract_config");
  jb.add_element("owner_address", owner_.rserialize(true));
  jb.start_array("proxy_hashes");
  for (auto &h : accepted_proxy_hashes_) {
    jb.add_element(h.to_hex());
  }
  jb.stop_array();
  jb.start_array("registered_proxies");
  for (auto &c : proxies_) {
    jb.start_object();
    jb.add_element("seqno", c.seqno);
    jb.add_element("address_for_clients", PSTRING() << c.address_for_clients);
    jb.add_element("address_for_workers", PSTRING() << c.address_for_workers);
    jb.stop_object();
  }
  jb.stop_array();
  jb.add_element("last_proxy_seqno", last_proxy_seqno_);
  jb.start_array("worker_hashes");
  for (auto &h : workers_) {
    jb.add_element(h.to_hex());
  }
  jb.stop_array();
  jb.start_array("model_hashes");
  for (auto &h : models_) {
    jb.add_element(h.to_hex());
  }
  jb.stop_array();
  jb.add_element("version", version_);
  jb.add_element("struct_version", struct_version_);
  jb.add_element("params_version", params_version_);
  jb.add_element("unique_id", unique_id_);
  jb.add_element("is_test", is_test_);
  jb.add_element("price_per_token", price_per_token_);
  jb.add_element("worker_fee_per_token", worker_fee_per_token_);
  jb.add_element("prompt_tokens_price_multiplier", prompt_tokens_price_multiplier_);
  jb.add_element("cached_tokens_price_multiplier", cached_tokens_price_multiplier_);
  jb.add_element("completion_tokens_price_multiplier", completion_tokens_price_multiplier_);
  jb.add_element("cached_tokens_price_multiplier", cached_tokens_price_multiplier_);
  jb.add_element("reasoning_tokens_price_multiplier", reasoning_tokens_price_multiplier_);
  jb.add_element("proxy_delay_before_close", proxy_delay_before_close_);
  jb.add_element("client_delay_before_close", client_delay_before_close_);
  jb.add_element("proxy_min_stake", min_proxy_stake_);
  jb.add_element("client_min_stake", min_client_stake_);
  jb.add_element("proxy_code_hash", proxy_sc_code()->get_hash().to_hex());
  jb.add_element("worker_code_hash", worker_sc_code()->get_hash().to_hex());
  jb.add_element("client_code_hash", client_sc_code()->get_hash().to_hex());
  jb.stop_object();
}

}  // namespace cocoon
