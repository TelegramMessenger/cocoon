#pragma once

#include "common/bitstring.h"
#include "nlohmann/json_fwd.hpp"
#include "td/utils/buffer.h"
#include "td/utils/Status.h"
#include "auto/tl/cocoon_api.h"
#include <nlohmann/json.hpp>

namespace cocoon {

struct MultipartFormDataValue {
  std::vector<std::string> descr;
  std::string value;

  MultipartFormDataValue() = default;
  static MultipartFormDataValue create(std::vector<std::string> descr, std::string value) {
    return MultipartFormDataValue(std::move(descr), std::move(value));
  }
  static MultipartFormDataValue create_with_name(std::string name, std::string value) {
    return MultipartFormDataValue({PSTRING() << "Content-Disposition: form-data; name=\"" << name << "\""},
                                  std::move(value));
  }

 private:
  MultipartFormDataValue(std::vector<std::string> descr, std::string value)
      : descr(std::move(descr)), value(std::move(value)) {
  }
};

using MultipartFormDataMap = std::map<std::string, MultipartFormDataValue>;

td::Result<td::Bits256> parse_bits256_from_json(td::Slice key);

void encrypt_json(nlohmann::json &value, const td::Bits256 &private_key, const td::Bits256 &public_key,
                  bool client_to_worker);
td::Status decrypt_json(nlohmann::json &value, const td::Bits256 &private_key, td::Bits256 &public_key,
                        bool check_public_key, bool client_to_worker);
td::Status decrypt_form(MultipartFormDataMap &value, const td::Bits256 &private_key, td::Bits256 &public_key,
                        bool check_public_key, bool client_to_worker);

// Validates an unencrypted /v1/chat/completions body with the same rules the worker applies.
// Intended for tests and tooling.
td::Status validate_plain_chat_completions(td::Slice request);

td::Result<td::BufferSlice> validate_decrypt_request(std::string url, td::Slice content_type, td::BufferSlice request,
                                                     std::string *model, td::int64 *max_tokens,
                                                     const td::Bits256 &private_key, td::Bits256 *client_public_key);
td::Result<td::BufferSlice> validate_encrypt_answer_part(std::string url, td::BufferSlice request, std::string *model,
                                                         td::int64 *max_tokens, const td::Bits256 *private_key);
td::Result<std::string> validate_client_request(td::Slice url, td::Slice content_type, td::Slice request,
                                                std::string *model, td::int64 *max_tokens, td::int32 *max_coefficient,
                                                double *timeout, bool *enable_debug, td::Bits256 *request_guid,
                                                td::Bits256 *receiver_public_key);

class AnswerPostprocessor {
 public:
  AnswerPostprocessor(td::int32 coef, td::int32 prompt_tokens_mult, td::int32 cached_tokens_mult,
                      td::int32 completion_tokens_mult, td::int32 reasoning_tokens_mult, td::int64 price_per_token,
                      td::Bits256 sender_private_key, td::Bits256 receiver_public_key)
      : coef_(coef)
      , prompt_tokens_mult_(prompt_tokens_mult)
      , cached_tokens_mult_(cached_tokens_mult)
      , completion_tokens_mult_(completion_tokens_mult)
      , reasoning_tokens_mult_(reasoning_tokens_mult)
      , price_per_token_(price_per_token)
      , sender_private_key_(sender_private_key)
      , receiver_public_key_(receiver_public_key) {
  }
  td::Status add_prompt(td::Slice) {
    return td::Status::OK();
  }
  std::string add_next_answer_slice(td::Slice);
  std::string finalize();
  ton::tl_object_ptr<cocoon_api::tokensUsed> usage();

 private:
  td::int32 coef_;
  std::string last_;
  td::int32 prompt_tokens_mult_;
  td::int32 cached_tokens_mult_;
  td::int32 completion_tokens_mult_;
  td::int32 reasoning_tokens_mult_;
  td::int64 price_per_token_;
  td::Bits256 sender_private_key_;
  td::Bits256 receiver_public_key_;

  td::int64 prompt_tokens_{0};
  td::int64 cached_tokens_{0};
  td::int64 completion_tokens_{0};
  td::int64 reasoning_tokens_{0};
};

}  // namespace cocoon
