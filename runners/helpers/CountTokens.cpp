#include "CountTokens.hpp"
#include "Ton.h"
#include "td/utils/StringBuilder.h"
#include "td/utils/buffer.h"
#include "tl/TlObject.h"
#include <memory>
#include <sstream>
#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>

namespace cocoon {

class ByteTokenCounter : public TokenCounter {
 public:
  ByteTokenCounter(td::int32 coef, td::int32 prompt_tokens_mult, td::int32 cached_tokens_mult,
                   td::int32 completion_tokens_mult, td::int32 reasoning_tokens_mult, td::int64 price_per_token)
      : coef_(coef)
      , prompt_tokens_mult_(prompt_tokens_mult)
      , cached_tokens_mult_(cached_tokens_mult)
      , completion_tokens_mult_(completion_tokens_mult)
      , reasoning_tokens_mult_(reasoning_tokens_mult)
      , price_per_token_(price_per_token) {
  }
  void add_prompt(td::Slice event) override {
  }

  static td::int64 get_json_value(nlohmann::json &json, const std::vector<std::string> &sub) {
    auto *ptr = &json;
    for (const auto &f : sub) {
      if (!ptr->is_object()) {
        return 0;
      }
      if (!ptr->contains(f)) {
        return 0;
      }
      ptr = &(*ptr)[f];
    }
    if (!ptr->is_number_unsigned()) {
      return 0;
    }
    return ptr->get<td::int64>();
  }

  std::string add_next_answer_slice(td::Slice event) override {
    last_ += event.str();

    td::StringBuilder sb;
    std::stringstream ss(last_);
    size_t pos = 0;
    bool is_end = false;
    while (!is_end) {
      try {
        nlohmann::json v;
        ss >> v;
        pos = ss.tellg();

        bool updated = false;

        {
          auto val = get_json_value(v, {"usage", "prompt_tokens"});
          if (val > prompt_tokens_) {
            prompt_tokens_ = val;
            updated = true;
          }
        }
        {
          auto val = get_json_value(v, {"usage", "prompt_tokens_details", "cached_tokens"});
          if (val > cached_tokens_) {
            cached_tokens_ = val;
            updated = true;
          }
        }
        {
          auto val = get_json_value(v, {"usage", "completion_tokens"});
          if (val > completion_tokens_) {
            completion_tokens_ = val;
            updated = true;
          }
        }
        {
          auto val = get_json_value(v, {"usage", "completion_tokens_details", "reasoning_tokens"});
          if (val > reasoning_tokens_) {
            reasoning_tokens_ = val;
            updated = true;
          }
        }
        {
          auto val = get_json_value(v, {"usage", "reasoning_tokens"});
          if (val > reasoning_tokens_) {
            reasoning_tokens_ = val;
            updated = true;
          }
        }

        if (updated) {
          auto prompt_tokens_adj = adjust_tokens(prompt_tokens_ - cached_tokens_, coef_, prompt_tokens_mult_);
          auto cached_tokens_adj = adjust_tokens(cached_tokens_, coef_, cached_tokens_mult_);
          auto completion_tokens_adj =
              adjust_tokens(completion_tokens_ - reasoning_tokens_, coef_, completion_tokens_mult_);
          auto reasoning_tokens_adj = adjust_tokens(reasoning_tokens_, coef_, reasoning_tokens_mult_);

          v["usage"]["prompt_total_cost"] = (prompt_tokens_adj + cached_tokens_adj) * price_per_token_;
          v["usage"]["completion_total_cost"] = (completion_tokens_adj + reasoning_tokens_adj) * price_per_token_;
          v["usage"]["total_cost"] =
              (prompt_tokens_adj + cached_tokens_adj + completion_tokens_adj + reasoning_tokens_adj) * price_per_token_;
        }

        sb << v.dump() << "\n";
      } catch (...) {
        is_end = true;
      }
    }
    last_ = last_.substr(pos);
    return sb.as_cslice().str();
  }
  std::string finalize() override {
    return last_;
  }
  ton::tl_object_ptr<cocoon_api::tokensUsed> usage() override {
    auto prompt_tokens_adj = adjust_tokens(prompt_tokens_ - cached_tokens_, coef_, prompt_tokens_mult_);
    auto cached_tokens_adj = adjust_tokens(cached_tokens_, coef_, cached_tokens_mult_);
    auto completion_tokens_adj = adjust_tokens(completion_tokens_ - reasoning_tokens_, coef_, completion_tokens_mult_);
    auto reasoning_tokens_adj = adjust_tokens(reasoning_tokens_, coef_, reasoning_tokens_mult_);
    return ton::create_tl_object<cocoon_api::tokensUsed>(
        prompt_tokens_adj, cached_tokens_adj, completion_tokens_adj, reasoning_tokens_adj,
        prompt_tokens_adj + cached_tokens_adj + completion_tokens_adj + reasoning_tokens_adj);
  }

 private:
  td::int32 coef_;
  std::string last_;
  td::int32 prompt_tokens_mult_;
  td::int32 cached_tokens_mult_;
  td::int32 completion_tokens_mult_;
  td::int32 reasoning_tokens_mult_;
  td::int64 price_per_token_;

  td::int64 prompt_tokens_{0};
  td::int64 cached_tokens_{0};
  td::int64 completion_tokens_{0};
  td::int64 reasoning_tokens_{0};
};

std::unique_ptr<TokenCounter> create_token_counter(std::string model_name, td::int32 coef, td::int32 prompt_tokens_mult,
                                                   td::int32 cached_tokens_mult, td::int32 completion_tokens_mult,
                                                   td::int32 reasoning_tokens_mult, td::int64 price_per_token) {
  return std::make_unique<ByteTokenCounter>(coef, prompt_tokens_mult, cached_tokens_mult, completion_tokens_mult,
                                            reasoning_tokens_mult, price_per_token);
}

}  // namespace cocoon
