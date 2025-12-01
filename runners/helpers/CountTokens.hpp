#include <memory>
#include <string>
#include "auto/tl/cocoon_api.h"

namespace cocoon {

class TokenCounter {
 public:
  virtual ~TokenCounter() = default;
  virtual void add_prompt(td::Slice event) = 0;
  virtual std::string add_next_answer_slice(td::Slice) = 0;
  virtual std::string finalize() = 0;
  virtual ton::tl_object_ptr<cocoon_api::tokensUsed> usage() = 0;
};

std::unique_ptr<TokenCounter> create_token_counter(std::string model_name, td::int32 coef, td::int32 prompt_tokens_mult,
                                                   td::int32 cached_tokens_mult, td::int32 completion_tokens_mult,
                                                   td::int32 reasoning_tokens_mult, td::int64 price_per_token);

}  // namespace cocoon
