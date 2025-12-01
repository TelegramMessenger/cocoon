#include "WorkerRunningRequest.hpp"
#include "WorkerRunner.h"
#include "errorcode.h"
#include "http/http.h"
#include "runners/helpers/HttpSender.hpp"
#include "runners/helpers/ValidateRequest.h"

#include "cocoon-tl-utils/cocoon-tl-utils.hpp"
#include "td/actor/actor.h"
#include "td/utils/Random.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/buffer.h"
#include <memory>

namespace cocoon {
WorkerRunningRequest::WorkerRunningRequest(td::Bits256 proxy_request_id, TcpClient::ConnectionId proxy_connection_id,
                                           td::BufferSlice data, double timeout, std::string model_base_name,
                                           td::int32 coefficient, std::shared_ptr<RunnerConfig> runner_config,
                                           td::actor::ActorId<WorkerRunner> runner, std::shared_ptr<WorkerStats> stats)
    : proxy_request_id_(proxy_request_id)
    , proxy_connection_id_(proxy_connection_id)
    , data_(std::move(data))
    , timeout_(timeout)
    , model_base_name_(std::move(model_base_name))
    , runner_(runner)
    , stats_(std::move(stats)) {
  tokens_counter_ = create_token_counter(model_base_name_, coefficient,
                                         runner_config->root_contract_config->prompt_tokens_price_multiplier(),
                                         runner_config->root_contract_config->cached_tokens_price_multiplier(),
                                         runner_config->root_contract_config->completion_tokens_price_multiplier(),
                                         runner_config->root_contract_config->reasoning_tokens_price_multiplier(),
                                         runner_config->root_contract_config->price_per_token());
}

/*
 *
 * 1. unpack request
 * 2. forward http request 
 * 3. receive http answer
 * 4. start downloading http answer payload
 *
 */
void WorkerRunningRequest::start_request() {
  LOG(INFO) << "worker request " << proxy_request_id_.to_hex() << ": received";
  stats()->requests_received++;

  auto R = cocoon::fetch_tl_object<cocoon_api::http_request>(std::move(data_), true);
  if (R.is_error()) {
    send_error(R.move_as_error_prefix("worker: invalid http request: "));
    return;
  }

  auto req = R.move_as_ok();

  // we count only bytes in payload
  stats()->request_bytes_received += (double)req->payload_.size();

  static const std::string v_stream = "stream";
  static const std::string v_stream_options = "stream_options";
  static const std::string v_include_usage = "include_usage";

  std::unique_ptr<ton::http::HttpRequest> request;
  auto S = [&]() {
    std::string model;
    TRY_RESULT(new_payload, validate_modify_request(req->url_, std::move(req->payload_), &model, nullptr));
    if (model != model_base_name_) {
      return td::Status::Error(ton::ErrorCode::protoviolation, "model name mismatch");
    }
    req->payload_ = std::move(new_payload);
    tokens_counter_->add_prompt(req->payload_.as_slice());

    TRY_RESULT_ASSIGN(request, ton::http::HttpRequest::create(req->method_, req->url_, req->http_version_));
    for (auto &x : req->headers_) {
      ton::http::HttpHeader h{x->name_, x->value_};
      if (x->name_ == "Content-Length" || x->name_ == "Transfer-Encoding" || x->name_ == "Connection") {
        continue;
      }
      TRY_STATUS(h.basic_check());
      request->add_header(std::move(h));
    }
    request->add_header(ton::http::HttpHeader{"Content-Length", PSTRING() << req->payload_.size()});
    TRY_STATUS(request->complete_parse_header());
    return td::Status::OK();
  }();
  if (S.is_error()) {
    send_error(S.move_as_error_prefix("worker: invalid http request: "));
    return;
  }

  LOG(INFO) << "working request " << proxy_request_id_.to_hex() << ": sending request to url " << req->url_
            << " method=" << req->method_;

  auto payload = request->create_empty_payload().move_as_ok();
  payload->add_chunk(std::move(req->payload_));
  payload->complete_parse();

  auto P = td::PromiseCreator::lambda(
      [self_id = actor_id(this)](
          td::Result<std::pair<std::unique_ptr<ton::http::HttpResponse>, std::shared_ptr<ton::http::HttpPayload>>>
              R) mutable {
        if (R.is_error()) {
          td::actor::send_closure(self_id, &WorkerRunningRequest::send_error,
                                  R.move_as_error_prefix("worker: http failed: "));
        } else {
          td::actor::send_closure(self_id, &WorkerRunningRequest::process_request_response, R.move_as_ok());
        }
      });

  td::actor::send_closure(runner_, &WorkerRunner::send_http_request, std::move(request), std::move(payload),
                          td::Timestamp::in(timeout_ * 0.95), std::move(P));
}

void WorkerRunningRequest::process_request_response(
    std::pair<std::unique_ptr<ton::http::HttpResponse>, std::shared_ptr<ton::http::HttpPayload>> res) {
  auto response = std::move(res.first);
  auto payload = std::move(res.second);
  if (payload->payload_type() == ton::http::HttpPayload::PayloadType::pt_empty) {
    send_answer(std::move(response), td::BufferSlice(), true);
    return;
  }

  send_answer(std::move(response), td::BufferSlice(), false);

  class Cb : public HttpPayloadCbReceiver::Cb {
   public:
    Cb(td::actor::ActorId<WorkerRunningRequest> self_id) : self_id_(self_id) {
    }
    void data_chunk(td::BufferSlice buffer, bool is_finished) override {
      td::actor::send_closure(self_id_, &WorkerRunningRequest::send_payload_part, std::move(buffer), is_finished);
    }
    void error(td::Status error) override {
      td::actor::send_closure(self_id_, &WorkerRunningRequest::send_error,
                              error.move_as_error_prefix("worker: failed to get payload: "));
    }

   private:
    td::actor::ActorId<WorkerRunningRequest> self_id_;
  };

  auto cb = std::make_unique<Cb>(actor_id(this));

  td::actor::create_actor<HttpPayloadCbReceiver>("payloadreceiver", std::move(payload), std::move(cb)).release();
}

void WorkerRunningRequest::send_error(td::Status error) {
  if (completed_) {
    return;
  }
  LOG(WARNING) << "worker request " << proxy_request_id_.to_hex() << " failed: " << error;

  stats()->requests_failed++;

  if (!sent_answer_) {
    auto ans = cocoon::cocoon_api::make_object<cocoon_api::proxy_queryAnswerError>(
        error.code(), error.message().str(), proxy_request_id_, tokens_counter_->usage());
    td::actor::send_closure(runner_, &WorkerRunner::send_message_to_connection, proxy_connection_id_,
                            cocoon::serialize_tl_object(ans, true));
  } else {
    auto ans = cocoon::cocoon_api::make_object<cocoon_api::proxy_queryAnswerPartError>(
        error.code(), error.message().str(), proxy_request_id_, tokens_counter_->usage());
    td::actor::send_closure(runner_, &WorkerRunner::send_message_to_connection, proxy_connection_id_,
                            cocoon::serialize_tl_object(ans, true));
    sent_answer_ = true;
  }

  finish_request(false);
}

void WorkerRunningRequest::send_answer(std::unique_ptr<ton::http::HttpResponse> response, td::BufferSlice orig_payload,
                                       bool payload_is_completed) {
  if (completed_) {
    return;
  }
  LOG(DEBUG) << "worker request " << proxy_request_id_.to_hex() << ": starting sending answer";

  auto payload_to_send = tokens_counter_->add_next_answer_slice(orig_payload.as_slice());
  if (payload_is_completed) {
    payload_to_send = payload_to_send + tokens_counter_->finalize();
  }

  stats()->answer_bytes_sent += (double)payload_to_send.size();
  if (payload_to_send.size() > 0) {
    payload_parts_++;
    payload_bytes_ += payload_to_send.size();
  }

  auto r = response->store_tl();

  //http.response http_version:string status_code:int reason:string headers:(vector http.header) payload:bytes = http.Response;
  auto res = cocoon::cocoon_api::make_object<cocoon_api::http_response>(
      r->http_version_, r->status_code_, r->reason_, std::vector<ton::tl_object_ptr<cocoon_api::http_header>>(),
      td::BufferSlice(payload_to_send));

  for (auto &h : r->headers_) {
    if (h->name_ == "Content-Length" || h->name_ == "Transfer-Encoding" || h->name_ == "Connection") {
      continue;
    }
    res->headers_.push_back(cocoon::cocoon_api::make_object<cocoon_api::http_header>(h->name_, h->value_));
  }

  // Add debug timing headers using Unix timestamps
  res->headers_.push_back(cocoon::cocoon_api::make_object<cocoon_api::http_header>(
      "X-Cocoon-Worker-Start", PSTRING() << td::StringBuilder::FixedDouble(started_at_unix_, 6)));
  res->headers_.push_back(cocoon::cocoon_api::make_object<cocoon_api::http_header>(
      "X-Cocoon-Worker-End", PSTRING() << td::StringBuilder::FixedDouble(td::Clocks::system(), 6)));

  if (payload_is_completed) {
    res->headers_.push_back(
        cocoon::cocoon_api::make_object<cocoon_api::http_header>("Content-Length", PSTRING() << res->payload_.size()));
  } else {
    res->headers_.push_back(cocoon::cocoon_api::make_object<cocoon_api::http_header>("Transfer-Encoding", "chunked"));
  }

  auto serialized_res = cocoon::serialize_tl_object(res, true);
  auto ans = cocoon::cocoon_api::make_object<cocoon_api::proxy_queryAnswer>(
      std::move(serialized_res), payload_is_completed, proxy_request_id_, tokens_counter_->usage());
  td::actor::send_closure(runner_, &WorkerRunner::send_message_to_connection, proxy_connection_id_,
                          cocoon::serialize_tl_object(ans, true));
  sent_answer_ = true;

  if (payload_is_completed) {
    finish_request(true);
  }
}

void WorkerRunningRequest::send_payload_part(td::BufferSlice orig_payload_part, bool payload_is_completed) {
  if (completed_) {
    return;
  }
  LOG(DEBUG) << "worker request " << proxy_request_id_.to_hex() << ": sending next payload part";

  CHECK(sent_answer_);
  CHECK(!completed_);

  auto payload_to_send = tokens_counter_->add_next_answer_slice(orig_payload_part.as_slice());
  if (payload_is_completed) {
    payload_to_send = payload_to_send + tokens_counter_->finalize();
  }

  if (!payload_to_send.size() && !payload_is_completed) {
    return;
  }

  payload_parts_++;
  payload_bytes_ += payload_to_send.size();
  stats()->answer_bytes_sent += (double)payload_to_send.size();

  auto ans = cocoon::cocoon_api::make_object<cocoon_api::proxy_queryAnswerPart>(
      td::BufferSlice(payload_to_send), payload_is_completed, proxy_request_id_, tokens_counter_->usage());
  td::actor::send_closure(runner_, &WorkerRunner::send_message_to_connection, proxy_connection_id_,
                          cocoon::serialize_tl_object(ans, true));

  if (payload_is_completed) {
    finish_request(true);
  }
}

void WorkerRunningRequest::finish_request(bool is_success) {
  if (completed_) {
    return;
  }
  auto tokens_used = tokens_counter_->usage();
  LOG(INFO) << "worker request " << proxy_request_id_.to_hex() << ": completed: success=" << (is_success ? "YES" : "NO")
            << " time=" << run_time() << " payload_parts=" << payload_parts_ << " payload_bytes=" << payload_bytes_
            << " tokens_used=" << tokens_used->prompt_tokens_used_ << "+" << tokens_used->cached_tokens_used_ << "+"
            << tokens_used->completion_tokens_used_ << "+" << tokens_used->reasoning_tokens_used_ << "="
            << tokens_used->total_tokens_used_;
  completed_ = true;
  stats_->total_adjusted_tokens_used += (double)tokens_used->total_tokens_used_;
  stats_->prompt_adjusted_tokens_used += (double)tokens_used->prompt_tokens_used_;
  stats_->cached_adjusted_tokens_used += (double)tokens_used->cached_tokens_used_;
  stats_->completion_adjusted_tokens_used += (double)tokens_used->completion_tokens_used_;
  stats_->reasoning_adjusted_tokens_used += (double)tokens_used->reasoning_tokens_used_;
  if (is_success) {
    stats()->requests_success++;
  } else {
    stats()->requests_failed++;
  }

  stats()->total_requests_time += run_time();

  td::actor::send_closure(runner_, &WorkerRunner::finish_request, proxy_request_id_, is_success);

  stop();
}

}  // namespace cocoon
