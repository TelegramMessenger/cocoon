// Regression tests for OpenAI-compatible request validation:
// tools / tool_choice (function calling) and response_format (structured output).
#include "runners/helpers/ValidateRequest.h"

#include <cstdio>
#include <string>

namespace {

int failures = 0;

td::Status run(const std::string &body) {
  return cocoon::validate_plain_chat_completions(body);
}

void expect(const char *name, const std::string &body, bool ok) {
  auto s = run(body);
  if (s.is_ok() != ok) {
    std::printf("FAIL %s: expected %s, got %s\n", name, ok ? "ok" : "error",
                s.is_ok() ? "ok" : s.message().str().c_str());
    failures++;
  } else {
    std::printf("ok   %s%s%s\n", name, s.is_ok() ? "" : " -> ", s.is_ok() ? "" : s.message().str().c_str());
  }
}

const std::string kMsg = R"("model":"Qwen/Qwen3-8B","messages":[{"role":"user","content":"weather in Dubai?"}])";
const std::string kTool =
    R"({"type":"function","function":{"name":"get_weather","description":"Get weather",)"
    R"("parameters":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]},"strict":true}})";

}  // namespace

int main() {
  expect("plain request", "{" + kMsg + "}", true);
  expect("tools", "{" + kMsg + R"(,"tools":[)" + kTool + "]}", true);
  expect("tools + tool_choice auto", "{" + kMsg + R"(,"tools":[)" + kTool + R"(],"tool_choice":"auto"})", true);
  expect("tool_choice named function",
         "{" + kMsg + R"(,"tools":[)" + kTool + R"(],"tool_choice":{"type":"function","function":{"name":"get_weather"}}})",
         true);
  expect("tool_choice bad string", "{" + kMsg + R"(,"tools":[)" + kTool + R"(],"tool_choice":"sometimes"})", false);
  expect("tool without name", "{" + kMsg + R"(,"tools":[{"type":"function","function":{"description":"x"}}]})",
         false);
  expect("tool unknown type", "{" + kMsg + R"(,"tools":[{"type":"magic"}]})", false);
  expect("tools not array", "{" + kMsg + R"(,"tools":{"type":"function"}})", false);
  expect("response_format json_object", "{" + kMsg + R"(,"response_format":{"type":"json_object"}})", true);
  expect("response_format json_schema",
         "{" + kMsg +
             R"(,"response_format":{"type":"json_schema","json_schema":{"name":"r","schema":{"type":"object"}}}})",
         true);
  expect("response_format without type", "{" + kMsg + R"(,"response_format":{"json_schema":{}}})", false);
  expect("assistant tool_calls round-trip",
         R"({"model":"Qwen/Qwen3-8B","messages":[{"role":"user","content":"hi"},)"
         R"({"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Dubai\"}"}}]},)"
         R"({"role":"tool","tool_call_id":"c1","content":"31C"}],"tools":[)" +
             kTool + "]}",
         true);

  std::printf(failures ? "%d test(s) FAILED\n" : "all tests passed\n", failures);
  return failures ? 1 : 0;
}
