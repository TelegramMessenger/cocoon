#include "ValidateRequest.h"
#include "Ed25519.h"
#include "checksum.h"
#include "common/bitstring.h"
#include "errorcode.h"
#include "nlohmann/detail/input/json_sax.hpp"
#include "td/utils/JsonBuilder.h"
#include "td/utils/Random.h"
#include "td/utils/SharedSlice.h"
#include "td/utils/Slice-decl.h"
#include "td/utils/Status.h"
#include "td/utils/StringBuilder.h"
#include "td/utils/base64.h"
#include "td/utils/buffer.h"
#include "td/utils/misc.h"
#include "td/utils/optional.h"
#include "tdport/td/e2e/MessageEncryption.h"
#include "runners/helpers/Ton.h"
#include "third-party/multipart-parser-c/multipart_parser.h"

#include <memory>
#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>
#include <set>
#include <sstream>
#include <string>
#include <string_view>

namespace cocoon {

bool ci_char_equals(char a, char b) {
  return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
}

bool ci_str_equals(td::Slice a, td::Slice b) {
  return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), ci_char_equals);
}

bool is_whitespace(char c) {
  return c == ' ' || c == '\n' || c == '\r' || c == '\t';
}

td::Slice trim(td::Slice S) {
  while (S.size() > 0 && is_whitespace(S[0])) {
    S.remove_prefix(1);
  }
  while (S.size() > 0 && is_whitespace(S.back())) {
    S.remove_suffix(1);
  }
  return S;
}

class MultipartParser {
 private:
  static int read_header_name(multipart_parser *p, const char *at, size_t length) {
    MultipartParser *self = (MultipartParser *)multipart_parser_get_data(p);
    if (self->was_data_) {
      self->was_data_ = false;
      self->name_ = "";
      self->descr_.clear();
    }

    self->header_name_ = std::string(at, length);
    self->process_header_ = ci_str_equals(td::Slice(at, length), "Content-Disposition");
    return 0;
  }
  static int read_header_value(multipart_parser *p, const char *at, size_t length) {
    MultipartParser *self = (MultipartParser *)multipart_parser_get_data(p);
    auto v = td::Slice(at, length);
    v = trim(v);

    self->descr_.push_back(PSTRING() << self->header_name_ << ": " << v.str());

    if (!self->process_header_) {
      return 0;
    }

    auto v_vec = td::full_split(v, ';');
    for (auto el : v_vec) {
      auto p = td::split(el, '=');
      auto name = trim(p.first);
      if (ci_str_equals(name, "name")) {
        auto value = trim(p.second);
        if (value.size() > 0) {
          if (value[0] == '"' && value.back() == '"' && value.size() >= 2) {
            self->name_ = value.substr(1, value.size() - 2).str();
          } else {
            self->name_ = value.str();
          }
        }
      }
    }

    return 0;
  }
  static int on_part_data(multipart_parser *p, const char *at, size_t length) {
    MultipartParser *self = (MultipartParser *)multipart_parser_get_data(p);
    if (self->name_ == "") {
      self->was_data_ = true;
      return 0;
    }
    if (!self->was_data_) {
      self->was_data_ = true;
      self->fields_[self->name_] = MultipartFormDataValue::create(std::move(self->descr_), std::string(at, length));
    } else {
      self->fields_[self->name_].value += std::string_view(at, length);
    }
    return 0;
  }

 public:
  MultipartParser(const std::string &boundary) {
    memset(&callbacks_, 0, sizeof(callbacks_));
    callbacks_.on_header_field = read_header_name;
    callbacks_.on_header_value = read_header_value;
    callbacks_.on_part_data = on_part_data;

    parser_ = multipart_parser_init(boundary.c_str(), &callbacks_);
    multipart_parser_set_data(parser_, this);
  }

  ~MultipartParser() {
    multipart_parser_free(parser_);
    parser_ = nullptr;
  }

  td::Result<MultipartFormDataMap> parse(td::Slice body) {
    auto v = multipart_parser_execute(parser_, body.data(), body.size());
    if (!v) {
      return td::Status::Error(ton::ErrorCode::protoviolation, "cannot parse form multipart data");
    }
    return std::move(fields_);
  }

 private:
  multipart_parser *parser_{nullptr};
  multipart_parser_settings callbacks_{};
  bool process_header_{false};
  bool was_data_{false};
  std::string name_;
  std::string header_name_;
  std::vector<std::string> descr_;
  MultipartFormDataMap fields_;
};

static td::Result<td::Slice> get_multipart_boundary(td::Slice content_type) {
  auto prefix = td::CSlice("multipart/form-data");
  if (content_type.size() < prefix.size() || content_type.copy().truncate(prefix.size()) != prefix) {
    return td::Status::Error(ton::ErrorCode::protoviolation,
                             PSTRING() << "expected " << prefix << " content type, found " << content_type);
  }
  content_type.remove_prefix(prefix.size());

  auto bprefix = td::CSlice("boundary=");
  auto args = td::full_split(content_type, ' ');
  td::Slice boundary = "";
  for (auto &arg : args) {
    if (arg.size() < bprefix.size() || arg.copy().truncate(bprefix.size()) != bprefix) {
      continue;
    }
    boundary = arg.remove_prefix(bprefix.size());
  }

  if (boundary.size() == 0) {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << "cannot find boundary in content type");
  }

  if (boundary[0] == '"') {
    boundary = boundary.substr(1, boundary.size() - 2);
  }
  return boundary;
}

static td::Result<MultipartFormDataMap> parse_multipart_form(td::Slice content_type, td::Slice body) {
  TRY_RESULT(boundary, get_multipart_boundary(content_type));

  std::string delim = PSTRING() << "--" << boundary;

  MultipartParser p(delim);

  return p.parse(body);
}

static td::Result<std::string> store_multipart_form(td::Slice content_type, MultipartFormDataMap &fields) {
  TRY_RESULT(boundary, get_multipart_boundary(content_type));
  td::StringBuilder body;

  for (const auto &[key, value] : fields) {
    body << "--" << boundary << "\r\n";
    for (auto &e : value.descr) {
      body << e << "\r\n";
    }
    body << "\r\n";
    body << value.value << "\r\n";
  }

  body << "--" << boundary << "--\r\n";

  auto res = body.as_cslice();
  return res.str();
}

static td::Result<td::SecureString> generate_shared_secret(const td::Bits256 &pk_b256, const td::Bits256 &pub_b256,
                                                           const td::Bits256 &expected_public_key, td::Slice nonce,
                                                           bool client_to_worker) {
  td::Ed25519::PrivateKey pk(td::SecureString{pk_b256.as_slice()});
  {
    TRY_RESULT(v, pk.get_public_key());
    if (v.as_octet_string().as_slice() != expected_public_key.as_slice()) {
      return td::Status::Error(ton::ErrorCode::error, "public key mismatch");
    }
  }

  td::Ed25519::PublicKey pub(td::SecureString{pub_b256.as_slice()});
  TRY_RESULT(shared_secret, td::Ed25519::compute_shared_secret(pub, pk));

  td::SecureString tmp(32 + nonce.size() + 1);

  tmp.as_mutable_slice().copy_from(shared_secret.as_slice());
  tmp.as_mutable_slice().remove_prefix(32).copy_from(nonce);
  tmp.as_mutable_slice().remove_prefix(32 + nonce.size()).copy_from(client_to_worker ? "c" : "w");
  auto val = td::sha256_bits256(tmp.as_slice());
  return td::SecureString(val.as_slice());
}

static const std::vector<std::string> json_encryption_related_str_fields{"is_encrypted", "sender_public_key",
                                                                         "receiver_public_key", "encryption_nonce"};
static const std::vector<std::string> do_not_encrypt_fields{
    "model", "max_completion_tokens", "max_tokens",  "max_coefficient", "timeout",
    "debug", "enable_debug",          "request_guid"};

bool should_encrypt_field(td::Slice name) {
  for (const auto &s : json_encryption_related_str_fields) {
    if (s == name) {
      return false;
    }
  }
  for (const auto &s : do_not_encrypt_fields) {
    if (s == name) {
      return false;
    }
  }
  return true;
}

static td::Result<std::string> decrypt_string(td::Slice S, td::Slice secret) {
  auto encryption_type = S.copy().truncate(4);
  S.remove_prefix(4);

  if (encryption_type == "ENC_") {
    TRY_RESULT(v, td::hex_decode(S));
    TRY_RESULT(res, tde2e_core::MessageEncryption::decrypt_data(v, secret));
    return res.as_slice().str();
  } else if (encryption_type == "DEC_") {
    return S.str();
  } else {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << "bad encryption method: " << S);
  }
}

static std::string encrypt_string(td::Slice S, td::Slice secret) {
  auto enc_value = tde2e_core::MessageEncryption::encrypt_data(S, secret);
  td::UniqueSlice buf(2 * enc_value.size() + 4);
  auto t = buf.as_mutable_slice();
  t.copy_from("ENC_");
  t.remove_prefix(4);
  t.copy_from(td::hex_encode(enc_value.as_slice()));
  return buf.as_slice().str();
}

static td::Status decrypt_all_strings(nlohmann::json &b, td::Slice shared_secret) {
  for (auto &[key, value] : b.items()) {
    if (should_encrypt_field(key)) {
      if (value.is_string()) {
        auto v = value.get<std::string>();
        TRY_RESULT(nv, decrypt_string(v, shared_secret));
        value = nv;
      } else if (value.is_structured()) {
        TRY_STATUS(decrypt_all_strings(value, shared_secret));
      }
    }
  }
  return td::Status::OK();
}

static td::Status decrypt_all_strings(MultipartFormDataMap &b, td::Slice shared_secret) {
  for (auto &[key, value] : b) {
    if (should_encrypt_field(key)) {
      TRY_RESULT(nv, decrypt_string(value.value, shared_secret));
      value.value = nv;
    }
  }
  return td::Status::OK();
}

static td::Status encrypt_all_strings(nlohmann::json &b, td::Slice shared_secret) {
  for (auto &[key, value] : b.items()) {
    if (should_encrypt_field(key)) {
      if (value.is_string()) {
        value = encrypt_string(value.get<std::string>(), shared_secret);
      } else if (value.is_structured()) {
        encrypt_all_strings(value, shared_secret);
      }
    }
  }
  return td::Status::OK();
}

static td::Result<nlohmann::json> parse_json(td::Slice S) {
  auto b = nlohmann::json::parse(S.begin(), S.end(), nullptr, false, false);

  if (b.is_discarded()) {
    return td::Status::Error(ton::ErrorCode::protoviolation, "expected json object");
  }
  if (!b.is_object()) {
    return td::Status::Error(ton::ErrorCode::protoviolation, "expected json object");
  }
  return b;
}

struct CtxLevel {
  enum class Mode { Json, Form, Slice };
  CtxLevel(nlohmann::json *obj, std::string path) : obj(obj), path(std::move(path)), mode(Mode::Json) {
  }
  CtxLevel(MultipartFormDataMap *fields, std::string path) : fields(fields), path(std::move(path)), mode(Mode::Form) {
  }
  CtxLevel(MultipartFormDataValue *field, std::string path)
      : field(std::move(field)), path(std::move(path)), mode(Mode::Slice) {
  }

  nlohmann::json *obj{nullptr};
  MultipartFormDataMap *fields{nullptr};
  MultipartFormDataValue *field{nullptr};
  std::string path;
  std::set<std::string> processed_fields;
  Mode mode;

  bool exists() const {
    return true;
  }

  bool is_object() {
    switch (mode) {
      case Mode::Form: {
        return true;
      }
      case Mode::Slice:
        return false;
      case Mode::Json: {
        return obj && obj->is_object();
      }
      default:
        return false;
    }
  }

  bool has_field(const std::string &name) {
    switch (mode) {
      case Mode::Form: {
        return fields->contains(name);
      }
      case Mode::Slice:
        return {};
      case Mode::Json: {
        return is_object() && obj->contains(name);
      }
      default:
        return {};
    }
  }

  template <typename T>
  void add_field(const std::string &name, T &&arg) {
    processed_fields.insert(name);
    switch (mode) {
      case Mode::Form: {
        (*fields)[name] = MultipartFormDataValue::create_with_name(name, PSTRING() << std::move(arg));
        return;
      }
      case Mode::Slice: {
        UNREACHABLE();
        return;
      }
      case Mode::Json: {
        CHECK(is_object());
        (*obj)[name] = std::move(arg);
        return;
      }
      default:
        return;
    }
  }

  void add_subfield(const std::string &name) {
    processed_fields.insert(name);
    switch (mode) {
      case Mode::Form: {
        UNREACHABLE();
        return;
      }
      case Mode::Slice: {
        UNREACHABLE();
        return;
      }
      case Mode::Json: {
        CHECK(is_object());
        if (!obj->contains(name)) {
          (*obj)[name] = nlohmann::json::object();
        }
        return;
      }
      default:
        return;
    }
  }

  void del_field(const std::string &name) {
    switch (mode) {
      case Mode::Form: {
        fields->erase(name);
        return;
      }
      case Mode::Slice: {
        UNREACHABLE();
        return;
      }
      case Mode::Json: {
        CHECK(is_object());
        obj->erase(name);
        return;
      }
      default:
        return;
    }
  }

  td::optional<std::unique_ptr<CtxLevel>> get_subfield(const std::string &name) {
    switch (mode) {
      case Mode::Form: {
        auto it = fields->find(name);
        if (it == fields->end()) {
          return {};
        } else {
          return std::make_unique<CtxLevel>(&it->second, PSTRING() << path << "." << name);
        }
      }
      case Mode::Slice:
        return {};
      case Mode::Json: {
        if (!is_object()) {
          return {};
        }
        if (!obj->contains(name)) {
          return {};
        }
        return std::make_unique<CtxLevel>(&(*obj)[name], PSTRING() << path << "." << name);
      }
      default:
        return {};
    }
  }

  td::Status check_unprocessed_fields() {
    switch (mode) {
      case Mode::Form: {
        for (auto &[name, value] : *fields) {
          if (!processed_fields.contains(name)) {
            return td::Status::Error(ton::ErrorCode::protoviolation,
                                     PSTRING() << path << " has unknown field '" << name << "'");
          }
        }
        return td::Status::OK();
      } break;
      case Mode::Slice:
        return td::Status::OK();
      case Mode::Json: {
        if (!is_object()) {
          return td::Status::OK();
        }

        for (auto &[name, value] : obj->items()) {
          if (!processed_fields.contains(name)) {
            return td::Status::Error(ton::ErrorCode::protoviolation,
                                     PSTRING() << path << " has unknown field '" << name << "'");
          }
        }
        return td::Status::OK();
      } break;
      default:
        return td::Status::OK();
    };
  }

  bool is_array() const {
    return mode == Mode::Json && obj && obj->is_array();
  }
  template <typename F>
  td::Status iterate_array(F &&run) {
    if (!is_array()) {
      return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << path << " must be an array");
    }
    size_t idx = 0;
    for (auto &x : *obj) {
      TRY_STATUS(run(std::make_unique<CtxLevel>(&x, PSTRING() << path << "[" << (idx++) << "]")));
    }
    return td::Status::OK();
  }

  bool is_string() {
    switch (mode) {
      case Mode::Form: {
        return false;
      }
      case Mode::Slice: {
        return true;
      }
      case Mode::Json: {
        auto e = obj;
        return e && e->is_string();
      }
      default:
        return false;
    }
  }

  td::Result<std::string> get_string() {
    switch (mode) {
      case Mode::Form:
        return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << path << " must be a string");
      case Mode::Json: {
        auto e = obj;
        if (!e || !e->is_string()) {
          return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << path << " must be a string");
        }
        return e->get<std::string>();
      }
      case Mode::Slice: {
        return field->value;
      }
      default:
        return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << path << " must be a string");
    }
  }

  bool is_integer() {
    switch (mode) {
      case Mode::Form: {
        return false;
      }
      case Mode::Slice: {
        return true;
      }
      case Mode::Json: {
        auto e = obj;
        return e && e->is_number_integer();
      }
      default:
        return false;
    }
  }

  td::Result<td::int64> get_integer() {
    switch (mode) {
      case Mode::Form:
        return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << path << " must be an integer");
      case Mode::Slice: {
        auto R = td::to_integer_safe<td::int64>(field->value);
        if (R.is_error()) {
          return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << path << " must be an integer");
        } else {
          return R.move_as_ok();
        }
      }
      case Mode::Json: {
        auto e = obj;
        if (!e || !e->is_number_integer()) {
          return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << path << " must be an integer");
        }
        return e->get<td::int64>();
      }
      default:
        return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << path << " must be an integer");
    }
  }

  bool is_boolean() {
    switch (mode) {
      case Mode::Form: {
        return false;
      }
      case Mode::Slice: {
        return is_integer();
      }
      case Mode::Json: {
        auto e = obj;
        return e && e->is_boolean();
      }
      default:
        return false;
    }
  }

  td::Result<bool> get_boolean() {
    switch (mode) {
      case Mode::Form:
        return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << path << " must be a boolean");
      case Mode::Slice: {
        auto R = td::to_integer_safe<td::int64>(field->value);
        if (R.is_error()) {
          return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << path << " must be a boolean");
        } else {
          return (bool)R.move_as_ok();
        }
      }
      case Mode::Json: {
        auto e = obj;
        if (!e || !e->is_boolean()) {
          return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << path << " must be a boolean");
        }
        return e->get<bool>();
      }
      default:
        return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << path << " must be an integer");
    }
  }

  bool is_double() {
    switch (mode) {
      case Mode::Form: {
        return false;
      }
      case Mode::Slice: {
        return true;
      }
      case Mode::Json: {
        auto e = obj;
        return e && e->is_number();
      }
      default:
        return false;
    }
  }

  td::Result<double> get_double() {
    switch (mode) {
      case Mode::Form:
        return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << path << " must be a double");
      case Mode::Slice: {
        return td::to_double(field->value);
      }
      case Mode::Json: {
        auto e = obj;
        if (!e || !e->is_number()) {
          return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << path << " must be a double");
        }
        return e->get<double>();
      }
      default:
        return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << path << " must be a double");
    }
  }
};

struct Ctx {
  std::vector<std::unique_ptr<CtxLevel>> levels;

  std::string model;
  td::int64 default_max_tokens;
  td::int64 max_tokens;

  Ctx(nlohmann::json *obj) {
    levels.emplace_back(std::make_unique<CtxLevel>(obj, ""));
  }
  Ctx(MultipartFormDataMap *fields) {
    levels.emplace_back(std::make_unique<CtxLevel>(fields, ""));
  }

  auto &back() const {
    return *levels.back();
  }

  const std::string &path() const {
    return back().path;
  }

  bool is_object() const {
    return back().is_object();
  }

  template <typename F>
  td::Status process_obj_field(const std::string &name, bool is_required, F &&run) {
    auto v = back().get_subfield(name);
    if (!v) {
      if (is_required) {
        return td::Status::Error(ton::ErrorCode::protoviolation,
                                 PSTRING() << "'" << path() << "' must have a field '" << name << "'");
      }
      return td::Status::OK();
    }

    back().processed_fields.insert(name);
    levels.push_back(std::move(v.value()));
    TRY_STATUS(run(*this));
    TRY_STATUS(check_unprocessed_fields());
    levels.pop_back();
    return td::Status::OK();
  }

  td::Status check_unprocessed_fields() {
    return back().check_unprocessed_fields();
  }

  void set_field_as_processed(std::string v) {
    back().processed_fields.insert(std::move(v));
  }

  bool is_array() const {
    return back().is_array();
  }

  template <typename F>
  td::Status process_array(bool is_required, F &&run) {
    if (!back().exists()) {
      if (is_required) {
        return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << path() << " must exist");
      }
      return td::Status::OK();
    }
    return back().iterate_array([&](std::unique_ptr<CtxLevel> obj) {
      levels.push_back(std::move(obj));
      TRY_STATUS(run(*this));
      TRY_STATUS(check_unprocessed_fields());
      levels.pop_back();
      return td::Status::OK();
    });
  }

  bool is_string() {
    return back().is_string();
  }

  td::Result<std::string> get_string() {
    return back().get_string();
  }

  bool is_integer() {
    return back().is_integer();
  }

  td::Result<td::int64> get_integer() {
    return back().get_integer();
  }

  bool is_boolean() {
    return back().is_boolean();
  }

  td::Result<bool> get_boolean() {
    return back().get_boolean();
  }

  bool is_double() {
    return back().is_double();
  }
  td::Result<double> get_double() {
    return back().get_double();
  }

  bool has_field(const std::string &name) {
    return back().has_field(name);
  }
  template <typename T>
  void add_field(const std::string &name, T &&arg) {
    return back().add_field(name, std::move(arg));
  }
  void add_subfield(const std::string &name) {
    return back().add_subfield(name);
  }
  void del_field(const std::string &name) {
    return back().del_field(name);
  }
};

static td::Status process_string(Ctx &ctx) {
  if (!ctx.is_string()) {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << ctx.path() << " must be a string");
  }
  TRY_STATUS(ctx.get_string());
  return td::Status::OK();
}

static td::Status process_string_hex(Ctx &ctx) {
  if (!ctx.is_string()) {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << ctx.path() << " must be a string");
  }
  TRY_RESULT(v, ctx.get_string());
  if (v.size() % 2 != 0) {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << ctx.path() << " must be a hex string");
  }
  for (auto c : v) {
    bool is_hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    if (!is_hex) {
      return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << ctx.path() << " must be a hex string");
    }
  }
  return td::Status::OK();
}

static td::Status process_string_url_or_b64(Ctx &ctx) {
  if (!ctx.is_string()) {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << ctx.path() << " must be a string");
  }
  TRY_STATUS(ctx.get_string());
  return td::Status::OK();
}

static td::Status process_double(Ctx &ctx) {
  if (!ctx.is_double()) {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << ctx.path() << " must be a number");
  }
  return td::Status::OK();
}

static td::Status process_integer(Ctx &ctx) {
  if (!ctx.is_integer()) {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << ctx.path() << " must be an integer");
  }
  return td::Status::OK();
}

static td::Status process_boolean(Ctx &ctx) {
  if (!ctx.is_boolean()) {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << ctx.path() << " must be a boolean");
  }
  return td::Status::OK();
}

template <typename F>
static td::Status process_string_or_array(Ctx &ctx, F &&run) {
  if (ctx.is_array()) {
    return ctx.process_array(true, std::move(run));
  }
  return process_string(ctx);
}

template <typename F>
static td::Status process_string_or_object(Ctx &ctx, F &&run) {
  if (ctx.is_object()) {
    return ctx.process_array(true, std::move(run));
  }
  return process_string(ctx);
}

static td::Status process_image_url(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("url", true, process_string_url_or_b64));
  TRY_STATUS(ctx.process_obj_field("detail", false, process_string));
  return td::Status::OK();
}

static td::Status process_content_part_text(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("text", true, process_string));
  return td::Status::OK();
}

static td::Status process_content_part_image(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("image", true, process_image_url));
  return td::Status::OK();
}

static td::Status process_content_part_audio(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("input_audio", true, [](Ctx &ctx) {
    TRY_STATUS(ctx.process_obj_field("format", true, process_string));
    TRY_STATUS(ctx.process_obj_field("data", true, process_string_hex));
    return td::Status::OK();
  }));
  return td::Status::OK();
}

static td::Status process_content_part_file(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("file", true, [](Ctx &ctx) {
    TRY_STATUS(ctx.process_obj_field("file_data", false, process_string_hex));
    TRY_STATUS(ctx.process_obj_field("file_id", false, process_string));
    TRY_STATUS(ctx.process_obj_field("filename", false, process_string));
    return td::Status::OK();
  }));
  return td::Status::OK();
}

static td::Status process_content_part_refusal(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("refusal", true, process_string));
  return td::Status::OK();
}

static td::Status process_content_part(Ctx &ctx) {
  std::string type;
  TRY_STATUS(ctx.process_obj_field("type", true, [&type](Ctx &ctx) {
    TRY_RESULT_ASSIGN(type, ctx.get_string());
    if (type.size() >= 128) {
      return td::Status::Error(ton::ErrorCode::protoviolation,
                               PSTRING() << ctx.path() << " must be a string not longer than 128 chars");
    }
    return td::Status::OK();
  }));

  bool is_text = type.find("text") != type.npos;
  bool is_image = type.find("image") != type.npos;
  bool is_audio = type.find("audio") != type.npos;
  bool is_file = type.find("file") != type.npos;
  bool is_refusal = ctx.has_field("refusal");
  if (is_refusal) {
    return process_content_part_refusal(ctx);
  } else if (is_text) {
    return process_content_part_text(ctx);
  } else if (is_image) {
    return process_content_part_image(ctx);
  } else if (is_audio) {
    return process_content_part_audio(ctx);
  } else if (is_file) {
    return process_content_part_file(ctx);
  } else {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << ctx.path() << " has unknown type " << type);
  }
}

static td::Status process_developer_message(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("content", true,
                                   [](Ctx &ctx) { return process_string_or_array(ctx, process_content_part); }));
  TRY_STATUS(ctx.process_obj_field("name", false, process_string));
  return td::Status::OK();
}

static td::Status process_system_message(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("content", true,
                                   [](Ctx &ctx) { return process_string_or_array(ctx, process_content_part); }));
  TRY_STATUS(ctx.process_obj_field("name", false, process_string));
  return td::Status::OK();
}

static td::Status process_user_message(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("content", true,
                                   [](Ctx &ctx) { return process_string_or_array(ctx, process_content_part); }));
  TRY_STATUS(ctx.process_obj_field("name", false, process_string));
  return td::Status::OK();
}

static td::Status process_function_call(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("arguments", true, process_string));
  TRY_STATUS(ctx.process_obj_field("name", true, process_string));
  return td::Status::OK();
}

static td::Status process_function_tool_call(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("id", true, process_string));
  TRY_STATUS(ctx.process_obj_field("function", true, process_function_call));
  return td::Status::OK();
}

static td::Status process_custom_tool_call(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("id", true, process_string));
  TRY_STATUS(ctx.process_obj_field("custom", true, [](Ctx &ctx) {
    TRY_STATUS(ctx.process_obj_field("input", true, process_string));
    TRY_STATUS(ctx.process_obj_field("name", true, process_string));
    return td::Status::OK();
  }));
  return td::Status::OK();
}

static td::Status process_tool_call(Ctx &ctx) {
  std::string type;
  TRY_STATUS(ctx.process_obj_field("type", true, [&type](Ctx &ctx) {
    TRY_RESULT_ASSIGN(type, ctx.get_string());
    return td::Status::OK();
  }));
  if (type == "function") {
    return process_function_tool_call(ctx);
  } else if (type == "custom") {
    return process_custom_tool_call(ctx);
  } else {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << ctx.path() << " has unknown type " << type);
  }
}

static td::Status process_assistant_message(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("audio", false, [](Ctx &ctx) {
    TRY_STATUS(ctx.process_obj_field("id", true, process_string));
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("content", false,
                                   [](Ctx &ctx) { return process_string_or_array(ctx, process_content_part); }));
  TRY_STATUS(ctx.process_obj_field("function_call", false, process_function_call));
  TRY_STATUS(ctx.process_obj_field("name", false, process_string));
  TRY_STATUS(ctx.process_obj_field("refusal", false, process_string));
  TRY_STATUS(ctx.process_obj_field("tool_calls", false, [](Ctx &ctx) {
    TRY_STATUS(ctx.process_array(false, process_tool_call));
    return td::Status::OK();
  }));
  return td::Status::OK();
}

static td::Status process_tool_message(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("tool_call_id", true, process_string));
  TRY_STATUS(ctx.process_obj_field("content", true,
                                   [](Ctx &ctx) { return process_string_or_array(ctx, process_content_part); }));
  return td::Status::OK();
}

static td::Status process_function_message(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("name", true, process_string));
  TRY_STATUS(ctx.process_obj_field("content", true, process_string));
  return td::Status::OK();
}

static td::Status process_message(Ctx &ctx) {
  std::string role;
  TRY_STATUS(ctx.process_obj_field("role", true, [&role](Ctx &ctx) {
    TRY_RESULT_ASSIGN(role, ctx.get_string());
    return td::Status::OK();
  }));

  if (role == "developer") {
    return process_developer_message(ctx);
  } else if (role == "system") {
    return process_system_message(ctx);
  } else if (role == "user") {
    return process_user_message(ctx);
  } else if (role == "assistant") {
    return process_assistant_message(ctx);
  } else if (role == "tool") {
    return process_tool_message(ctx);
  } else if (role == "function") {
    return process_function_message(ctx);
  } else {
    return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << ctx.path() << " has unknown role " << role);
  }
}

static td::Status process_static_content(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("type", true, process_string));
  TRY_STATUS(ctx.process_obj_field("content", true,
                                   [](Ctx &ctx) { return process_string_or_array(ctx, process_content_part); }));
  return td::Status::OK();
}

static td::Status process_stream_options(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("include_obfuscation", false, process_boolean));
  TRY_STATUS(ctx.process_obj_field("include_usage", false, process_boolean));
  return td::Status::OK();
}

static td::Status process_chat_template_kwargs(Ctx &ctx) {
  TRY_STATUS(ctx.process_obj_field("enable_thinking", false, process_boolean));
  return td::Status::OK();
}

static td::Status process_chat_completions(Ctx &ctx) {
  std::string model;
  td::int64 max_completion_tokens = 0;
  bool has_stream = false;

  TRY_STATUS(ctx.process_obj_field("messages", true, [](Ctx &ctx) {
    TRY_STATUS(ctx.process_array(true, process_message));
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("model", true, [&model](Ctx &ctx) {
    TRY_RESULT_ASSIGN(model, ctx.get_string());
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("audio", false, [](Ctx &ctx) {
    TRY_STATUS(ctx.process_obj_field("format", true, process_string));
    TRY_STATUS(ctx.process_obj_field("voice", true, [](Ctx &ctx) {
      return process_string_or_object(ctx, [](Ctx &ctx) {
        TRY_STATUS(ctx.process_obj_field("id", true, process_string));
        return td::Status::OK();
      });
    }));
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("frequency_penalty", false, process_double));
  if (false) {
    TRY_STATUS(ctx.process_obj_field("function_call", false, [](Ctx &ctx) {
      return process_string_or_object(ctx, [](Ctx &ctx) {
        TRY_STATUS(ctx.process_obj_field("name", true, process_string));
        return td::Status::OK();
      });
    }));
  }
  if (false) {
    TRY_STATUS(ctx.process_obj_field("function", false, [](Ctx &ctx) {
      return process_string_or_object(ctx, [](Ctx &ctx) {
        TRY_STATUS(ctx.process_obj_field("name", true, process_string));
        TRY_STATUS(ctx.process_obj_field("description", false, process_string));
        TRY_STATUS(ctx.process_obj_field("parameters", false, [](Ctx &ctx) { return td::Status::OK(); }));
        return td::Status::OK();
      });
    }));
  }
  if (false) {
    TRY_STATUS(ctx.process_obj_field("logit_bias", false, [](Ctx &ctx) { return td::Status::OK(); }));
  }
  TRY_STATUS(ctx.process_obj_field("logprobs", false, process_boolean));
  TRY_STATUS(ctx.process_obj_field("max_completion_tokens", false, [&max_completion_tokens](Ctx &ctx) {
    TRY_RESULT_ASSIGN(max_completion_tokens, ctx.get_integer());
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("max_tokens", false, [&max_completion_tokens](Ctx &ctx) {
    TRY_RESULT_ASSIGN(max_completion_tokens, ctx.get_integer());
    return td::Status::OK();
  }));
  if (false) {
    TRY_STATUS(ctx.process_obj_field("metadata", false, [](Ctx &ctx) { return td::Status::OK(); }));
  }
  TRY_STATUS(
      ctx.process_obj_field("modalities", false, [](Ctx &ctx) { return ctx.process_array(false, process_string); }));
  TRY_STATUS(ctx.process_obj_field("n", false, process_integer));
  TRY_STATUS(ctx.process_obj_field("parallel_tool_calls", false, process_boolean));
  TRY_STATUS(ctx.process_obj_field("prediction", false, process_static_content));
  TRY_STATUS(ctx.process_obj_field("presence_penalty", false, process_double));
  TRY_STATUS(ctx.process_obj_field("prompt_cache_key", false, process_string));
  TRY_STATUS(ctx.process_obj_field("prompt_cache_retention", false, process_string));
  TRY_STATUS(ctx.process_obj_field("reasoning_effort", false, process_string));
  TRY_STATUS(ctx.process_obj_field("response_format", false, [](Ctx &ctx) {  // do not validate
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("safety_identifier", false, process_string));
  TRY_STATUS(ctx.process_obj_field("seed", false, process_integer));
  TRY_STATUS(ctx.process_obj_field("service_tier", false, process_integer));
  TRY_STATUS(ctx.process_obj_field("stop", false, [](Ctx &ctx) {
    TRY_STATUS(ctx.process_array(false, process_string));
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("store", false, process_boolean));
  TRY_STATUS(ctx.process_obj_field("stream", false, [&has_stream](Ctx &ctx) {
    TRY_RESULT_ASSIGN(has_stream, ctx.get_boolean());
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("stream_options", false, process_stream_options));
  TRY_STATUS(ctx.process_obj_field("temperature", false, process_double));
  if (false) {
    TRY_STATUS(ctx.process_obj_field("tool_choice", false, [](Ctx &ctx) { return td::Status::OK(); }));
  }
  if (false) {
    TRY_STATUS(ctx.process_obj_field(
        "tools", false, [](Ctx &ctx) { return ctx.process_array(false, [](Ctx &ctx) { return td::Status::OK(); }); }));
  }
  TRY_STATUS(ctx.process_obj_field("top_logprobs", false, process_integer));
  TRY_STATUS(ctx.process_obj_field("top_p", false, process_double));
  TRY_STATUS(ctx.process_obj_field("user", false, process_string));
  TRY_STATUS(ctx.process_obj_field("verbosity", false, process_string));
  if (false) {
    TRY_STATUS(ctx.process_obj_field("web_search_options", false, [](Ctx &ctx) { return td::Status::OK(); }));
  }
  TRY_STATUS(ctx.process_obj_field("skip_special_tokens", false, process_boolean)); /* non-standard */
  TRY_STATUS(ctx.process_obj_field("chat_template_kwargs", false, process_chat_template_kwargs));

  if (has_stream) {
    ctx.add_subfield("stream_options");
    TRY_STATUS(ctx.process_obj_field("stream_options", false, [](Ctx &ctx) {
      ctx.add_field("include_usage", true);
      return td::Status::OK();
    }));
  } else {
    ctx.del_field("stream_options");
  }

  if (max_completion_tokens <= 0 && ctx.default_max_tokens > 0) {
    max_completion_tokens = ctx.default_max_tokens;
  }
  if (max_completion_tokens > 0) {
    ctx.add_field("max_tokens", max_completion_tokens);
    ctx.add_field("max_completion_tokens", max_completion_tokens);
    ctx.max_tokens = max_completion_tokens;
  }
  ctx.model = model;

  return td::Status::OK();
}

static td::Status process_completions(Ctx &ctx) {
  std::string model;
  td::int64 max_completion_tokens = 0;
  bool has_stream = false;

  TRY_STATUS(ctx.process_obj_field("model", true, [&model](Ctx &ctx) {
    TRY_RESULT_ASSIGN(model, ctx.get_string());
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("prompt", true, [](Ctx &ctx) {
    TRY_STATUS(process_string_or_array(ctx, process_string));
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("best_of", false, process_integer));
  TRY_STATUS(ctx.process_obj_field("echo", false, process_boolean));
  TRY_STATUS(ctx.process_obj_field("frequency_penalty", false, process_double));
  if (false) {
    TRY_STATUS(ctx.process_obj_field("logit_bias", false, [](Ctx &ctx) { return td::Status::OK(); }));
  }
  TRY_STATUS(ctx.process_obj_field("logprobs", false, process_boolean));
  TRY_STATUS(ctx.process_obj_field("max_completion_tokens", false, [&max_completion_tokens](Ctx &ctx) {
    TRY_RESULT_ASSIGN(max_completion_tokens, ctx.get_integer());
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("max_tokens", false, [&max_completion_tokens](Ctx &ctx) {
    TRY_RESULT_ASSIGN(max_completion_tokens, ctx.get_integer());
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("n", false, process_integer));
  TRY_STATUS(ctx.process_obj_field("presence_penalty", false, process_double));
  TRY_STATUS(ctx.process_obj_field("seed", false, process_integer));
  TRY_STATUS(ctx.process_obj_field("stop", false, [](Ctx &ctx) {
    TRY_STATUS(ctx.process_array(false, process_string));
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("stream", false, [&has_stream](Ctx &ctx) {
    TRY_RESULT_ASSIGN(has_stream, ctx.get_boolean());
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("stream_options", false, process_stream_options));
  TRY_STATUS(ctx.process_obj_field("suffix", false, process_string));
  TRY_STATUS(ctx.process_obj_field("temperature", false, process_double));
  TRY_STATUS(ctx.process_obj_field("top_p", false, process_double));
  TRY_STATUS(ctx.process_obj_field("user", false, process_string));
  TRY_STATUS(ctx.process_obj_field("skip_special_tokens", false, process_boolean)); /* non-standard */

  if (has_stream) {
    ctx.add_subfield("stream_options");
    TRY_STATUS(ctx.process_obj_field("stream_options", false, [](Ctx &ctx) {
      ctx.add_field("include_usage", true);
      return td::Status::OK();
    }));
  } else {
    ctx.del_field("stream_options");
  }

  if (max_completion_tokens <= 0 && ctx.default_max_tokens > 0) {
    max_completion_tokens = ctx.default_max_tokens;
  }
  if (max_completion_tokens > 0) {
    ctx.add_field("max_tokens", max_completion_tokens);
    ctx.add_field("max_completion_tokens", max_completion_tokens);
    ctx.max_tokens = max_completion_tokens;
  }
  ctx.model = model;

  return td::Status::OK();
}

static td::Status process_create_audio_transcription(Ctx &ctx) {
  std::string model;
  td::int64 max_completion_tokens = 0;
  bool has_stream = false;

  TRY_STATUS(ctx.process_obj_field("model", true, [&model](Ctx &ctx) {
    TRY_RESULT_ASSIGN(model, ctx.get_string());
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("file", true, [](Ctx &ctx) {
    TRY_STATUS(process_string_or_array(ctx, process_string));
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("chunking_strategy", false, [](Ctx &ctx) {
    return process_string_or_object(ctx, [](Ctx &ctx) {
      TRY_STATUS(ctx.process_obj_field("type", true, process_string));
      TRY_STATUS(ctx.process_obj_field("prefix_padding_ms", false, process_integer));
      TRY_STATUS(ctx.process_obj_field("silence_duration_ms", false, process_integer));
      TRY_STATUS(ctx.process_obj_field("threshold", false, process_double));
      return td::Status::OK();
    });
  }));
  TRY_STATUS(
      ctx.process_obj_field("include", false, [](Ctx &ctx) { return ctx.process_array(false, process_string); }));
  TRY_STATUS(ctx.process_obj_field("known_speaker_names", false,
                                   [](Ctx &ctx) { return ctx.process_array(false, process_string); }));
  TRY_STATUS(ctx.process_obj_field("known_speaker_references", false,
                                   [](Ctx &ctx) { return ctx.process_array(false, process_string); }));
  TRY_STATUS(ctx.process_obj_field("language", false, process_string));
  TRY_STATUS(ctx.process_obj_field("max_completion_tokens", false, [&max_completion_tokens](Ctx &ctx) {
    TRY_RESULT_ASSIGN(max_completion_tokens, ctx.get_integer());
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("max_tokens", false, [&max_completion_tokens](Ctx &ctx) {
    TRY_RESULT_ASSIGN(max_completion_tokens, ctx.get_integer());
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("prompt", false, process_string));
  TRY_STATUS(ctx.process_obj_field("response_format", false, [](Ctx &ctx) {
    TRY_RESULT(value, ctx.get_string());
    if (value != "json") {
      return td::Status::Error(ton::ErrorCode::error, "response_format must be 'json'");
    }
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("stream", false, [&has_stream](Ctx &ctx) {
    TRY_RESULT_ASSIGN(has_stream, ctx.get_boolean());
    return td::Status::OK();
  }));
  TRY_STATUS(ctx.process_obj_field("stream_options", false, process_stream_options));
  TRY_STATUS(ctx.process_obj_field("temperature", false, process_double));
  TRY_STATUS(ctx.process_obj_field("timestamp_granularities", false,
                                   [](Ctx &ctx) { return ctx.process_array(false, process_string); }));

  if (max_completion_tokens <= 0 && ctx.default_max_tokens > 0) {
    max_completion_tokens = ctx.default_max_tokens;
  }
  if (max_completion_tokens > 0) {
    ctx.add_field("max_tokens", max_completion_tokens);
    ctx.max_tokens = max_completion_tokens;
  }
  ctx.model = model;

  return td::Status::OK();
}

td::Result<td::Bits256> parse_bits256_from_json(td::Slice val) {
  td::Bits256 res;
  if (val.size() == 32) {
    res.as_slice().copy_from(val);
  } else if (val.size() == 64) {
    TRY_RESULT(v, td::hex_decode(val));
    res.as_slice().copy_from(v);
  } else if (val.size() == 44) {
    TRY_RESULT(v, td::base64_decode(val));
    res.as_slice().copy_from(v);
  } else {
    return td::Status::Error(ton::ErrorCode::protoviolation, "public_key bad length");
  }
  return res;
}

td::Result<td::BufferSlice> validate_decrypt_request(std::string url, td::Slice content_type, td::BufferSlice request,
                                                     std::string *model, td::int64 *max_tokens,
                                                     const td::Bits256 &private_key, td::Bits256 *client_public_key) {
  auto p = url.find('/');
  if (p != std::string::npos) {
    url = url.substr(p);
  }

  td::int32 is_json;
  if (url == "/v1/chat/completions") {
    is_json = true;
  } else if (url == "/v1/completions") {
    is_json = true;
  } else if (url == "/v1/audio/transcriptions") {
    is_json = false;
  } else {
    return td::Status::Error(ton::ErrorCode::protoviolation, "unsupported method");
  }

  nlohmann::json b;
  MultipartFormDataMap fields;

  TRY_RESULT(ctx, [&]() -> td::Result<Ctx> {
    if (is_json) {
      TRY_RESULT_ASSIGN(b, parse_json(request.as_slice()));
      TRY_STATUS(decrypt_json(b, private_key, *client_public_key, false, true));
      return Ctx(&b);
    } else {
      TRY_RESULT_ASSIGN(fields, parse_multipart_form(content_type, request.as_slice()));
      TRY_STATUS(decrypt_form(fields, private_key, *client_public_key, false, true));
      return Ctx(&fields);
    }
  }());
  for (const auto &s : json_encryption_related_str_fields) {
    ctx.set_field_as_processed(s);
  }

  ctx.default_max_tokens = max_tokens ? *max_tokens : 0;

  if (url == "/v1/chat/completions") {
    TRY_STATUS(process_chat_completions(ctx));
  } else if (url == "/v1/completions") {
    TRY_STATUS(process_completions(ctx));
  } else if (url == "/v1/audio/transcriptions") {
    TRY_STATUS(process_create_audio_transcription(ctx));
  } else {
    return td::Status::Error(ton::ErrorCode::protoviolation, "unsupported method");
  }

  TRY_STATUS(ctx.check_unprocessed_fields());

  if (model) {
    *model = ctx.model;
  }
  if (max_tokens) {
    *max_tokens = ctx.max_tokens;
  }
  if (is_json) {
    return td::BufferSlice(b.dump());
  } else {
    TRY_RESULT(v, store_multipart_form(content_type, fields));
    return td::BufferSlice{v};
  }
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

std::string AnswerPostprocessor::add_next_answer_slice(td::Slice event) {
  last_ += event.str();

  td::StringBuilder sb;
  // SSE streams from vLLM start with "data:"; anything else is a single-JSON reply.
  size_t first_ch = last_.find_first_not_of(" \t\r\n");
  bool sse_mode = first_ch != std::string::npos && last_[first_ch] == 'd';

  std::stringstream ss(last_);
  size_t pos = 0;
  while (true) {
    nlohmann::json v;
    if (sse_mode) {
      size_t end = last_.find("\n\n", pos);
      if (end == std::string::npos) {
        break;
      }
      std::string line = last_.substr(pos, end - pos);
      pos = end + 2;
      if (line.rfind("data:", 0) != 0) {
        continue;
      }
      std::string payload = line.substr(5);
      if (!payload.empty() && payload.front() == ' ') {
        payload.erase(payload.begin());
      }
      if (payload == "[DONE]") {
        sb << "data: [DONE]\n\n";
        continue;
      }
      try {
        v = nlohmann::json::parse(payload);
      } catch (...) {
        sb << "data: " << payload << "\n\n";
        continue;
      }
    } else {
      try {
        ss >> v;
        pos = ss.tellg();
      } catch (...) {
        break;
      }
    }

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

    if (!sender_private_key_.is_zero()) {
      encrypt_json(v, sender_private_key_, receiver_public_key_, false);
    }

    if (sse_mode) {
      sb << "data: " << v.dump() << "\n\n";
    } else {
      sb << v.dump() << "\n";
    }
  }
  last_ = last_.substr(pos);
  return sb.as_cslice().str();
}

ton::tl_object_ptr<cocoon_api::tokensUsed> AnswerPostprocessor::usage() {
  auto prompt_tokens_adj = adjust_tokens(prompt_tokens_ - cached_tokens_, coef_, prompt_tokens_mult_);
  auto cached_tokens_adj = adjust_tokens(cached_tokens_, coef_, cached_tokens_mult_);
  auto completion_tokens_adj = adjust_tokens(completion_tokens_ - reasoning_tokens_, coef_, completion_tokens_mult_);
  auto reasoning_tokens_adj = adjust_tokens(reasoning_tokens_, coef_, reasoning_tokens_mult_);
  return ton::create_tl_object<cocoon_api::tokensUsed>(
      prompt_tokens_adj, cached_tokens_adj, completion_tokens_adj, reasoning_tokens_adj,
      prompt_tokens_adj + cached_tokens_adj + completion_tokens_adj + reasoning_tokens_adj);
}

std::string AnswerPostprocessor::finalize() {
  if (last_.empty()) {
    return "";
  }
  // SSE tail without a terminating "\n\n": synthesize one so the final event is parsed.
  size_t first_ch = last_.find_first_not_of(" \t\r\n");
  if (first_ch != std::string::npos && last_[first_ch] == 'd') {
    std::string tail = std::move(last_);
    last_.clear();
    return add_next_answer_slice(tail + "\n\n");
  }
  if (last_.size() >= 4) {
    LOG(ERROR) << "worker request: unprocessed data in answer: bytes=" << last_.size();
  }
  return "";
}

void encrypt_json(nlohmann::json &v, const td::Bits256 &private_key, const td::Bits256 &public_key,
                  bool client_to_worker) {
  v["is_encrypted"] = "v1";

  td::Ed25519::PrivateKey pk(td::SecureString{private_key.as_slice()});
  td::Bits256 pub;
  pub.as_slice().copy_from(pk.get_public_key().move_as_ok().as_octet_string().as_slice());
  v["sender_public_key"] = td::hex_encode(pub.as_slice());
  v["receiver_public_key"] = td::hex_encode(public_key.as_slice());

  char buf[32];
  td::Random::secure_bytes(td::MutableSlice(buf, 32));
  auto encryption_nonce = td::base64_encode(td::Slice(buf, 32));
  v["encryption_nonce"] = encryption_nonce;

  auto shared_secret =
      generate_shared_secret(private_key, public_key, pub, encryption_nonce, client_to_worker).move_as_ok();
  encrypt_all_strings(v, shared_secret.as_slice());
}

td::Status decrypt_json(nlohmann::json &v, const td::Bits256 &private_key, td::Bits256 &public_key,
                        bool check_public_key, bool client_to_worker) {
  bool is_encrypted = v.contains("is_encrypted");
  if (!is_encrypted) {
    if (!private_key.is_zero()) {
      return td::Status::Error(ton::ErrorCode::error, "encryption key is provided, but request is unencrypted");
    } else {
      if (check_public_key) {
        if (!public_key.is_zero()) {
          return td::Status::Error(ton::ErrorCode::error, "public key is provided, but request is unencrypted");
        }
      } else {
        public_key = td::Bits256::zero();
      }
    }
    return td::Status::OK();
  }

  for (const auto &s : json_encryption_related_str_fields) {
    if (!v.contains(s) || !v[s].is_string()) {
      return td::Status::Error(ton::ErrorCode::error, "not all encryption-related fields are present");
    }
  }

  TRY_RESULT(sender_public_key, parse_bits256_from_json(v["sender_public_key"].get<std::string>()));
  TRY_RESULT(receiver_public_key, parse_bits256_from_json(v["receiver_public_key"].get<std::string>()));
  auto encryption_nonce = v["encryption_nonce"].get<std::string>();

  if (private_key.is_zero()) {
    return td::Status::Error(ton::ErrorCode::error, "cannot find private key for an encrypted request");
  }
  if (check_public_key) {
    if (public_key != sender_public_key) {
      return td::Status::Error(ton::ErrorCode::error, "sender public key mismatch");
    }
  } else {
    public_key = sender_public_key;
  }
  TRY_RESULT(shared_secret, generate_shared_secret(private_key, sender_public_key, receiver_public_key,
                                                   encryption_nonce, client_to_worker));
  TRY_STATUS(decrypt_all_strings(v, shared_secret.as_slice()));
  return td::Status::OK();
}

td::Status decrypt_form(MultipartFormDataMap &v, const td::Bits256 &private_key, td::Bits256 &public_key,
                        bool check_public_key, bool client_to_worker) {
  bool is_encrypted = v.contains("is_encrypted");
  if (!is_encrypted) {
    if (!private_key.is_zero()) {
      return td::Status::Error(ton::ErrorCode::error, "encryption key is provided, but request is unencrypted");
    } else {
      if (check_public_key) {
        if (!public_key.is_zero()) {
          return td::Status::Error(ton::ErrorCode::error, "public key is provided, but request is unencrypted");
        }
      } else {
        public_key = td::Bits256::zero();
      }
    }
    return td::Status::OK();
  }

  for (const auto &s : json_encryption_related_str_fields) {
    if (!v.contains(s)) {
      return td::Status::Error(ton::ErrorCode::error, "not all encryption-related fields are present");
    }
  }

  TRY_RESULT(sender_public_key, parse_bits256_from_json(v["sender_public_key"].value));
  TRY_RESULT(receiver_public_key, parse_bits256_from_json(v["receiver_public_key"].value));
  auto encryption_nonce = v["encryption_nonce"].value;

  if (private_key.is_zero()) {
    return td::Status::Error(ton::ErrorCode::error, "cannot find private key for an encrypted request");
  }
  if (check_public_key) {
    if (public_key != sender_public_key) {
      return td::Status::Error(ton::ErrorCode::error, "sender public key mismatch");
    }
  } else {
    public_key = sender_public_key;
  }
  TRY_RESULT(shared_secret, generate_shared_secret(private_key, sender_public_key, receiver_public_key,
                                                   encryption_nonce, client_to_worker));
  TRY_STATUS(decrypt_all_strings(v, shared_secret.as_slice()));
  return td::Status::OK();
}

td::Result<std::string> validate_client_json_request(td::Slice url, td::Slice content_type, td::Slice request,
                                                     std::string *model, td::int64 *max_tokens,
                                                     td::int32 *max_coefficient, double *timeout, bool *enable_debug,
                                                     td::Bits256 *request_guid, td::Bits256 *receiver_public_key) {
  TRY_RESULT(b, parse_json(request));
  if (!b.contains("model") || !b["model"].is_string()) {
    return td::Status::Error(ton::ErrorCode::protoviolation, "missing field 'model'");
  }
  if (model) {
    *model = b["model"].get<std::string>();
  }
  if (b.contains("max_completion_tokens")) {
    if (!b["max_completion_tokens"].is_number_unsigned()) {
      return td::Status::Error(ton::ErrorCode::protoviolation,
                               "field 'max_completion_tokens' must be positive integer");
    }
    if (max_tokens) {
      *max_tokens = b["max_completion_tokens"].get<td::int32>();
    }
  } else if (b.contains("max_tokens")) {
    if (!b["max_tokens"].is_number_unsigned()) {
      return td::Status::Error(ton::ErrorCode::protoviolation, "field 'max_tokens' must be positive integer");
    }
    if (max_tokens) {
      *max_tokens = b["max_tokens"].get<td::int32>();
    }
  } else {
    if (max_tokens) {
      b["max_tokens"] = *max_tokens;
    }
  }
  if (b.contains("max_coefficient")) {
    if (!b["max_coefficient"].is_number_unsigned()) {
      return td::Status::Error(ton::ErrorCode::protoviolation, "field 'max_coefficient' must be non-negative integer");
    }
    if (max_coefficient) {
      *max_coefficient = b["max_coefficient"].get<td::int32>();
    }
    b.erase("max_coefficient");
  }
  if (b.contains("timeout")) {
    if (!b["timeout"].is_number()) {
      return td::Status::Error(ton::ErrorCode::protoviolation, "field 'timeout' must be a number");
    }
    if (timeout) {
      *timeout = b["timeout"].get<double>();
    }
    b.erase("timeout");
  }
  if (b.contains("enable_debug")) {
    if (!b["enable_debug"].is_boolean()) {
      return td::Status::Error(ton::ErrorCode::protoviolation, "field 'enable_debug' must be a boolean");
    }
    if (enable_debug) {
      *enable_debug = b["enable_debug"].get<bool>();
    }
    b.erase("enable_debug");
  }
  if (b.contains("request_guid")) {
    if (!b["request_guid"].is_string()) {
      return td::Status::Error(ton::ErrorCode::protoviolation, "field 'request_guid' must be a string");
    }
    if (request_guid) {
      *request_guid = td::sha256_bits256(b["request_guid"].get<std::string>());
    }
    b.erase("request_guid");
  }
  if (b.contains("receiver_public_key")) {
    if (!b["receiver_public_key"].is_string()) {
      return td::Status::Error(ton::ErrorCode::protoviolation, "field 'receiver_public_key' must be a string");
    }
    if (receiver_public_key) {
      TRY_RESULT_ASSIGN(*receiver_public_key, parse_bits256_from_json(b["receiver_public_key"].get<std::string>()));
    }
  }
  return b.dump();
}

td::Result<std::string> validate_client_form_data_request(td::Slice url, td::Slice content_type, td::Slice request,
                                                          std::string *model, td::int64 *max_tokens,
                                                          td::int32 *max_coefficient, double *timeout,
                                                          bool *enable_debug, td::Bits256 *request_guid,
                                                          td::Bits256 *receiver_public_key) {
  TRY_RESULT(b, parse_multipart_form(content_type, request));
  if (!b.contains("model")) {
    return td::Status::Error(ton::ErrorCode::protoviolation, "missing field 'model'");
  }
  if (model) {
    *model = b["model"].value;
  }
  if (b.contains("max_completion_tokens")) {
    TRY_RESULT(val, td::to_integer_safe<td::uint32>(b["max_completion_tokens"].value));
    if (max_tokens) {
      *max_tokens = val;
    }
  } else if (b.contains("max_tokens")) {
    TRY_RESULT(val, td::to_integer_safe<td::uint32>(b["max_tokens"].value));
    if (max_tokens) {
      *max_tokens = val;
    }
  } else {
    if (max_tokens) {
      b["max_tokens"] = MultipartFormDataValue::create_with_name("max_tokens", PSTRING() << *max_tokens);
    }
  }
  if (b.contains("max_coefficient")) {
    TRY_RESULT(val, td::to_integer_safe<td::uint32>(b["max_coefficient"].value));
    if (max_coefficient) {
      *max_coefficient = val;
    }
    b.erase("max_coefficient");
  }
  if (b.contains("timeout")) {
    auto val = td::to_double(b["timeout"].value);
    if (timeout) {
      *timeout = val;
    }
    b.erase("timeout");
  }
  if (b.contains("enable_debug")) {
    TRY_RESULT(val, td::to_integer_safe<td::uint32>(b["enable_debug"].value));
    if (enable_debug) {
      *enable_debug = val;
    }
    b.erase("enable_debug");
  }
  if (b.contains("request_guid")) {
    if (request_guid) {
      *request_guid = td::sha256_bits256(b["request_guid"].value);
    }
    b.erase("request_guid");
  }
  if (b.contains("receiver_public_key")) {
    if (receiver_public_key) {
      TRY_RESULT_ASSIGN(*receiver_public_key, parse_bits256_from_json(b["receiver_public_key"].value));
    }
  }

  TRY_RESULT(v, store_multipart_form(content_type, b));
  return v;
}

td::Result<std::string> validate_client_request(td::Slice url, td::Slice content_type, td::Slice request,
                                                std::string *model, td::int64 *max_tokens, td::int32 *max_coefficient,
                                                double *timeout, bool *enable_debug, td::Bits256 *request_guid,
                                                td::Bits256 *receiver_public_key) {
  if (url == "/v1/chat/completions") {
    return validate_client_json_request(std::move(url), content_type, std::move(request), model, max_tokens,
                                        max_coefficient, timeout, enable_debug, request_guid, receiver_public_key);
  } else if (url == "/v1/completions") {
    return validate_client_json_request(std::move(url), content_type, std::move(request), model, max_tokens,
                                        max_coefficient, timeout, enable_debug, request_guid, receiver_public_key);
  } else if (url == "/v1/audio/transcriptions") {
    return validate_client_form_data_request(std::move(url), content_type, std::move(request), model, max_tokens,
                                             max_coefficient, timeout, enable_debug, request_guid, receiver_public_key);
  } else {
    return td::Status::Error(ton::ErrorCode::protoviolation, "unsupported method");
  }
}

}  // namespace cocoon
