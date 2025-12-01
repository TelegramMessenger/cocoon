// Minimal TDX/SGX helpers and SSL context

#include "cocoon/openssl_utils.h"
#include "cocoon/tdx.h"
#include "cocoon/AttestationCache.h"
#include "td/utils/as.h"
#include "td/utils/misc.h"
#include "td/utils/filesystem.h"
#include "td/utils/format.h"
#include "td/utils/StringBuilder.h"
#include "td/utils/tl_helpers.h"
#include "td/net/utils.h"

#include <functional>
#include <limits>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#if TD_TDX_ATTESTATION
#include "sgx_dcap_quoteverify.h"
#include "sgx_default_quote_provider.h"
#include "sgx_quote_5.h"
#include "tdx_attest.h"
#endif

#include "td/utils/Time.h"
#include "td/utils/Variant.h"
#include <cstring>
#include <mutex>
#include <optional>
#include <unordered_map>

// Constants
static constexpr size_t ED25519_PUBLIC_KEY_SIZE = 32;
static constexpr long SECONDS_PER_DAY = 86400L;
static constexpr int MAX_CERT_CHAIN_DEPTH = 1;
static constexpr size_t MAX_OID_BUFFER_SIZE = 128;
static constexpr size_t MAX_CERT_NAME_BUFFER_SIZE = 1024;
static constexpr int WARNING_THROTTLE_SECONDS = 60 * 5;
static constexpr size_t MAX_TDX_QUOTE_EXTENSION_SIZE = 32 * 1024;  // 32 KiB hard cap for quote in X.509 extension

// TODO: Replace OBJ_* calls with NID_* equivalents for better performance
namespace td {
template <size_t N>
td::StringBuilder &operator<<(td::StringBuilder &sb, const td::UInt<N> &value) {
  return sb << td::hex_encode(value.as_slice());
}
// Helper operator<< for UInt types
template <size_t N, class T>
td::StringBuilder &operator<<(td::StringBuilder &sb, const std::array<T, N> &value) {
  return sb << td::format::as_array(value);
}
}  // namespace td

namespace tdx {
td::StringBuilder &operator<<(td::StringBuilder &sb, const TdxAttestationData &data) {
  sb << "TDX attestation data\n";
  auto p = [&](td::Slice name, auto value) {
    sb << name << ": " << td::Slice(td::hex_encode(value.as_slice())) << "\n";
  };
  p("MRTD", data.mr_td);
  p("MRCONFIGID", data.mr_config_id);
  p("MROWNER", data.mr_owner);
  p("MROWNERCONFIG", data.mr_owner_config);
  for (int i = 0; i < 4; i++) {
    p(PSLICE() << "RTMR" << i, data.rtmr[i]);
  }
  p("REPORTDATA", data.reportdata);
  return sb;
}
td::StringBuilder &operator<<(td::StringBuilder &sb, const SgxAttestationData &data) {
  sb << "SGX attestation data\n";
  return sb;
}
td::StringBuilder &operator<<(td::StringBuilder &sb, const AttestationData &data) {
  if (data.is_empty()) {
    sb << "No attestation data";
  } else if (data.is_tdx()) {
    sb << "COLLATERAL_ROOT_HASH: " << data.collateral_root_hash() << "\n";
    sb << data.as_tdx();
    sb << "image_hash: " << td::Slice(td::hex_encode(data.image_hash().as_slice())) << "\n";
  } else if (data.is_sgx()) {
    sb << "COLLATERAL_ROOT_HASH: " << data.collateral_root_hash() << "\n";
    sb << data.as_sgx();
    sb << "image_hash: " << td::Slice(td::hex_encode(data.image_hash().as_slice())) << "\n";
  } else {
    sb << "Unknown attestation data";
  }
  return sb;
}

td::StringBuilder &operator<<(td::StringBuilder &sb, const PolicyConfig &config) {
  sb << "{\n";

  if (!config.allowed_mrtd.empty()) {
    sb << "  allowed_mrtd: " << config.allowed_mrtd << "\n";
  }

  if (!config.allowed_rtmr.empty()) {
    sb << "  allowed_rtmr: " << config.allowed_rtmr << "\n";
  }

  if (!config.allowed_image_hashes.empty()) {
    sb << "  allowed_image_hashes: " << config.allowed_image_hashes << "\n";
  }

  if (!config.allowed_collateral_root_hashes.empty()) {
    sb << "  allowed_collateral_root_hashes: " << config.allowed_collateral_root_hashes << "\n";
  }

  if (config.allowed_mrtd.empty() && config.allowed_rtmr.empty() && config.allowed_image_hashes.empty() &&
      config.allowed_collateral_root_hashes.empty()) {
    sb << "  (default - no restrictions)\n";
  }

  sb << "}";
  return sb;
}

td::UInt256 AttestationData::image_hash() const {
  // TODO(now): use some well defined serialization, e.g. tl serialization
  if (is_empty()) {
    return td::UInt256{};
  }

  if (is_tdx()) {
    TdxAttestationData tdx_copy = as_tdx();
    tdx_copy.reportdata = td::UInt512{};

    auto serialized = td::serialize(tdx_copy);

    td::UInt256 hash;
    td::sha256(serialized, hash.as_mutable_slice());
    return hash;
  }

  if (is_sgx()) {
    SgxAttestationData sgx_copy = as_sgx();
    sgx_copy.reportdata = td::UInt512{};

    auto serialized = td::serialize(sgx_copy);

    td::UInt256 hash;
    td::sha256(serialized, hash.as_mutable_slice());
    return hash;
  }

  return td::UInt256{};
}
td::UInt512 UserClaims::to_hash() const {
  auto str = serialize();
  td::UInt512 hash;
  td::sha512(str, hash.as_mutable_slice());
  return hash;
}

std::string UserClaims::serialize() const {
  // TODO: proper serialization with structured format
  // For now, use a more efficient approach than string concatenation
  auto key_slice = public_key.to_secure_string().as_slice();
  return std::string(key_slice.data(), key_slice.size());
}

// (Removed string printers for attestation data)

// Fake TDX for tests
struct FakeTdxInterface : public TdxInterface {
  td::Result<AttestationData> get_data(const Quote &quote) const override {
    TdxAttestationData data{};

    if (quote.raw_quote.size() != data.reportdata.as_mutable_slice().size()) {
      return td::Status::Error(PSLICE() << "Invalid fake quote size: expected "
                                        << data.reportdata.as_mutable_slice().size() << " bytes, got "
                                        << quote.raw_quote.size());
    }

    data.reportdata.as_mutable_slice().copy_from(quote.raw_quote);
    return data;
  }

  td::Result<AttestationData> get_data(const Report &report) const override {
    TdxAttestationData data{};

    if (report.raw_report.size() != data.reportdata.as_mutable_slice().size()) {
      return td::Status::Error(PSLICE() << "Invalid fake report size: expected "
                                        << data.reportdata.as_mutable_slice().size() << " bytes, got "
                                        << report.raw_report.size());
    }

    data.reportdata.as_mutable_slice().copy_from(report.raw_report);
    return data;
  }

  td::Result<Quote> make_quote(td::UInt512 user_claims_hash) const override {
    return Quote{user_claims_hash.as_slice().str()};
  }

  td::Result<Report> make_report(td::UInt512 user_claims_hash) const override {
    return Report{user_claims_hash.as_slice().str()};
  }

  td::Result<AttestationData> validate_quote(const Quote &quote) const override {
    TRY_RESULT(attestation_data, get_data(quote));
    return attestation_data;
  }
};
// Error TDX for platforms without support
struct ErrorTdxInterface : public TdxInterface {
  td::Result<AttestationData> get_data(const Quote &quote) const override {
    return td::Status::Error("TDX is not supported on this platform");
  }

  td::Result<AttestationData> get_data(const Report &report) const override {
    return td::Status::Error("TDX is not supported on this platform");
  }

  td::Result<Quote> make_quote(td::UInt512 user_claims_hash) const override {
    return td::Status::Error("TDX is not supported on this platform");
  }

  td::Result<Report> make_report(td::UInt512 user_claims_hash) const override {
    return td::Status::Error("TDX is not supported on this platform");
  }

  td::Result<AttestationData> validate_quote(const Quote &quote) const override {
    return td::Status::Error("TDX is not supported on this platform");
  }
};

#if TD_TDX_ATTESTATION
td::CSlice to_str(quote3_error_t result) {
  switch (result) {
    case SGX_QL_SUCCESS:
      return "SGX_QL_SUCCESS";
    case SGX_QL_ERROR_UNEXPECTED:
      return "SGX_QL_ERROR_UNEXPECTED";
    case SGX_QL_ERROR_INVALID_PARAMETER:
      return "SGX_QL_ERROR_INVALID_PARAMETER";
    case SGX_QL_ERROR_OUT_OF_MEMORY:
      return "SGX_QL_ERROR_OUT_OF_MEMORY";
    case SGX_QL_ERROR_ECDSA_ID_MISMATCH:
      return "SGX_QL_ERROR_ECDSA_ID_MISMATCH";
    case SGX_QL_PATHNAME_BUFFER_OVERFLOW_ERROR:
      return "SGX_QL_PATHNAME_BUFFER_OVERFLOW_ERROR";
    case SGX_QL_FILE_ACCESS_ERROR:
      return "SGX_QL_FILE_ACCESS_ERROR";
    case SGX_QL_ERROR_STORED_KEY:
      return "SGX_QL_ERROR_STORED_KEY";
    case SGX_QL_ERROR_PUB_KEY_ID_MISMATCH:
      return "SGX_QL_ERROR_PUB_KEY_ID_MISMATCH";
    case SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME:
      return "SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME";
    case SGX_QL_ATT_KEY_BLOB_ERROR:
      return "SGX_QL_ATT_KEY_BLOB_ERROR";
    case SGX_QL_UNSUPPORTED_ATT_KEY_ID:
      return "SGX_QL_UNSUPPORTED_ATT_KEY_ID";
    case SGX_QL_UNSUPPORTED_LOADING_POLICY:
      return "SGX_QL_UNSUPPORTED_LOADING_POLICY";
    case SGX_QL_INTERFACE_UNAVAILABLE:
      return "SGX_QL_INTERFACE_UNAVAILABLE";
    case SGX_QL_PLATFORM_LIB_UNAVAILABLE:
      return "SGX_QL_PLATFORM_LIB_UNAVAILABLE";
    case SGX_QL_ATT_KEY_NOT_INITIALIZED:
      return "SGX_QL_ATT_KEY_NOT_INITIALIZED";
    case SGX_QL_ATT_KEY_CERT_DATA_INVALID:
      return "SGX_QL_ATT_KEY_CERT_DATA_INVALID";
    case SGX_QL_NO_PLATFORM_CERT_DATA:
      return "SGX_QL_NO_PLATFORM_CERT_DATA";
    case SGX_QL_OUT_OF_EPC:
      return "SGX_QL_OUT_OF_EPC";
    case SGX_QL_ERROR_REPORT:
      return "SGX_QL_ERROR_REPORT";
    case SGX_QL_ENCLAVE_LOST:
      return "SGX_QL_ENCLAVE_LOST";
    case SGX_QL_INVALID_REPORT:
      return "SGX_QL_INVALID_REPORT";
    case SGX_QL_ENCLAVE_LOAD_ERROR:
      return "SGX_QL_ENCLAVE_LOAD_ERROR";
    case SGX_QL_UNABLE_TO_GENERATE_QE_REPORT:
      return "SGX_QL_UNABLE_TO_GENERATE_QE_REPORT";
    case SGX_QL_KEY_CERTIFCATION_ERROR:
      return "SGX_QL_KEY_CERTIFCATION_ERROR";
    case SGX_QL_NETWORK_ERROR:
      return "SGX_QL_NETWORK_ERROR";
    case SGX_QL_MESSAGE_ERROR:
      return "SGX_QL_MESSAGE_ERROR";
    case SGX_QL_NO_QUOTE_COLLATERAL_DATA:
      return "SGX_QL_NO_QUOTE_COLLATERAL_DATA";
    case SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED:
      return "SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED";
    case SGX_QL_QUOTE_FORMAT_UNSUPPORTED:
      return "SGX_QL_QUOTE_FORMAT_UNSUPPORTED";
    case SGX_QL_UNABLE_TO_GENERATE_REPORT:
      return "SGX_QL_UNABLE_TO_GENERATE_REPORT";
    case SGX_QL_QE_REPORT_INVALID_SIGNATURE:
      return "SGX_QL_QE_REPORT_INVALID_SIGNATURE";
    case SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT:
      return "SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT";
    case SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT:
      return "SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT";
    case SGX_QL_PCK_CERT_CHAIN_ERROR:
      return "SGX_QL_PCK_CERT_CHAIN_ERROR";
    case SGX_QL_TCBINFO_UNSUPPORTED_FORMAT:
      return "SGX_QL_TCBINFO_UNSUPPORTED_FORMAT";
    case SGX_QL_TCBINFO_MISMATCH:
      return "SGX_QL_TCBINFO_MISMATCH";
    case SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT:
      return "SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT";
    case SGX_QL_QEIDENTITY_MISMATCH:
      return "SGX_QL_QEIDENTITY_MISMATCH";
    case SGX_QL_TCB_OUT_OF_DATE:
      return "SGX_QL_TCB_OUT_OF_DATE";
    case SGX_QL_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED:
      return "SGX_QL_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED";
    case SGX_QL_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE:
      return "SGX_QL_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE";
    case SGX_QL_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE:
      return "SGX_QL_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE";
    case SGX_QL_QE_IDENTITY_OUT_OF_DATE:
      return "SGX_QL_QE_IDENTITY_OUT_OF_DATE";
    case SGX_QL_SGX_TCB_INFO_EXPIRED:
      return "SGX_QL_SGX_TCB_INFO_EXPIRED";
    case SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED:
      return "SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED";
    case SGX_QL_SGX_CRL_EXPIRED:
      return "SGX_QL_SGX_CRL_EXPIRED";
    case SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED:
      return "SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED";
    case SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED:
      return "SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED";
    case SGX_QL_PCK_REVOKED:
      return "SGX_QL_PCK_REVOKED";
    case SGX_QL_TCB_REVOKED:
      return "SGX_QL_TCB_REVOKED";
    case SGX_QL_TCB_CONFIGURATION_NEEDED:
      return "SGX_QL_TCB_CONFIGURATION_NEEDED";
    case SGX_QL_UNABLE_TO_GET_COLLATERAL:
      return "SGX_QL_UNABLE_TO_GET_COLLATERAL";
    case SGX_QL_ERROR_INVALID_PRIVILEGE:
      return "SGX_QL_ERROR_INVALID_PRIVILEGE";
    case SGX_QL_NO_QVE_IDENTITY_DATA:
      return "SGX_QL_NO_QVE_IDENTITY_DATA";
    case SGX_QL_CRL_UNSUPPORTED_FORMAT:
      return "SGX_QL_CRL_UNSUPPORTED_FORMAT";
    case SGX_QL_QEIDENTITY_CHAIN_ERROR:
      return "SGX_QL_QEIDENTITY_CHAIN_ERROR";
    case SGX_QL_TCBINFO_CHAIN_ERROR:
      return "SGX_QL_TCBINFO_CHAIN_ERROR";
    case SGX_QL_ERROR_QVL_QVE_MISMATCH:
      return "SGX_QL_ERROR_QVL_QVE_MISMATCH";
    case SGX_QL_TCB_SW_HARDENING_NEEDED:
      return "SGX_QL_TCB_SW_HARDENING_NEEDED";
    case SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED:
      return "SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED";
    case SGX_QL_UNSUPPORTED_MODE:
      return "SGX_QL_UNSUPPORTED_MODE";
    case SGX_QL_NO_DEVICE:
      return "SGX_QL_NO_DEVICE";
    case SGX_QL_SERVICE_UNAVAILABLE:
      return "SGX_QL_SERVICE_UNAVAILABLE";
    case SGX_QL_NETWORK_FAILURE:
      return "SGX_QL_NETWORK_FAILURE";
    case SGX_QL_SERVICE_TIMEOUT:
      return "SGX_QL_SERVICE_TIMEOUT";
    case SGX_QL_ERROR_BUSY:
      return "SGX_QL_ERROR_BUSY";
    case SGX_QL_UNKNOWN_MESSAGE_RESPONSE:
      return "SGX_QL_UNKNOWN_MESSAGE_RESPONSE";
    case SGX_QL_PERSISTENT_STORAGE_ERROR:
      return "SGX_QL_PERSISTENT_STORAGE_ERROR";
    case SGX_QL_ERROR_MESSAGE_PARSING_ERROR:
      return "SGX_QL_ERROR_MESSAGE_PARSING_ERROR";
    case SGX_QL_PLATFORM_UNKNOWN:
      return "SGX_QL_PLATFORM_UNKNOWN";
    case SGX_QL_UNKNOWN_API_VERSION:
      return "SGX_QL_UNKNOWN_API_VERSION";
    case SGX_QL_CERTS_UNAVAILABLE:
      return "SGX_QL_CERTS_UNAVAILABLE";
    case SGX_QL_QVEIDENTITY_MISMATCH:
      return "SGX_QL_QVEIDENTITY_MISMATCH";
    case SGX_QL_QVE_OUT_OF_DATE:
      return "SGX_QL_QVE_OUT_OF_DATE";
    case SGX_QL_PSW_NOT_AVAILABLE:
      return "SGX_QL_PSW_NOT_AVAILABLE";
    case SGX_QL_COLLATERAL_VERSION_NOT_SUPPORTED:
      return "SGX_QL_COLLATERAL_VERSION_NOT_SUPPORTED";
    case SGX_QL_TDX_MODULE_MISMATCH:
      return "SGX_QL_TDX_MODULE_MISMATCH";
    case SGX_QL_QEIDENTITY_NOT_FOUND:
      return "SGX_QL_QEIDENTITY_NOT_FOUND";
    case SGX_QL_TCBINFO_NOT_FOUND:
      return "SGX_QL_TCBINFO_NOT_FOUND";
    case SGX_QL_INTERNAL_SERVER_ERROR:
      return "SGX_QL_INTERNAL_SERVER_ERROR";
    case SGX_QL_SUPPLEMENTAL_DATA_VERSION_NOT_SUPPORTED:
      return "SGX_QL_SUPPLEMENTAL_DATA_VERSION_NOT_SUPPORTED";
    case SGX_QL_ROOT_CA_UNTRUSTED:
      return "SGX_QL_ROOT_CA_UNTRUSTED";
    case SGX_QL_TCB_NOT_SUPPORTED:
      return "SGX_QL_TCB_NOT_SUPPORTED";
    case SGX_QL_CONFIG_INVALID_JSON:
      return "SGX_QL_CONFIG_INVALID_JSON";
    case SGX_QL_RESULT_INVALID_SIGNATURE:
      return "SGX_QL_RESULT_INVALID_SIGNATURE";
    case SGX_QL_QAEIDENTITY_MISMATCH:
      return "SGX_QL_QAEIDENTITY_MISMATCH";
    case SGX_QL_QAE_OUT_OF_DATE:
      return "SGX_QL_QAE_OUT_OF_DATE";
    case SGX_QL_QUOTE_HASH_MISMATCH:
      return "SGX_QL_QUOTE_HASH_MISMATCH";
    case SGX_QL_REPORT_DATA_MISMATCH:
      return "SGX_QL_REPORT_DATA_MISMATCH";
    default:
      return "UNKNOWN_QUOTE3_ERROR";
  }
}

td::CSlice to_str(sgx_ql_qv_result_t result) {
  switch (result) {
    case TEE_QV_RESULT_OK:
      return "TEE_QV_RESULT_OK";
    case TEE_QV_RESULT_CONFIG_NEEDED:
      return "TEE_QV_RESULT_CONFIG_NEEDED";
    case TEE_QV_RESULT_OUT_OF_DATE:
      return "TEE_QV_RESULT_OUT_OF_DATE";
    case TEE_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
      return "TEE_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED";
    case TEE_QV_RESULT_INVALID_SIGNATURE:
      return "TEE_QV_RESULT_INVALID_SIGNATURE";
    case TEE_QV_RESULT_REVOKED:
      return "TEE_QV_RESULT_REVOKED";
    case TEE_QV_RESULT_UNSPECIFIED:
      return "TEE_QV_RESULT_UNSPECIFIED";
    case TEE_QV_RESULT_SW_HARDENING_NEEDED:
      return "TEE_QV_RESULT_SW_HARDENING_NEEDED";
    case TEE_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
      return "TEE_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED";
    case TEE_QV_RESULT_TD_RELAUNCH_ADVISED:
      return "TEE_QV_RESULT_TD_RELAUNCH_ADVISED";
    case TEE_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED:
      return "TEE_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED";
    case TEE_QV_RESULT_MAX:
      return "TEE_QL_QV_RESULT_MAX";
    default:
      return "UNKNOWN_QV_RESULT";
  }
}

td::CSlice to_str(tdx_attest_error_t result) {
  switch (result) {
    case TDX_ATTEST_SUCCESS:
      return "TDX_ATTEST_SUCCESS";
    case TDX_ATTEST_ERROR_UNEXPECTED:
      return "TDX_ATTEST_ERROR_UNEXPECTED";
    case TDX_ATTEST_ERROR_INVALID_PARAMETER:
      return "TDX_ATTEST_ERROR_INVALID_PARAMETER";
    case TDX_ATTEST_ERROR_OUT_OF_MEMORY:
      return "TDX_ATTEST_ERROR_OUT_OF_MEMORY";
    case TDX_ATTEST_ERROR_VSOCK_FAILURE:
      return "TDX_ATTEST_ERROR_VSOCK_FAILURE";
    case TDX_ATTEST_ERROR_REPORT_FAILURE:
      return "TDX_ATTEST_ERROR_REPORT_FAILURE";
    case TDX_ATTEST_ERROR_EXTEND_FAILURE:
      return "TDX_ATTEST_ERROR_EXTEND_FAILURE";
    case TDX_ATTEST_ERROR_NOT_SUPPORTED:
      return "TDX_ATTEST_ERROR_NOT_SUPPORTED";
    case TDX_ATTEST_ERROR_QUOTE_FAILURE:
      return "TDX_ATTEST_ERROR_QUOTE_FAILURE";
    case TDX_ATTEST_ERROR_BUSY:
      return "TDX_ATTEST_ERROR_BUSY";
    case TDX_ATTEST_ERROR_DEVICE_FAILURE:
      return "TDX_ATTEST_ERROR_DEVICE_FAILURE";
    case TDX_ATTEST_ERROR_INVALID_RTMR_INDEX:
      return "TDX_ATTEST_ERROR_INVALID_RTMR_INDEX";
    case TDX_ATTEST_ERROR_UNSUPPORTED_ATT_KEY_ID:
      return "TDX_ATTEST_ERROR_UNSUPPORTED_ATT_KEY_ID";
    default:
      return "UNKNOWN_TDX_ATTEST_ERROR";
  }
}

// TEE (Trusted Execution Environment) type constants
static constexpr td::uint32 TEE_TYPE_SGX = 0x00000000;
static constexpr td::uint32 TEE_TYPE_TDX = 0x00000081;

// Quote body type constants
static constexpr td::uint16 BODY_SGX_ENCLAVE_REPORT_TYPE = 1;
static constexpr td::uint16 BODY_TD_REPORT10_TYPE = 2;  // TDX 1.0
static constexpr td::uint16 BODY_TD_REPORT15_TYPE = 3;  // TDX 1.5

// Quote version constants
static constexpr td::uint16 QUOTE_VERSION_3 = 3;
static constexpr td::uint16 QUOTE_VERSION_4 = 4;
static constexpr td::uint16 QUOTE_VERSION_5 = 5;

// TDX report constants
static constexpr td::uint8 TDX_REPORT_TYPE = 0x81;
static constexpr td::uint8 TDX_REPORT_SUBTYPE_CURRENT = 0;
static constexpr td::uint8 TDX_REPORT_VERSION_1_0 = 0;
static constexpr td::uint8 TDX_REPORT_VERSION_1_5 = 1;

static constexpr size_t TDX_TD_INFO_OFFSET = 512;
static constexpr size_t TDX_FULL_REPORT_SIZE = 1024;

#pragma pack(push, 1)
struct QuoteHeader {
  uint16_t version;               // Quote format version (3, 4, or 5)
  uint16_t attestation_key_type;  // Attestation Key type (2 = ECDSA-256)
  uint32_t tee_type;              // TEE type (0x00000000 for SGX, 0x00000081 for TDX)
  uint8_t reserved1[2];           // Reserved (must be 0)
  uint8_t reserved2[2];           // Reserved (must be 0)
  uint8_t qe_vendor_id[16];       // QE vendor ID (16-byte UUID)
  uint8_t user_data[20];          // User data (e.g., platform ID in first 16 bytes)
};

struct BodyHeader {
  uint16_t body_type;  // Type of quote body (1=SGX, 2=TDX1.0, 3=TDX1.5)
  uint32_t size;       // Size of the quote body in bytes
};

struct TdxQuoteBody10 {
  uint8_t tee_tcb_svn[16];      // TEE TCB Security Version Number
  td::UInt384 mr_seam;          // Measurement of SEAM module
  td::UInt384 mr_signer_seam;   // Measurement of SEAM signer
  uint8_t seam_attributes[8];   // SEAM attributes
  uint8_t td_attributes[8];     // TD attributes
  uint8_t xfam[8];              // Extended Feature Allow Mask
  td::UInt384 mr_td;            // Measurement of initial TD contents (MRTD)
  td::UInt384 mr_config_id;     // Software-defined config ID (MRCONFIGID)
  td::UInt384 mr_owner;         // TD owner identifier (MROWNER)
  td::UInt384 mr_owner_config;  // Owner-defined config (MROWNERCONFIG)
  td::UInt384 rtmr0;            // Runtime measurement register 0 (RTMR0)
  td::UInt384 rtmr1;            // Runtime measurement register 1 (RTMR1)
  td::UInt384 rtmr2;            // Runtime measurement register 2 (RTMR2)
  td::UInt384 rtmr3;            // Runtime measurement register 3 (RTMR3)
  td::UInt512 report_data;      // 64-byte REPORTDATA (user-defined report data)
};

struct TdxQuoteBody15 {
  TdxQuoteBody10 body10;      // All TDX 1.0 fields
  uint8_t tee_tcb_svn_2[16];  // Additional TEE TCB SVN for TDX 1.5
  td::UInt384 mr_service_td;  // Measurement of Service TD (new in TDX 1.5)
};

struct SgxQuoteBody {
  uint8_t cpu_svn[16];      // CPU Security Version Number
  uint32_t misc_select;     // Miscellaneous select bits
  uint8_t reserved1[28];    // Reserved space
  uint8_t attributes[16];   // Enclave attributes
  td::UInt256 mr_enclave;   // Measurement of enclave (MRENCLAVE)
  uint8_t reserved2[32];    // Reserved space
  td::UInt256 mr_signer;    // Measurement of enclave signer (MRSIGNER)
  uint8_t reserved3[96];    // Reserved space
  uint16_t isv_prod_id;     // Independent Software Vendor Product ID
  uint16_t isv_svn;         // Independent Software Vendor Security Version Number
  uint8_t reserved4[60];    // Reserved space
  td::UInt512 report_data;  // 64-byte REPORTDATA (user-defined report data)
};
#pragma pack(pop)

using QuoteBody = td::Variant<TdxQuoteBody10, TdxQuoteBody15, SgxQuoteBody>;

template <class T, class TT = T>
td::Result<TT> to(td::Slice s) {
  if (s.size() != sizeof(T)) {
    return td::Status::Error(PSLICE() << "Size mismatch in to(): got " << s.size() << " bytes, expected " << sizeof(T));
  }
  T result = td::as<T>(s.ubegin());
  return result;
}

template <class T, class TT = T>
td::Result<TT> cut(td::Slice &s) {
  if (s.size() < sizeof(T)) {
    return td::Status::Error(PSLICE() << "Insufficient data in cut(): got " << s.size() << " bytes, need at least "
                                      << sizeof(T));
  }
  T result = td::as<T>(s.ubegin());
  s.remove_prefix(sizeof(T));
  return result;
}

td::Result<QuoteBody> tdx_quote_to_body(td::Slice quote) {
  // Validate minimum quote size
  if (quote.size() < sizeof(QuoteHeader)) {
    return td::Status::Error(PSLICE() << "Quote too small: got " << quote.size() << " bytes, need at least "
                                      << sizeof(QuoteHeader));
  }

  // Parse quote header
  TRY_RESULT(header, cut<QuoteHeader>(quote));
  auto body_slice = quote;

  uint16_t version = header.version;
  LOG(INFO) << "Parsing quote v" << version << ", TEE 0x" << td::format::as_hex(header.tee_type);

  switch (version) {
    case QUOTE_VERSION_3: {
      if (header.tee_type == TEE_TYPE_SGX) {
        return cut<SgxQuoteBody, QuoteBody>(body_slice);
      }
      return td::Status::Error(PSLICE() << "Unsupported TEE type for quote version 3: 0x"
                                        << td::format::as_hex(header.tee_type));
    }

    case QUOTE_VERSION_4: {
      if (header.tee_type == TEE_TYPE_SGX) {
        return cut<SgxQuoteBody, QuoteBody>(body_slice);
      }
      if (header.tee_type == TEE_TYPE_TDX) {
        return cut<TdxQuoteBody10, QuoteBody>(body_slice);
      }
      return td::Status::Error(PSLICE() << "Unsupported TEE type for quote version 4: 0x"
                                        << td::format::as_hex(header.tee_type));
    }

    case QUOTE_VERSION_5: {
      TRY_RESULT(body_header, cut<BodyHeader>(body_slice));
      body_slice.truncate(body_header.size);

      // v5 body type and size

      switch (body_header.body_type) {
        case BODY_SGX_ENCLAVE_REPORT_TYPE:
          return to<SgxQuoteBody, QuoteBody>(body_slice);
        case BODY_TD_REPORT10_TYPE:
          return to<TdxQuoteBody10, QuoteBody>(body_slice);
        case BODY_TD_REPORT15_TYPE:
          return to<TdxQuoteBody15, QuoteBody>(body_slice);
        default:
          return td::Status::Error(PSLICE() << "Unsupported body type: " << body_header.body_type);
      }
    }

    default:
      return td::Status::Error(PSLICE() << "Unsupported quote version: " << version << " (expected 3, 4, or 5)");
  }
}

TdxAttestationData from_body(const TdxQuoteBody10 &body) {
  TdxAttestationData result{};
  result.mr_td = body.mr_td;
  result.mr_config_id = body.mr_config_id;
  result.mr_owner = body.mr_owner;
  result.mr_owner_config = body.mr_owner_config;

  // Copy the four RTMR values
  result.rtmr[0] = body.rtmr0;
  result.rtmr[1] = body.rtmr1;
  result.rtmr[2] = body.rtmr2;
  result.rtmr[3] = body.rtmr3;

  result.reportdata = body.report_data;

  return result;
}
TdxAttestationData from_body(const TdxQuoteBody15 &body) {
  return from_body(body.body10);
}
SgxAttestationData from_body(const SgxQuoteBody &body) {
  SgxAttestationData result{};
  result.mr_enclave = body.mr_enclave;
  result.reportdata = body.report_data;
  return result;
}
AttestationData from_body(const QuoteBody &body) {
  AttestationData res;
  body.visit([&](auto &inner_body) { res = AttestationData(from_body(inner_body)); });
  return res;
}

#pragma pack(push, 1)
struct TdxReportType {
  uint8_t type;      // Report type: 0x81 for TDX (0 for SGX)
  uint8_t sub_type;  // Report subtype (0 for current versions)
  uint8_t version;   // Report version (0 for TDX 1.0, 1 for TDX 1.5)
  uint8_t reserved;  // Reserved byte (must be 0 in current spec)
};

struct TdxReportMac {
  TdxReportType type_hdr;         // Report type header (4 bytes)
  uint8_t reserved1[12];          // Reserved for future use
  uint8_t cpu_svn[16];            // CPU Security Version Number
  td::UInt384 tee_tcb_info_hash;  // SHA384 hash of TEE TCB info section
  td::UInt384 tee_td_info_hash;   // SHA384 hash of TD Info section
  td::UInt512 report_data;        // User-provided REPORTDATA
  uint8_t reserved2[32];          // Reserved for future use
  uint8_t mac[32];                // 32-byte MAC tag for integrity verification
};

struct TdxTdInfo {
  uint8_t attributes[8];        // TD attributes (ATTRIBUTES field)
  uint8_t xfam[8];              // Extended Feature Allow Mask (XFAM)
  td::UInt384 mr_td;            // Measurement of initial TD contents (MRTD)
  td::UInt384 mr_config_id;     // Measurement of TD configuration (MRCONFIGID)
  td::UInt384 mr_owner;         // TD owner identifier (MROWNER)
  td::UInt384 mr_owner_config;  // TD owner configuration (MROWNERCONFIG)
  td::UInt384 rtmr0;            // Runtime Measurement Register 0 (RTMR0)
  td::UInt384 rtmr1;            // Runtime Measurement Register 1 (RTMR1)
  td::UInt384 rtmr2;            // Runtime Measurement Register 2 (RTMR2)
  td::UInt384 rtmr3;            // Runtime Measurement Register 3 (RTMR3)
  uint8_t reserved[112];        // Reserved space (includes SERVTD_HASH if version=1)
};
#pragma pack(pop)

td::Result<TdxAttestationData> parse_tdx_report(td::Slice report) {
  // Validate report size
  static_assert(TDX_TD_INFO_OFFSET <= TDX_FULL_REPORT_SIZE);
  if (report.size() < TDX_FULL_REPORT_SIZE) {
    return td::Status::Error(PSLICE() << "TDX report too small: got " << report.size() << " bytes, expected "
                                      << TDX_FULL_REPORT_SIZE);
  }

  // Parse the REPORTMAC structure (first 256 bytes)
  auto report_copy = report;
  TRY_RESULT(report_mac, cut<TdxReportMac>(report_copy));

  // Validate report type
  if (report_mac.type_hdr.type != TDX_REPORT_TYPE) {
    return td::Status::Error(PSLICE() << "Invalid TDX report type: got 0x"
                                      << td::format::as_hex(report_mac.type_hdr.type) << ", expected 0x"
                                      << td::format::as_hex(TDX_REPORT_TYPE));
  }

  if (report_mac.type_hdr.sub_type != TDX_REPORT_SUBTYPE_CURRENT) {
    return td::Status::Error(PSLICE() << "Unsupported TDX report subtype: " << int(report_mac.type_hdr.sub_type)
                                      << " (expected 0)");
  }

  uint8_t version = report_mac.type_hdr.version;
  if (version != TDX_REPORT_VERSION_1_0 && version != TDX_REPORT_VERSION_1_5) {
    return td::Status::Error(PSLICE() << "Unsupported TDX report version: " << int(version) << " (expected 0 or 1)");
  }

  // Parse the TD Info section (512 bytes at offset 512)
  TRY_RESULT(td_info, to<TdxTdInfo>(report.substr(TDX_TD_INFO_OFFSET)));

  // Build attestation data structure
  TdxAttestationData result;

  // Copy 48-byte measurement fields (td::UInt384 is 48-byte type)
  result.mr_td = td_info.mr_td;
  result.mr_config_id = td_info.mr_config_id;
  result.mr_owner = td_info.mr_owner;
  result.mr_owner_config = td_info.mr_owner_config;

  // Copy the four Runtime Measurement Registers (each 48 bytes)
  result.rtmr[0] = td_info.rtmr0;
  result.rtmr[1] = td_info.rtmr1;
  result.rtmr[2] = td_info.rtmr2;
  result.rtmr[3] = td_info.rtmr3;

  // Copy the 64-byte REPORTDATA from the MAC structure
  result.reportdata = report_mac.report_data;

  // Note: SERVTD_HASH is available in td_info.reserved[0..47] if version==1

  return result;
}

struct RealTdxInterface : public TdxInterface {
  td::Result<AttestationData> get_data(const Quote &quote) const override {
    LOG(INFO) << "Extracting data from quote (" << quote.raw_quote.size() << ")";
    TRY_RESULT(quote_body, tdx_quote_to_body(quote.raw_quote));
    return from_body(quote_body);
  }

  td::Result<AttestationData> get_data(const Report &report_raw) const override {
    if (report_raw.raw_report.size() != TDX_FULL_REPORT_SIZE) {
      return td::Status::Error(PSLICE() << "Invalid TDX report size: got " << report_raw.raw_report.size()
                                        << " bytes, expected " << TDX_FULL_REPORT_SIZE);
    }

    LOG(INFO) << "Parsing TDX report (" << report_raw.raw_report.size() << ")";

    // Cast to SGX report structure for compatibility with existing code
    auto *sgx_report = reinterpret_cast<const sgx_report2_t *>(report_raw.raw_report.data());

    // These pointers are used for accessing TEE info structures but not used in current implementation
    [[maybe_unused]] auto *tee_tcb_info_v1 = reinterpret_cast<const tee_tcb_info_t *>(sgx_report->tee_tcb_info);
    [[maybe_unused]] auto *tee_info_v1 = reinterpret_cast<const tee_info_t *>(sgx_report->tee_info);
    [[maybe_unused]] auto *tee_tcb_info_v1_5 = reinterpret_cast<const tee_tcb_info_v1_5_t *>(sgx_report->tee_tcb_info);
    [[maybe_unused]] auto *tee_info_v1_5 = reinterpret_cast<const tee_info_v1_5_t *>(sgx_report->tee_info);

    TRY_RESULT(tdx_attestation_data, parse_tdx_report(report_raw.raw_report));
    return tdx_attestation_data;
  }
  td::Result<Report> make_report(td::UInt512 user_claims_hash) const override {
    // Prepare report data structure
    tdx_report_data_t report_data;
    static_assert(TDX_REPORT_DATA_SIZE == 64, "TDX report data must be 64 bytes");
    static_assert(sizeof(report_data.d) == TDX_REPORT_DATA_SIZE, "Report data structure size mismatch");

    // Copy user claims hash into report data
    td::as<td::UInt512>(report_data.d) = user_claims_hash;

    // Generate TDX report
    tdx_report_t tdx_report;
    auto status = tdx_att_get_report(&report_data, &tdx_report);

    if (status != TDX_ATTEST_SUCCESS) {
      return td::Status::Error(PSLICE() << "Failed to generate TDX report: " << to_str(status) << " (0x"
                                        << td::format::as_hex(status) << ")");
    }

    return Report{td::Slice(tdx_report.d, TDX_REPORT_SIZE).str()};
  }

  td::Result<Quote> make_quote(td::UInt512 user_claims_hash) const override {
    // Prepare report data structure
    tdx_report_data_t report_data;
    static_assert(TDX_REPORT_DATA_SIZE == 64, "TDX report data must be 64 bytes");
    static_assert(sizeof(report_data.d) == TDX_REPORT_DATA_SIZE, "Report data structure size mismatch");

    // Copy user claims hash into report data
    td::as<td::UInt512>(report_data.d) = user_claims_hash;

    // Prepare quote generation parameters
    tdx_uuid_t selected_attestation_key_id{};
    uint8_t *quote_buffer = nullptr;
    uint32_t quote_size = 0;

    // Generate TDX quote
    auto status =
        tdx_att_get_quote(&report_data, nullptr, 0, &selected_attestation_key_id, &quote_buffer, &quote_size, 0);

    if (status != TDX_ATTEST_SUCCESS) {
      return td::Status::Error(PSLICE() << "Failed to generate TDX quote: " << to_str(status) << " (0x"
                                        << td::format::as_hex(status) << ")");
    }

    if (!quote_buffer || quote_size == 0) {
      return td::Status::Error("TDX quote generation returned null buffer or zero size");
    }

    // Copy quote data and free the allocated buffer
    Quote result{td::Slice(quote_buffer, quote_size).str()};
    tdx_att_free_quote(quote_buffer);

    return result;
  }

  td::Result<AttestationData> validate_quote(const Quote &quote) const override {
    // Prepare verification parameters
    uint32_t collateral_expiration_status = 0;
    time_t current_time = std::time(nullptr);
    sgx_ql_qv_result_t verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    quote3_error_t status = SGX_QL_SUCCESS;

    td::uint32 data_version = 0;
    td::uint32 data_size = 0;
    status = tee_get_supplemental_data_version_and_size(td::Slice(quote.raw_quote).ubegin(),
                                                        td::narrow_cast<uint32_t>(quote.raw_quote.size()),
                                                        &data_version, &data_size);
    if (status != SGX_QL_SUCCESS) {
      return td::Status::Error(PSLICE() << "Failed to get suppemental data size from collateral" << to_str(status)
                                        << " (0x" << td::format::as_hex(status) << ")");
    }
    if (data_size > (1 << 20)) {
      return td::Status::Error(PSLICE() << "Supplemental data size is too large: " << data_size);
    }
    std::vector<uint8_t> supplemental_data(data_size);
    tee_supp_data_descriptor_t supplemental_data_descriptor = {
        .major_version = 0,
        .data_size = data_size,
        .p_data = &supplemental_data[0],
    };

    // Verify the quote using Intel's quote verification library
    status = tee_verify_quote(td::Slice(quote.raw_quote).ubegin(), td::narrow_cast<uint32_t>(quote.raw_quote.size()),
                              nullptr,  // No additional collateral
                              current_time, &collateral_expiration_status, &verification_result, nullptr,
                              &supplemental_data_descriptor);

    if (status != SGX_QL_SUCCESS) {
      return td::Status::Error(PSLICE() << "Quote verification failed: " << to_str(status) << " (0x"
                                        << td::format::as_hex(status) << ")");
    }

    if (verification_result != SGX_QL_QV_RESULT_OK) {
      return td::Status::Error(PSLICE() << "Quote verification result invalid: " << to_str(verification_result)
                                        << " (0x" << td::format::as_hex(verification_result) << ")");
    }

    if (collateral_expiration_status != 0) {
      return td::Status::Error(PSLICE() << "Collateral expired or invalid (status=" << collateral_expiration_status
                                        << ")");
    }

    // Extract attestation data from the verified quote
    TRY_RESULT(attestation_data, get_data(quote));
    TRY_RESULT(supplemental, to<sgx_ql_qv_supplemental_t>(td::Slice(&supplemental_data[0], supplemental_data.size())))
    td::UInt384 root_key_id = td::as<td::UInt384>(supplemental.root_key_id);
    attestation_data.set_collateral_root_hash(root_key_id);
    return attestation_data;
  }
};
#endif

// TDX interface wrapper that adds caching layer
class CachedTdxInterface : public TdxInterface {
 public:
  CachedTdxInterface(TdxInterfaceRef inner, std::shared_ptr<cocoon::AttestationCache> cache)
      : inner_(std::move(inner)), cache_(std::move(cache)) {
  }

  td::Result<AttestationData> get_data(const Quote &quote) const override {
    return inner_->get_data(quote);
  }

  td::Result<AttestationData> get_data(const Report &report) const override {
    return inner_->get_data(report);
  }

  td::Result<Quote> make_quote(td::UInt512 user_claims_hash) const override {
    return inner_->make_quote(user_claims_hash);
  }

  td::Result<Report> make_report(td::UInt512 user_claims_hash) const override {
    return inner_->make_report(user_claims_hash);
  }

  td::Result<AttestationData> validate_quote(const Quote &quote) const override {
    auto quote_hash = hash_quote(quote);

    // Check cache first
    if (auto cached = cache_->get(quote_hash)) {
      LOG(DEBUG) << "Cache hit for quote hash " << td::hex_encode(quote_hash.as_slice());
      return cached->data;
    }

    // Cache miss - validate quote
    LOG(DEBUG) << "Cache miss for quote hash " << td::hex_encode(quote_hash.as_slice());
    TRY_RESULT(data, inner_->validate_quote(quote));

    // Store in cache
    cache_->put(quote_hash, data);

    return data;
  }

 private:
  TdxInterfaceRef inner_;
  std::shared_ptr<cocoon::AttestationCache> cache_;

  td::UInt256 hash_quote(const Quote &quote) const {
    td::UInt256 hash;
    td::sha256(td::Slice(quote.raw_quote), hash.as_mutable_slice());
    return hash;
  }
};

std::shared_ptr<const TdxInterface> TdxInterface::create_fake() {
  return std::make_shared<FakeTdxInterface>();
}

TdxInterfaceRef TdxInterface::add_cache(TdxInterfaceRef inner, std::shared_ptr<cocoon::AttestationCache> cache) {
  return std::make_shared<CachedTdxInterface>(std::move(inner), std::move(cache));
}

std::shared_ptr<const TdxInterface> TdxInterface::create() {
#if TD_TDX_ATTESTATION
  return std::make_shared<RealTdxInterface>();
#else
  return std::make_shared<ErrorTdxInterface>();
#endif
}
struct DefaultPolicy : public Policy {
  explicit DefaultPolicy(TdxInterfaceRef tdx, PolicyConfig config = {})
      : tdx_(std::move(tdx)), config_(std::move(config)) {
  }

  td::Result<AttestationData> validate(const Quote *quote, const UserClaims &user_claims) const override {
    // If there is no TDX interface, this is the "any" policy: allow without attestation
    if (!tdx_) {
      if (!config_.allowed_image_hashes.empty()) {
        return td::Status::Error("Image hash verification required but policy has no TDX interface");
      }
      return AttestationData{};
    }

    // TDX policy: always verify. Must have TDX interface and a quote to validate.
    if (!quote) {
      return td::Status::Error("TDX attestation quote is required by policy");
    }

    TRY_RESULT(attestation, tdx_->validate_quote(*quote));

    if (attestation.is_tdx()) {
      auto status = validate_tdx_attestation(attestation, user_claims);
      if (status.is_error()) {
        LOG(WARNING) << "Tdx validation failed: " << status.error() << "\nAttestation: " << attestation;
        return status;
      }
      return attestation;
    }

    // Explicitly reject SGX attestation for TLS policies. We never communicate with SGX over TLS.
    if (attestation.is_sgx()) {
      return td::Status::Error("SGX attestation is not accepted by this policy");
    }

    return td::Status::Error("Unknown attestation type");
  }

 private:
  TdxInterfaceRef tdx_;
  PolicyConfig config_;

  template <typename T>
  bool is_allowed(const std::vector<T> &allowed_values, const T &actual) const {
    if (allowed_values.empty()) {
      return true;
    }
    for (const auto &allowed : allowed_values) {
      if (actual == allowed) {
        return true;
      }
    }
    return false;
  }

  td::Status validate_tdx_attestation(const AttestationData &attestation_data, const UserClaims &user_claims) const {
    CHECK(attestation_data.is_tdx());
    const auto &attestation = attestation_data.as_tdx();

    // Verify reportdata matches user claims
    if (user_claims.to_hash() != attestation.reportdata) {
      return td::Status::Error("Report data mismatch (user claims don't match attestation)");
    }

    // Verify MRTD is in allowed list
    if (!is_allowed(config_.allowed_mrtd, attestation.mr_td)) {
      return td::Status::Error(PSLICE() << "MRTD not in policy allowlist: "
                                        << td::hex_encode(attestation.mr_td.as_slice()));
    }

    // Verify RTMR set is in allowed list
    if (!is_allowed(config_.allowed_rtmr, attestation.rtmr)) {
      return td::Status::Error("RTMR set not in policy allowlist");
    }

    // Verify image hash is in allowed list
    auto actual_hash = attestation_data.image_hash();
    if (!is_allowed(config_.allowed_image_hashes, actual_hash)) {
      return td::Status::Error(PSLICE() << "Image hash not in policy allowlist: "
                                        << td::hex_encode(actual_hash.as_slice()));
    }

    // Verify collateral root hash (Intel DCAP root key ID)
    auto collateral_hash = attestation_data.collateral_root_hash();
    if (!is_allowed(config_.allowed_collateral_root_hashes, collateral_hash)) {
      return td::Status::Error(PSLICE() << "Collateral root hash not in policy allowlist: "
                                        << td::hex_encode(collateral_hash.as_slice()));
    }

    return td::Status::OK();
  }
};

PolicyRef Policy::make(TdxInterfaceRef tdx) {
  return std::make_shared<DefaultPolicy>(std::move(tdx));
}

PolicyRef Policy::make(TdxInterfaceRef tdx, PolicyConfig config) {
  return std::make_shared<DefaultPolicy>(std::move(tdx), std::move(config));
}

/**
 * Generates a self-signed X.509 certificate with the given private key and configuration.
 *
 * @param private_key Ed25519 private key for signing the certificate
 * @param config Certificate configuration (subject, validity, extensions, etc.)
 * @return PEM-encoded certificate or error
 */
td::Result<std::string> generate_self_signed_cert(const tde2e_core::PrivateKey &private_key, const CertConfig &config) {
  // Validate configuration parameters
  if (config.country.size() != 2) {
    return td::Status::Error(
        PSLICE() << "Invalid country code: must be exactly 2 characters (ISO 3166-1 alpha-2), got '" << config.country
                 << "' (" << config.country.size() << " chars)");
  }

  if (config.common_name.empty()) {
    return td::Status::Error("Certificate common name cannot be empty");
  }

  if (config.validity_seconds == 0) {
    return td::Status::Error("Certificate validity must be positive");
  }

  constexpr td::uint32 MAX_VALIDITY_SECONDS = (1u << 30);
  if (config.validity_seconds > MAX_VALIDITY_SECONDS) {
    return td::Status::Error(PSLICE() << "Certificate validity too large: " << config.validity_seconds
                                      << " seconds (max: " << MAX_VALIDITY_SECONDS << ")");
  }

  // Convert private key to OpenSSL format
  auto public_key = private_key.to_public_key();
  auto private_key_bytes = private_key.to_secure_string();

  OPENSSL_MAKE_PTR(openssl_pkey,
                   EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, private_key_bytes.as_slice().ubegin(),
                                                private_key_bytes.size()),
                   EVP_PKEY_free, "Failed to create OpenSSL private key from Ed25519 key");

  // Create X.509 certificate structure
  OPENSSL_MAKE_PTR(certificate, X509_new(), X509_free, "Failed to create X509 certificate structure");

  // Set certificate serial number: 128-bit random
  unsigned char serial_bytes[16];
  OPENSSL_CHECK_OK(RAND_bytes(serial_bytes, sizeof(serial_bytes)), "Failed to generate random serial");
  OPENSSL_MAKE_PTR(serial_bn, BN_bin2bn(serial_bytes, sizeof(serial_bytes), nullptr), BN_free,
                   "Failed to create BIGNUM for serial");
  OPENSSL_CHECK_PTR(BN_to_ASN1_INTEGER(serial_bn.get(), X509_get_serialNumber(certificate.get())),
                    "Failed to set certificate serial number");

  // Set certificate validity period
  if (config.current_time.has_value()) {
    // Use provided time instead of system time
    td::uint32 not_before = config.current_time.value();

    // Check for overflow when adding validity_seconds
    if (not_before > std::numeric_limits<td::uint32>::max() - config.validity_seconds) {
      return td::Status::Error(PSLICE() << "Certificate validity would overflow: notBefore=" << not_before
                                        << " + validity_seconds=" << config.validity_seconds);
    }
    td::uint32 not_after = not_before + config.validity_seconds;

    OPENSSL_MAKE_PTR(asn1_not_before, ASN1_TIME_set(nullptr, not_before), ASN1_TIME_free,
                     "Failed to create ASN1_TIME for notBefore");
    OPENSSL_MAKE_PTR(asn1_not_after, ASN1_TIME_set(nullptr, not_after), ASN1_TIME_free,
                     "Failed to create ASN1_TIME for notAfter");

    OPENSSL_CHECK_OK(X509_set1_notBefore(certificate.get(), asn1_not_before.get()),
                     "Failed to set certificate notBefore time");
    OPENSSL_CHECK_OK(X509_set1_notAfter(certificate.get(), asn1_not_after.get()),
                     "Failed to set certificate notAfter time");
  } else {
    // Use system time (backwards compatible)
    OPENSSL_CHECK_PTR(X509_gmtime_adj(X509_get_notBefore(certificate.get()), 0),
                      "Failed to set certificate notBefore time");
    OPENSSL_CHECK_PTR(X509_gmtime_adj(X509_get_notAfter(certificate.get()), config.validity_seconds),
                      "Failed to set certificate notAfter time");
  }

  for (const auto &[oid_string, extension_value] : config.extra_extensions) {
    // Create OID object (allow numerical OID format)
    OPENSSL_MAKE_PTR(extension_oid, OBJ_txt2obj(oid_string.c_str(), 1), ASN1_OBJECT_free,
                     PSLICE() << "Failed to create OID object for: '" << oid_string << "'");

    // Create extension value as ASN.1 OCTET STRING
    OPENSSL_MAKE_PTR(extension_data, ASN1_OCTET_STRING_new(), ASN1_OCTET_STRING_free,
                     "Failed to create ASN1_OCTET_STRING for extension data");
    OPENSSL_CHECK_OK(ASN1_OCTET_STRING_set(extension_data.get(), td::Slice(extension_value).ubegin(),
                                           td::narrow_cast<int>(extension_value.size())),
                     "Failed to set extension data in ASN1_OCTET_STRING");

    // Create the X.509 extension (critical)
    OPENSSL_MAKE_PTR(x509_extension,
                     X509_EXTENSION_create_by_OBJ(nullptr, extension_oid.get(), 1, extension_data.get()),
                     X509_EXTENSION_free, PSLICE() << "Failed to create X509 extension for OID: " << oid_string);

    // Add extension to certificate
    OPENSSL_CHECK_OK(X509_add_ext(certificate.get(), x509_extension.get(), -1),
                     PSLICE() << "Failed to add extension '" << oid_string << "' to certificate");
  }

  // Set certificate public key
  OPENSSL_CHECK_OK(X509_set_pubkey(certificate.get(), openssl_pkey.get()), "Failed to set certificate public key");

  X509V3_CTX v3;
  memset(&v3, 0, sizeof(v3));
  X509V3_set_ctx_nodb(&v3);
  X509V3_set_ctx(&v3, /*issuer*/ certificate.get(), /*subject*/ certificate.get(), nullptr, nullptr, 0);
  X509V3_CTX *v3_ptr = &v3;

  // Add Basic Constraints (critical, CA:FALSE)
  OPENSSL_MAKE_PTR(basic_constraints_extension,
                   X509V3_EXT_conf_nid(nullptr, v3_ptr, NID_basic_constraints, "critical,CA:FALSE"),
                   X509_EXTENSION_free, "Failed to create Basic Constraints extension");
  OPENSSL_CHECK_OK(X509_add_ext(certificate.get(), basic_constraints_extension.get(), -1),
                   "Failed to add Basic Constraints extension to certificate");

  // Add Key Usage (critical, digitalSignature only for Ed25519)
  OPENSSL_MAKE_PTR(key_usage_extension,
                   X509V3_EXT_conf_nid(nullptr, v3_ptr, NID_key_usage, "critical,digitalSignature"),
                   X509_EXTENSION_free, "Failed to create Key Usage extension");
  OPENSSL_CHECK_OK(X509_add_ext(certificate.get(), key_usage_extension.get(), -1),
                   "Failed to add Key Usage extension to certificate");

  // Add Extended Key Usage (critical)
  OPENSSL_MAKE_PTR(extended_key_usage_extension,
                   X509V3_EXT_conf_nid(nullptr, v3_ptr, NID_ext_key_usage, "critical,serverAuth,clientAuth"),
                   X509_EXTENSION_free, "Failed to create Extended Key Usage extension");
  OPENSSL_CHECK_OK(X509_add_ext(certificate.get(), extended_key_usage_extension.get(), -1),
                   "Failed to add Extended Key Usage extension to certificate");

  // Add Subject Key Identifier (hash)
  OPENSSL_MAKE_PTR(ski_extension, X509V3_EXT_conf_nid(nullptr, v3_ptr, NID_subject_key_identifier, "hash"),
                   X509_EXTENSION_free, "Failed to create Subject Key Identifier extension");
  OPENSSL_CHECK_OK(X509_add_ext(certificate.get(), ski_extension.get(), -1),
                   "Failed to add Subject Key Identifier extension to certificate");

  /*
  // Add Authority Key Identifier (keyid,issuer)
  OPENSSL_MAKE_PTR(aki_extension, X509V3_EXT_conf_nid(nullptr, v3_ptr, NID_authority_key_identifier, "keyid,issuer"),
                   X509_EXTENSION_free, "Failed to create Authority Key Identifier extension");
  OPENSSL_CHECK_OK(X509_add_ext(certificate.get(), aki_extension.get(), -1),
                   "Failed to add Authority Key Identifier extension to certificate");
  */

  // Build Subject Alternative Name extension
  std::string san_value;
  for (size_t i = 0; i < config.san_names.size(); ++i) {
    if (i > 0) {
      san_value += ",";
    }

    const auto &name = config.san_names[i];
    if (name.find(':') != std::string::npos && name != "localhost") {
      // Contains colon - likely IPv6 address
      san_value += "IP:" + name;
    } else if (name.find('.') != std::string::npos || name == "localhost") {
      // Contains dot or is localhost - treat as DNS name
      san_value += "DNS:" + name;
    } else {
      // Assume IPv4 address or other IP format
      san_value += "IP:" + name;
    }
  }

  OPENSSL_MAKE_PTR(san_extension, X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, san_value.c_str()),
                   X509_EXTENSION_free, "Failed to create Subject Alternative Name extension");

  OPENSSL_CHECK_OK(X509_add_ext(certificate.get(), san_extension.get(), -1),
                   "Failed to add Subject Alternative Name extension to certificate");

  // Set certificate subject name (also issuer, since self-signed)
  X509_NAME *subject_name = X509_get_subject_name(certificate.get());
  if (!subject_name) {
    return td::Status::Error("Failed to get certificate subject name structure");
  }

  // Add subject name components
  OPENSSL_CHECK_OK(X509_NAME_add_entry_by_txt(subject_name, "C", MBSTRING_ASC,
                                              (const unsigned char *)config.country.c_str(), -1, -1, 0),
                   PSLICE() << "Failed to add country '" << config.country << "' to certificate subject");

  OPENSSL_CHECK_OK(X509_NAME_add_entry_by_txt(subject_name, "ST", MBSTRING_ASC,
                                              (const unsigned char *)config.state.c_str(), -1, -1, 0),
                   PSLICE() << "Failed to add state '" << config.state << "' to certificate subject");

  if (!config.locality.empty()) {
    OPENSSL_CHECK_OK(X509_NAME_add_entry_by_txt(subject_name, "L", MBSTRING_ASC,
                                                (const unsigned char *)config.locality.c_str(), -1, -1, 0),
                     PSLICE() << "Failed to add locality '" << config.locality << "' to certificate subject");
  }

  OPENSSL_CHECK_OK(X509_NAME_add_entry_by_txt(subject_name, "O", MBSTRING_ASC,
                                              (const unsigned char *)config.organization.c_str(), -1, -1, 0),
                   PSLICE() << "Failed to add organization '" << config.organization << "' to certificate subject");

  OPENSSL_CHECK_OK(
      X509_NAME_add_entry_by_txt(subject_name, "OU", MBSTRING_ASC,
                                 (const unsigned char *)config.organizational_unit.c_str(), -1, -1, 0),
      PSLICE() << "Failed to add organizational unit '" << config.organizational_unit << "' to certificate subject");

  OPENSSL_CHECK_OK(X509_NAME_add_entry_by_txt(subject_name, "CN", MBSTRING_ASC,
                                              (const unsigned char *)config.common_name.c_str(), -1, -1, 0),
                   PSLICE() << "Failed to add common name '" << config.common_name << "' to certificate subject");

  // Set issuer name (same as subject for self-signed certificates)
  OPENSSL_CHECK_OK(X509_set_issuer_name(certificate.get(), subject_name), "Failed to set certificate issuer name");

  // Sign the certificate with the private key
  OPENSSL_CHECK_OK(X509_sign(certificate.get(), openssl_pkey.get(), nullptr),
                   "Failed to sign certificate with private key");

  // Convert certificate to PEM format
  OPENSSL_MAKE_PTR(certificate_bio, BIO_new(BIO_s_mem()), BIO_free,
                   "Failed to create memory BIO for certificate output");
  OPENSSL_CHECK_OK(PEM_write_bio_X509(certificate_bio.get(), certificate.get()),
                   "Failed to write certificate to PEM format");

  // Extract PEM data from BIO
  char *certificate_data = nullptr;
  long certificate_length = BIO_get_mem_data(certificate_bio.get(), &certificate_data);

  if (certificate_length <= 0 || !certificate_data) {
    return td::Status::Error("Failed to extract certificate data from BIO");
  }

  return std::string(certificate_data, certificate_length);
}
td::Result<std::string> generate_tdx_self_signed_cert(const tde2e_core::PrivateKey &private_key, CertConfig config,
                                                      const UserClaims &user_claims, const TdxInterface &tdx) {
  if (user_claims.public_key != private_key.to_public_key()) {
    return td::Status::Error("public key in user claims doesn't match a given private key");
  }
  TRY_RESULT(quota, tdx.make_quote(user_claims.to_hash()));
  auto serialized_user_claims = user_claims.serialize();
  config.extra_extensions.emplace_back(OID::TDX_QUOTA.c_str(), quota.raw_quote);
  config.extra_extensions.emplace_back(OID::TDX_USER_CLAIMS.c_str(), serialized_user_claims);
  return generate_self_signed_cert(private_key, config);
}

td::Result<std::optional<std::string>> get_extension(X509 *cert, td::CSlice oid) {
  OPENSSL_MAKE_PTR(custom_oid, OBJ_txt2obj(oid.c_str(), 1), ASN1_OBJECT_free,
                   PSLICE() << "Failed to create OID object for: " << oid);  // 1 means allow numerical OID
  int ext_pos = X509_get_ext_by_OBJ(cert, custom_oid.get(), -1);
  if (ext_pos < 0) {
    return std::nullopt;
  }
  auto *ext = X509_get_ext(cert, ext_pos);
  CHECK(ext != nullptr);
  ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(ext);
  if (!ext_data) {
    return td::Status::Error(PSLICE() << "Failed to get extention data: " << oid);
  }
  const unsigned char *data = ASN1_STRING_get0_data(ext_data);
  int len = ASN1_STRING_length(ext_data);
  if (oid == OID::TDX_QUOTA && len > td::narrow_cast<int>(MAX_TDX_QUOTE_EXTENSION_SIZE)) {
    return td::Status::Error(PSLICE() << "Quote extension too large: " << len << ", max "
                                      << MAX_TDX_QUOTE_EXTENSION_SIZE);
  }
  return td::Slice(data, len).str();
}

void append_cert_info(X509 *cert, td::StringBuilder &sb) {
  BIO *bio = BIO_new(BIO_s_mem());
  if (bio) {
    if (X509_print(bio, cert) == 1) {
      char *data = nullptr;
      long len = BIO_get_mem_data(bio, &data);
      if (data && len > 0) {
        sb << "Certificate details:\n" << td::Slice(data, len);
      }
    } else {
      sb << "Failed to print certificate details\n";
    }
    BIO_free(bio);
  } else {
    sb << "Failed to create BIO for certificate printing\n";
  }

  sb << "\nExtensions:\n";
  int num_ext = X509_get_ext_count(cert);
  for (int i = 0; i < num_ext; ++i) {
    X509_EXTENSION *ext = X509_get_ext(cert, i);
    if (!ext) {
      continue;
    }
    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
    char oid_buf[MAX_OID_BUFFER_SIZE];
    int oid_len = OBJ_obj2txt(oid_buf, sizeof(oid_buf), obj, 1);
    auto oid = td::Slice(oid_buf, oid_len);
    if (oid == OID::TDX_QUOTA) {
      sb << "  Extension " << i << ": OID = TDX_QUOTA";
    } else if (oid == OID::TDX_USER_CLAIMS) {
      sb << "  Extension " << i << ": OID = TDX_USER_CLAIMS";
    } else {
      continue;
    }

    ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(ext);
    if (ext_data) {
      const unsigned char *data = ASN1_STRING_get0_data(ext_data);
      int len = ASN1_STRING_length(ext_data);
      sb << ", Value (hex): " << td::format::as_hex_dump<0>(td::Slice(data, len)) << "\n";
    } else {
      sb << " (no data)\n";
    }
  }
}

CertAndKey generate_cert_and_key(const TdxInterface *tdx, const CertConfig &config) {
  auto private_key = tde2e_core::PrivateKey::generate().move_as_ok();
  auto key = private_key.to_pem().move_as_ok().as_slice().str();
  std::string cert;
  if (tdx) {
    UserClaims user_claims;
    user_claims.public_key = private_key.to_public_key();
    cert = generate_tdx_self_signed_cert(private_key, config, user_claims, *tdx).move_as_ok();
  } else {
    cert = generate_self_signed_cert(private_key, config).move_as_ok();
  }
  return {std::move(cert), std::move(key)};
}

td::Result<CertAndKey> load_cert_and_key(td::Slice name) {
  TRY_RESULT(cert_pem, td::read_file_str(PSLICE() << name << "_cert.pem"));
  TRY_RESULT(key_pem, td::read_file_str(PSLICE() << name << "_key.pem"));
  return CertAndKey{std::move(cert_pem), std::move(key_pem)};
}

struct Verifier {
  explicit Verifier(PolicyRef policy) : policy_(std::move(policy)) {
  }
  int verify_callback(int preverify_ok, void *ctx) const {
    auto *x509_ctx = static_cast<X509_STORE_CTX *>(ctx);
    if (!preverify_ok) {
      int err = X509_STORE_CTX_get_error(x509_ctx);
      if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
        return 1;
      }
      if (err == X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION) {
        return 1;
      }

      char buf[MAX_CERT_NAME_BUFFER_SIZE];
      X509_NAME_oneline(X509_get_subject_name(X509_STORE_CTX_get_current_cert(x509_ctx)), buf,
                        MAX_CERT_NAME_BUFFER_SIZE);

      auto warning = PSTRING() << "verify error:num=" << err << ":" << X509_verify_cert_error_string(err)
                               << ":depth=" << X509_STORE_CTX_get_error_depth(x509_ctx) << ":"
                               << td::Slice(buf, std::strlen(buf));
      double now = td::Time::now();

      static std::mutex warning_mutex;
      static std::unordered_map<std::string, double> next_warning_time;

      {
        std::lock_guard<std::mutex> lock(warning_mutex);
        double &next = next_warning_time[warning];
        if (next <= now) {
          next = now + WARNING_THROTTLE_SECONDS;  // one warning per 5 minutes
          LOG(WARNING) << warning;
        }
      }
      return 0;
    }
    auto *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    FLOG(DEBUG) {
      sb << "Certificate verification callback called:\n";
      sb << "  Preverify result: " << (preverify_ok ? "OK" : "FAILED") << "\n";
      sb << "  Context pointer: " << ctx << "\n";
      if (cert) {
        append_cert_info(cert, sb);
      }
    };

    auto error_depth = X509_STORE_CTX_get_error_depth(x509_ctx);

    auto status = do_verify(cert, error_depth);
    if (status.is_error()) {
      FLOG(ERROR) {
        sb << "Certificate verification callback:\n";
        sb << "  Preverify result: " << (preverify_ok ? "OK" : "FAILED") << "\n";
        sb << "  Context pointer: " << ctx << "\n";
        if (cert) {
          append_cert_info(cert, sb);
        }
      };
      LOG(ERROR) << "Invalid certificate: " << status;
      return 0;
    }

    return 1;  // always allow
  }
  td::Status do_verify(X509 *cert, int error_depth) const {
    if (error_depth != 0) {
      return td::Status::Error("We currently allow only self signed certificates of depth 0");
    }

    if (!cert) {
      return td::Status::Error("Certificate is null");
    }

    int ext_count = X509_get_ext_count(cert);
    for (int i = 0; i < ext_count; i++) {
      X509_EXTENSION *ex = X509_get_ext(cert, i);
      int crit = X509_EXTENSION_get_critical(ex);
      if (!crit || X509_supported_extension(ex)) {
        continue;
      }
      ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
      char oid_raw[128];
      OBJ_obj2txt(oid_raw, sizeof(oid_raw), obj, 1);
      auto oid = td::CSlice(oid_raw, oid_raw + strlen(oid_raw));
      if (oid != OID::TDX_QUOTA && oid != OID::TDX_USER_CLAIMS) {
        return td::Status::Error(PSLICE() << "Unkown critical oid=" << oid);
      }
    }

    TRY_RESULT(o_raw_quota, get_extension(cert, OID::TDX_QUOTA));
    TRY_RESULT(o_raw_user_claims, get_extension(cert, OID::TDX_USER_CLAIMS));  // TODO: maybe use them?..

    OPENSSL_MAKE_PTR(pkey, X509_get_pubkey(cert), EVP_PKEY_free, "No public key found in the certificate");

    // TODO: use hash of key?
    if (EVP_PKEY_get_base_id(pkey.get()) != EVP_PKEY_ED25519) {
      return td::Status::Error("Public key is not Ed25519");
    }

    size_t pkey_length = ED25519_PUBLIC_KEY_SIZE;
    unsigned char buf[ED25519_PUBLIC_KEY_SIZE];
    OPENSSL_CHECK_OK(EVP_PKEY_get_raw_public_key(pkey.get(), buf, &pkey_length), "can't read public key's length");

    if (pkey_length != ED25519_PUBLIC_KEY_SIZE) {
      return td::Status::Error(PSLICE() << "Invalid Ed25519 key length: " << pkey_length);
    }

    TRY_RESULT(public_key, tde2e_core::PublicKey::from_slice(td::Slice(buf, ED25519_PUBLIC_KEY_SIZE)));

    UserClaims user_claims;
    // TODO deserialize claims?..
    user_claims.public_key = public_key;

    Quote quote;
    Quote *quote_ptr = nullptr;
    if (o_raw_quota) {
      quote = Quote{o_raw_quota.value()};
      quote_ptr = &quote;
    }

    TRY_STATUS(policy_->validate(quote_ptr, user_claims));

    return td::Status::OK();
  }

 private:
  PolicyRef policy_;
};

std::function<int(int, void *)> VerifyCallbackBuilder::from_policy(PolicyRef policy) {
  auto verifier = std::shared_ptr<const Verifier>(std::make_shared<Verifier>(std::move(policy)));
  return [verifier = std::move(verifier)](int preverify_ok, void *ctx) {
    return verifier->verify_callback(preverify_ok, ctx);
  };
}
void SslCtxFree::operator()(void *ptr) const {
  SSL_CTX_free(static_cast<SSL_CTX *>(ptr));
}
namespace {
struct Context {
  Context() = default;
  Context(const Context &) = delete;
  Context &operator=(const Context &) = delete;
  Context(Context &&) = delete;
  Context &operator=(Context &&) = delete;
  std::function<int(int, void *)> custom_verify_callback{};
};

Context *extract_context(SSL_CTX *ssl_ctx, bool create_if_empty) {
  static int index = SSL_CTX_get_ex_new_index(
      0, nullptr, nullptr, nullptr, [](void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp) {
        delete static_cast<Context *>(ptr);
      });
  auto context = reinterpret_cast<Context *>(SSL_CTX_get_ex_data(ssl_ctx, index));
  if (!context && create_if_empty) {
    context = new Context{};
    SSL_CTX_set_ex_data(ssl_ctx, index, context);
  }
  return context;
}
int context_verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
  SSL *ssl = (SSL *)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
  SSL_CTX *ssl_ctx = ssl ? SSL_get_SSL_CTX(ssl) : nullptr;
  auto *custom_ctx = ssl_ctx ? extract_context(ssl_ctx, false) : nullptr;
  CHECK(custom_ctx->custom_verify_callback);
  return custom_ctx->custom_verify_callback(preverify_ok, static_cast<void *>(ctx));
}
}  // namespace

CertAndKey::CertAndKey(std::string cert_pem, std::string key_pem)
    : impl_(std::make_shared<Impl>(Impl{std::move(cert_pem), std::move(key_pem)})) {
}

const std::string &CertAndKey::cert_pem() const {
  return impl_->cert_pem;
}

const std::string &CertAndKey::key_pem() const {
  return impl_->key_pem;
}

td::Result<SslCtxHolder> create_ssl_ctx(SslOptions options) {
  td::clear_openssl_errors("create_ssl_ctx");

  const SSL_METHOD *ssl_method = options.mode == SslOptions::Mode::Client ? TLS_client_method() : TLS_server_method();
  OPENSSL_CHECK_PTR(ssl_method, "Failed to obtain TLS method");

  OPENSSL_MAKE_PTR(ctx_ptr, SSL_CTX_new(ssl_method), SSL_CTX_free, "Failed to create SSL_CTX");

  long ctx_options =
      SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TICKET;  // disable TLS session resumption via session tickets
  SSL_CTX_set_options(ctx_ptr.get(), ctx_options);
  SSL_CTX_set_min_proto_version(ctx_ptr.get(), TLS1_3_VERSION);
  SSL_CTX_set_mode(ctx_ptr.get(), SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);

  OPENSSL_MAKE_PTR(cert_bio, BIO_new_mem_buf(options.cert_and_key.cert_pem().c_str(), -1), BIO_free,
                   "Failed to create BIO for certificate");
  OPENSSL_MAKE_PTR(cert, PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr), X509_free,
                   "Failed to parse certificate PEM");
  OPENSSL_CHECK_OK(SSL_CTX_use_certificate(ctx_ptr.get(), cert.get()), "Failed to set certificate in SSL_CTX");

  OPENSSL_MAKE_PTR(key_bio, BIO_new_mem_buf(options.cert_and_key.key_pem().c_str(), -1), BIO_free,
                   "Failed to create BIO for private key");
  OPENSSL_MAKE_PTR(pkey, PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free,
                   "Failed to parse private key PEM");
  OPENSSL_CHECK_OK(SSL_CTX_use_PrivateKey(ctx_ptr.get(), pkey.get()), "Failed to set private key in SSL_CTX");

  OPENSSL_CHECK_OK(SSL_CTX_check_private_key(ctx_ptr.get()), "Private key does not match the certificate");

  int verify_flags = SSL_VERIFY_PEER;
  if (options.mode == SslOptions::Mode::Server) {
    verify_flags |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
  }
  SSL_CTX_set_verify(ctx_ptr.get(), verify_flags, context_verify_callback);
  SSL_CTX_set_verify_depth(ctx_ptr.get(), MAX_CERT_CHAIN_DEPTH);
  extract_context(ctx_ptr.get(), true)->custom_verify_callback = options.custom_verify;

  // NOTE: We intentionally always send a certificate and perform full RA verification per-connection.
  // Future optimization: cache DCAP verification and policy decisions in router by hash(quote),
  // with TTL bound to collateral freshness and policy version.

  const std::string cipher_suites = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384";
  OPENSSL_CHECK_OK(SSL_CTX_set_ciphersuites(ctx_ptr.get(), cipher_suites.c_str()),
                   PSLICE() << "Failed to set cipher suites \"" << cipher_suites << "\"");

  SslCtxHolder holder;
  holder.reset(ctx_ptr.release());
  return holder;
}

}  // namespace tdx