// Request parsing and response building (docs/PROTOCOL.md §4). Host + device (no crypto keys here).
#pragma once
#include <string>
#include <vector>

#include "abi.h"
#include "cbor.h"
#include "eip712.h"
#include "tokens.h"
#include "util.h"

namespace ripar {

struct Risk {
  bool present = false;
  std::string src, category, label;
  uint64_t ageDays = 0;
};
struct AiClaims {
  bool present = false;
  std::string text;
  bool hasClaims = false;
  Addr to, token;
  U256 amount;
};

struct CosignReq {
  Bytes reqId;
  uint64_t chainId = 0;
  Addr enforcer;
  HumanApproval h;  // presenceHash filled in at signing time
  Bytes calldata;
  Risk risk;
  AiClaims ai;
  bool hasBudget = false;
  U256 budgetLeft;
  int decimals = 18;       // key 15 as sent (a companion CLAIM; 18 when absent) - display uses `token`
  std::string symbol;      // key 16 as sent (a companion CLAIM)
  bool hasDecimals = false, hasSymbol = false;
  // derived by the device
  Erc20Call call;
  TokenView token;         // asset of the amount: native (call None) or the call target (ERC-20), checked against
                           // the firmware table (tokens.h); a listed asset whose keys 15/16 disagree is refused
  bool aiMatches = false;  // claims (recipient, token, amount) equal the device's own decode; only a native send or
                           // an ERC-20 transfer can match (never transferFrom / approve / unknown)
};
struct MandateReq {
  Bytes reqId;
  uint64_t chainId = 0;
  Addr manager;
  Delegation d;
  std::string label;
  bool hasAgentId = false;
  uint64_t agentId = 0;
};
struct DenyReq {
  Bytes reqId;
  uint64_t chainId = 0;
  Addr relay;
  uint64_t agentId = 0;
  B32 requestHash;
};
struct PairReq {
  Bytes reqId;
  uint64_t chainId = 0;
  Addr registry;
  // optional contracts to pin (keys 4..8; zero = not given): DelegationManager, PulseCosignEnforcer,
  // RiparSentinel, RiparReputationRelay, vault (HybridDeleGator owned by K1)
  Addr manager, enforcer, sentinel, relay, vault;
  // (appended) key 9: the companion's clock (unix s, < 2^40), shown as UTC and confirmed with the pairing; it
  // advances the device's monotonic "not before" time (policy.h expiry_check)
  bool hasNow = false;
  uint64_t now = 0;
  // (appended) keys 10 / 11: floors for the device's monotonic counters (< 2^63), e.g. the on-chain minEpoch of this
  // P1 key and the last reopen nonce the sentinel saw, after the device lost its context. They can only RAISE
  // Context::minEpoch / reopenNonce (policy.h context_after_pair), never lower them; both are shown on the review.
  bool hasMinEpoch = false;
  uint64_t minEpoch = 0;
  bool hasReopenNonce = false;
  uint64_t reopenNonce = 0;
};
const uint64_t PAIR_FLOOR_LIMIT = uint64_t(1) << 63;  // keys 10 / 11 must be below this (panic / reopen headroom)

// Privy authorization-signature payload, restricted to the exact request shapes Ripar needs (security review M1):
//   PATCH https://api.privy.io/v1/wallets/{id}      body members from {policy_ids, additional_signers}
//   PATCH https://api.privy.io/v1/key_quorums/{id}  body members from {public_keys, authorization_threshold,
//                                                     display_name, user_ids, key_quorum_ids}
// Everything else (other methods / paths incl. /rpc, other hosts, query strings, unknown members or headers, values
// that could not be shown in full) is refused by parse_privy_req. Every value below is shown in full.
struct PrivySigner {
  std::string signerId;
  bool hasOverride = false;
  std::vector<std::string> overridePolicyIds;
};
struct PrivyReq {
  enum Kind : uint8_t { None, WalletUpdate, KeyQuorumUpdate };
  Bytes reqId;
  Bytes json;                 // the exact bytes signed: sha256(json)
  std::string method, path;   // "PATCH", "/v1/wallets/<id>"
  Kind kind = None;
  std::string resourceId;     // wallet id / key quorum id
  std::string appId;          // header privy-app-id (required)
  std::string idempotencyKey; // header privy-idempotency-key ("" = absent)
  // WalletUpdate
  bool hasPolicyIds = false;
  std::vector<std::string> policyIds;
  bool hasSigners = false;
  std::vector<PrivySigner> signers;
  // KeyQuorumUpdate
  bool hasPublicKeys = false;
  std::vector<std::string> publicKeys;  // base64 DER SubjectPublicKeyInfo, exactly as in the JSON
  std::vector<Bytes> publicKeyXY;       // the P-256 key of each (64 bytes x||y), decoded by the device
  bool hasThreshold = false;
  uint64_t threshold = 0;
  bool hasDisplayName = false;
  std::string displayName;
  bool hasUserIds = false;
  std::vector<std::string> userIds;
  bool hasKeyQuorumIds = false;
  std::vector<std::string> keyQuorumIds;
};

enum class ReqType { Unknown, Pair, Cosign, Mandate, Deny, Privy };
ReqType req_type_from_ur(const std::string& urType);  // "ripar-cosign-req" -> Cosign, ...

bool parse_pair_req(const CborVal& m, PairReq& r, std::string& err);
bool parse_cosign_req(const CborVal& m, CosignReq& r, std::string& err);    // also fills call, aiMatches, callDataHash
bool parse_mandate_req(const CborVal& m, MandateReq& r, std::string& err);  // rejects non-ROOT authority
bool parse_deny_req(const CborVal& m, DenyReq& r, std::string& err);
bool parse_privy_req(const CborVal& m, PrivyReq& r, std::string& err);     // strict JSON + request-shape allowlist

// digests the device signs (rebuilt from parsed fields only)
B32 cosign_digest(const CosignReq& r);  // uses r.h (with presenceHash set)
B32 mandate_digest(const MandateReq& r);
B32 deny_digest(const DenyReq& r, const B32& presenceHash);
B32 presence_hash(const uint8_t evidence12[12], const uint8_t salt16[16]);  // sha256

// responses (CBOR) -> wrap with ur_encode(type, cbor)
Bytes build_pair(const Bytes& reqId, const Addr& k1, const uint8_t p1xy[64], const uint8_t* p1sig64,
                 const uint8_t* k1sig65, const uint8_t fwid[8]);  // sigs may be nullptr
Bytes build_cosign(const Bytes& reqId, const uint8_t rs[64], const uint8_t ev12[12], const uint8_t salt16[16]);
Bytes build_eth_signature(const Bytes& reqId, const uint8_t rsv[65]);
// {1: req-id, 2: r||s, 3: evidence12, 4: salt16, 5: agentId, 6: requestHash} - 5/6 echo exactly what was signed
Bytes build_deny(const DenyReq& r, const uint8_t rs[64], const uint8_t ev12[12], const uint8_t salt16[16]);
Bytes build_revoke(const B32& delegationHash, const uint8_t rs[64]);
Bytes build_panic(uint64_t minEpoch, const uint8_t rs[64]);
Bytes build_der_sig(const Bytes& reqId, const Bytes& der);

// Plain-language name of a caveat enforcer the device can DECODE (address -> "ERC-20 total spend cap", ...);
// nullptr for anything else (unknown, or a known enforcer without a terms decoder: fail-closed). The Ripar
// PulseCosignEnforcer is only known here when its address is compiled in; review.h enforcer_kind() also knows the
// address pinned at pairing.
const char* enforcer_name(uint64_t chainId, const Addr& enforcer);

// ---- additions (append-only; nothing above changed): digests + builder for the device-initiated messages and
// pairing, so the EIP-712 domain names live in one place (src/protocol.cpp). Contracts come from the stored
// pairing / mandate context.
B32 pair_digest(uint64_t chainId, const Addr& registry, const Addr& k1, const uint8_t p1xy[64]);  // BindDevice
B32 revoke_digest(uint64_t chainId, const Addr& cosignEnforcer, const B32& delegationHash);     // RiparPulseCosign
B32 panic_digest(uint64_t chainId, const Addr& cosignEnforcer, uint64_t minEpoch);             // RiparPulseCosign
B32 reopen_digest(uint64_t chainId, const Addr& sentinel, const Addr& vault, const U256& nonce);  // RiparSentinel
Bytes build_reopen(const Addr& vault, const U256& nonce, const uint8_t rs[64]);  // nonce: minimal BE, >= 1 byte

// Deny from a co-sign review (security review MINOR 7): requestHash is computed by the device, never taken from
// the companion = hashStruct(HumanApproval) of the reviewed request with presenceHash = 0.
B32 cosign_request_hash(const CosignReq& r);

}  // namespace ripar
