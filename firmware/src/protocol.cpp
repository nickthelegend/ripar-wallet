// Request parsing, digest rebuilding and response building (docs/PROTOCOL.md §3-§4). Portable C++14 (host + device).
//
// Parser policy (every request arrives from an untrusted companion through the camera). The parsers check FORMAT;
// whether a well-formed request may be signed with the device's pinned context (chain, contracts, vault, agent,
// expiry window, mandate caveats) is decided by include/policy.h, and the review screen lines by include/review.h.
//  - the request must be a CBOR map whose keys are all unsigned integers from the table of that request type;
//    an unknown key, a missing required key or a value of the wrong CBOR type / length is an error
//  - req-id (key 1): bstr of exactly 16 bytes, optionally wrapped in tag 37 (UUID). Responses echo it as a plain bstr.
//  - addr = bstr(20); every top-level address must be non-zero (AI claims may carry the zero address = native).
//    bstr32 = exactly 32 bytes. u256 = bstr of at most 32 bytes (leading zeros optional). uint = CBOR major type 0.
//  - chainId must be non-zero.
//  - companion-provided display text (risk, ai text, symbol, label) must not contain control characters
//    (bytes < 0x20 or 0x7f: a newline could forge an extra review line) and is length-limited (UTF-8 bytes):
//    risk src/category/label <= 64, ai text <= 100, symbol <= 16, mandate label <= 64
//  - decimals <= 255 (ERC-20 decimals() is a uint8)
//  - co-sign: the asset of the amount (native coin for empty calldata, else the call target) is resolved against the
//    firmware token table (tokens.h, security review B3): a LISTED asset whose keys 15 / 16 disagree with the table
//    is refused; an unlisted one parses (the review shows base units + UNKNOWN TOKEN).
//    aiMatches (security review MINOR 1): only a plain native send or an ERC-20 transfer can match, and only when
//    recipient, token (zero = native) and amount all equal the device's own decode; transferFrom / approve /
//    unknown calls never "match".
//  - mandate: authority must be ROOT_AUTHORITY; caveats: 1..16 entries of [enforcer addr, terms bstr]. An empty
//    caveat list is refused. Enforcers and terms are checked by policy.h check_mandate() (B2 / M4).
//  - pair: keys 4..8 (contracts to pin) are optional non-zero addresses, key 9 (companion clock) < 2^40.
//  - Privy: strict JSON (json_strict.h) AND an allow-list of exactly the request shapes Ripar needs (security review
//    M1, see protocol.h PrivyReq): every value is kept in full; anything that could not be shown in full is refused.
//  - expiry is NOT compared with the clock here; that is policy.h expiry_check().
//  - on failure the output struct is left unchanged and err says which key failed.
#include "protocol.h"

#include <cstring>

#include "hashes.h"
#include "json_strict.h"

namespace ripar {

namespace {

std::string u64_str(uint64_t v) {
  char buf[24];
  size_t k = 0;
  do {
    buf[k++] = char('0' + v % 10);
    v /= 10;
  } while (v);
  std::string s;
  while (k) s += buf[--k];
  return s;
}

struct KeySpec {
  uint64_t key;
  const char* name;
  bool required;
};

// Error context for one CBOR map ("cosign-req", "cosign-req.risk", ...).
struct Ctx {
  const char* what;
  const KeySpec* spec;
  size_t nspec;
  std::string* err;

  const KeySpec* find(uint64_t k) const {
    for (size_t i = 0; i < nspec; i++)
      if (spec[i].key == k) return &spec[i];
    return nullptr;
  }
  bool fail(const std::string& m) const {
    *err = std::string(what) + ": " + m;
    return false;
  }
  bool fail(uint64_t k, const char* m) const {
    const KeySpec* s = find(k);
    return fail("key " + u64_str(k) + " (" + (s ? s->name : "?") + ") " + m);
  }
};

bool check_map(const Ctx& c, const CborVal& m) {
  if (m.type != CborVal::Map) return c.fail("not a CBOR map");
  for (size_t i = 0; i + 1 < m.items.size(); i += 2) {
    const CborVal& k = m.items[i];
    if (k.type != CborVal::UInt) return c.fail("map key is not an unsigned integer");
    if (!c.find(k.u)) return c.fail("unknown key " + u64_str(k.u));
  }
  for (size_t i = 0; i < c.nspec; i++)
    if (c.spec[i].required && !cbor_get(m, c.spec[i].key)) return c.fail(c.spec[i].key, "is missing");
  return true;
}

// ---- typed field readers (the key has been checked to be present by the caller)
bool rd_reqid(const Ctx& c, const CborVal& m, uint64_t k, Bytes& out) {
  const CborVal* v = cbor_get(m, k);
  if (v && v->type == CborVal::Tag && v->u == 37 && v->items.size() == 1) v = &v->items[0];  // UUID tag
  if (!v || v->type != CborVal::Bytes_) return c.fail(k, "must be a bstr (optionally tag 37)");
  if (v->b.size() != 16) return c.fail(k, "must be exactly 16 bytes");
  out = v->b;
  return true;
}

bool rd_uint(const Ctx& c, const CborVal& m, uint64_t k, uint64_t& out) {
  const CborVal* v = cbor_get(m, k);
  if (!v || v->type != CborVal::UInt) return c.fail(k, "must be an unsigned integer");
  out = v->u;
  return true;
}

bool rd_chain(const Ctx& c, const CborVal& m, uint64_t k, uint64_t& out) {
  uint64_t x;
  if (!rd_uint(c, m, k, x)) return false;
  if (x == 0) return c.fail(k, "must not be 0");
  out = x;
  return true;
}

bool rd_bstr(const Ctx& c, const CborVal& m, uint64_t k, const CborVal*& out) {
  const CborVal* v = cbor_get(m, k);
  if (!v || v->type != CborVal::Bytes_) return c.fail(k, "must be a bstr");
  out = v;
  return true;
}

bool rd_addr(const Ctx& c, const CborVal& m, uint64_t k, Addr& out, bool nonzero) {
  const CborVal* v;
  if (!rd_bstr(c, m, k, v)) return false;
  if (v->b.size() != 20) return c.fail(k, "must be a 20-byte address");
  Addr a;
  std::memcpy(a.v, v->b.data(), 20);
  if (nonzero && a.is_zero()) return c.fail(k, "must not be the zero address");
  out = a;
  return true;
}

bool rd_b32(const Ctx& c, const CborVal& m, uint64_t k, B32& out) {
  const CborVal* v;
  if (!rd_bstr(c, m, k, v)) return false;
  if (v->b.size() != 32) return c.fail(k, "must be exactly 32 bytes");
  std::memcpy(out.v, v->b.data(), 32);
  return true;
}

bool rd_u256(const Ctx& c, const CborVal& m, uint64_t k, U256& out) {
  const CborVal* v;
  if (!rd_bstr(c, m, k, v)) return false;
  if (!U256::from_be(v->b.data(), v->b.size(), out)) return c.fail(k, "must be at most 32 bytes (u256)");
  return true;
}

bool rd_bytes(const Ctx& c, const CborVal& m, uint64_t k, Bytes& out) {
  const CborVal* v;
  if (!rd_bstr(c, m, k, v)) return false;
  out = v->b;
  return true;
}

// Display text: CBOR text (UTF-8 already validated by the decoder), <= maxLen bytes, no control characters.
bool rd_text(const Ctx& c, const CborVal& m, uint64_t k, std::string& out, size_t maxLen) {
  const CborVal* v = cbor_get(m, k);
  if (!v || v->type != CborVal::Text) return c.fail(k, "must be a text string");
  if (v->b.size() > maxLen) return c.fail(k, ("is longer than " + u64_str(maxLen) + " bytes").c_str());
  for (uint8_t ch : v->b)
    if (ch < 0x20 || ch == 0x7F) return c.fail(k, "contains a control character");
  out = v->str();
  return true;
}

// ---- small encoders
void put_u256_min(CborWriter& w, const U256& x) {  // minimal big-endian, at least one byte (0 -> h'00')
  size_t i = 0;
  while (i < 31 && x.v[i] == 0) i++;
  w.bytes(x.v + i, 32 - i);
}

B32 domain(const char* name, uint64_t chainId, const Addr& contract) {
  return eip712_domain(name, "1", chainId, contract);
}

// ---- Privy request allow-list (security review M1)
const char PRIVY_WALLETS[] = "https://api.privy.io/v1/wallets/";
const char PRIVY_QUORUMS[] = "https://api.privy.io/v1/key_quorums/";
const size_t PRIVY_MAX_ID = 64;     // ids / app id / idempotency key: longer is refused (never truncated)
const size_t PRIVY_MAX_ITEMS = 8;   // entries per array: more is refused (the review shows every one)
const size_t PRIVY_MAX_NAME = 64;   // display_name bytes

// Error text: printable ASCII only, at most k bytes (member names come from the untrusted JSON).
std::string safe(const std::string& s, size_t k = 32) {
  std::string o;
  for (char ch : s) {
    if (o.size() >= k) {
      o += "...";
      break;
    }
    const uint8_t b = uint8_t(ch);
    o += (b >= 0x20 && b < 0x7F) ? ch : '?';
  }
  return o;
}

// Privy ids: 1..64 of [A-Za-z0-9_:.-] (e.g. "cm0appid1234", "did:privy:cm0...", UUID idempotency keys).
bool id_ok(const std::string& s) {
  if (s.empty() || s.size() > PRIVY_MAX_ID) return false;
  for (char ch : s) {
    const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' ||
                    ch == ':' || ch == '.' || ch == '-';
    if (!ok) return false;
  }
  return true;
}

bool printable_ascii(const std::string& s) {
  for (char ch : s)
    if (uint8_t(ch) < 0x20 || uint8_t(ch) > 0x7E) return false;
  return true;
}

// One member of an object, checked against the allowed names. why = error text.
bool members_allowed(const JsonVal& o, const char* const* names, size_t n, const char* what, std::string& why) {
  for (const std::string& k : o.keys) {
    bool ok = false;
    for (size_t i = 0; i < n; i++) ok = ok || k == names[i];
    if (!ok) {
      why = std::string(what) + " member \"" + safe(k) + "\" is not allowed";
      return false;
    }
  }
  return true;
}

// JSON array of id strings, 0..PRIVY_MAX_ITEMS entries.
bool id_array(const JsonVal* v, const char* what, std::vector<std::string>& out, std::string& why) {
  if (!v || v->type != JsonVal::Array) {
    why = std::string(what) + " must be an array of ids";
    return false;
  }
  if (v->items.size() > PRIVY_MAX_ITEMS) {
    why = std::string(what) + " has more than 8 entries (not shown in full: refused)";
    return false;
  }
  std::vector<std::string> t;
  for (const JsonVal& e : v->items) {
    if (e.type != JsonVal::String || !id_ok(e.str)) {
      why = std::string(what) + " entries must be ids of 1..64 characters [A-Za-z0-9_:.-]";
      return false;
    }
    t.push_back(e.str);
  }
  out.swap(t);
  return true;
}

// Strict RFC 4648 base64 (standard alphabet, '=' padding required, canonical: unused bits zero).
bool b64_decode(const std::string& s, Bytes& out) {
  if (s.empty() || s.size() % 4) return false;
  Bytes r;
  r.reserve(s.size() / 4 * 3);
  for (size_t i = 0; i < s.size(); i += 4) {
    int v[4];
    int pad = 0;
    for (int j = 0; j < 4; j++) {
      const char ch = s[i + size_t(j)];
      int x;
      if (ch >= 'A' && ch <= 'Z')
        x = ch - 'A';
      else if (ch >= 'a' && ch <= 'z')
        x = ch - 'a' + 26;
      else if (ch >= '0' && ch <= '9')
        x = ch - '0' + 52;
      else if (ch == '+')
        x = 62;
      else if (ch == '/')
        x = 63;
      else if (ch == '=' && i + 4 == s.size() && j >= 2)
        x = -1;
      else
        return false;
      if (x < 0)
        pad++;
      else if (pad)
        return false;  // data after '='
      v[j] = x < 0 ? 0 : x;
    }
    const uint32_t w = (uint32_t(v[0]) << 18) | (uint32_t(v[1]) << 12) | (uint32_t(v[2]) << 6) | uint32_t(v[3]);
    r.push_back(uint8_t(w >> 16));
    if (pad < 2) r.push_back(uint8_t(w >> 8));
    if (pad < 1) r.push_back(uint8_t(w));
    if ((pad == 1 && (w & 0xFF)) || (pad == 2 && (w & 0xFFFF))) return false;  // non-canonical unused bits
  }
  out.swap(r);
  return true;
}

// DER SubjectPublicKeyInfo of an uncompressed P-256 key: exactly these 27 bytes, then x || y (91 bytes in total).
const uint8_t SPKI_P256_PREFIX[27] = {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
                                      0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04};

bool p256_spki_b64(const std::string& s, Bytes& xy) {
  Bytes der;
  if (!b64_decode(s, der) || der.size() != 91 || std::memcmp(der.data(), SPKI_P256_PREFIX, 27) != 0) return false;
  xy.assign(der.begin() + 27, der.end());
  return true;
}

}  // namespace

// =====================================================================================================================
ReqType req_type_from_ur(const std::string& urType) {
  std::string t(urType);
  for (char& ch : t)
    if (ch >= 'A' && ch <= 'Z') ch = char(ch - 'A' + 'a');
  if (t == "ripar-pair-req") return ReqType::Pair;
  if (t == "ripar-cosign-req") return ReqType::Cosign;
  if (t == "ripar-mandate-req") return ReqType::Mandate;
  if (t == "ripar-deny-req") return ReqType::Deny;
  if (t == "ripar-privy-req") return ReqType::Privy;
  return ReqType::Unknown;
}

// ---------------------------------------------------------------------------------------------------------------------
bool parse_pair_req(const CborVal& m, PairReq& r, std::string& err) {
  static const KeySpec SPEC[] = {{1, "req-id", true},  {2, "chainId", true},  {3, "registry", true},
                                 {4, "DelegationManager", false}, {5, "PulseCosignEnforcer", false},
                                 {6, "sentinel", false}, {7, "relay", false}, {8, "vault", false},
                                 {9, "now", false}, {10, "minEpoch floor", false},
                                 {11, "reopenNonce floor", false}};
  const Ctx c = {"pair-req", SPEC, sizeof(SPEC) / sizeof(SPEC[0]), &err};
  PairReq t;
  if (!check_map(c, m)) return false;
  if (!rd_reqid(c, m, 1, t.reqId) || !rd_chain(c, m, 2, t.chainId) || !rd_addr(c, m, 3, t.registry, true))
    return false;
  Addr* opt[5] = {&t.manager, &t.enforcer, &t.sentinel, &t.relay, &t.vault};
  for (uint64_t k = 4; k <= 8; k++)
    if (cbor_get(m, k) && !rd_addr(c, m, k, *opt[k - 4], true)) return false;
  if (cbor_get(m, 9)) {
    if (!rd_uint(c, m, 9, t.now)) return false;
    if (t.now >= (uint64_t(1) << 40)) return c.fail(9, "must be below 2^40 (unix seconds)");
    t.hasNow = true;
  }
  if (cbor_get(m, 10)) {
    if (!rd_uint(c, m, 10, t.minEpoch)) return false;
    if (t.minEpoch >= PAIR_FLOOR_LIMIT) return c.fail(10, "must be below 2^63");
    t.hasMinEpoch = true;
  }
  if (cbor_get(m, 11)) {
    if (!rd_uint(c, m, 11, t.reopenNonce)) return false;
    if (t.reopenNonce >= PAIR_FLOOR_LIMIT) return c.fail(11, "must be below 2^63");
    t.hasReopenNonce = true;
  }
  r = std::move(t);
  err.clear();
  return true;
}

// ---------------------------------------------------------------------------------------------------------------------
bool parse_cosign_req(const CborVal& m, CosignReq& r, std::string& err) {
  static const KeySpec SPEC[] = {
      {1, "req-id", true},     {2, "chainId", true},    {3, "enforcer", true},    {4, "delegationHash", true},
      {5, "delegator", true},  {6, "redeemer", true},   {7, "target", true},      {8, "value", true},
      {9, "calldata", true},   {10, "nonce", true},     {11, "expiry", true},     {12, "risk", false},
      {13, "ai", false},       {14, "budgetLeft", false}, {15, "decimals", false}, {16, "symbol", false}};
  static const KeySpec RISK[] = {
      {1, "src", true}, {2, "category", true}, {3, "label", true}, {4, "ageDays", true}};
  static const KeySpec AI[] = {{1, "text", true}, {2, "claims", false}};
  static const KeySpec CLAIMS[] = {{1, "to", true}, {2, "token", true}, {3, "amount", true}};
  const Ctx c = {"cosign-req", SPEC, sizeof(SPEC) / sizeof(SPEC[0]), &err};

  CosignReq t;
  if (!check_map(c, m)) return false;
  if (!rd_reqid(c, m, 1, t.reqId) || !rd_chain(c, m, 2, t.chainId) || !rd_addr(c, m, 3, t.enforcer, true) ||
      !rd_b32(c, m, 4, t.h.delegationHash) || !rd_addr(c, m, 5, t.h.delegator, true) ||
      !rd_addr(c, m, 6, t.h.redeemer, true) || !rd_addr(c, m, 7, t.h.target, true) ||
      !rd_u256(c, m, 8, t.h.value) || !rd_bytes(c, m, 9, t.calldata) || !rd_u256(c, m, 10, t.h.nonce) ||
      !rd_uint(c, m, 11, t.h.expiry))
    return false;

  if (const CborVal* v = cbor_get(m, 12)) {
    const Ctx cr = {"cosign-req.risk", RISK, sizeof(RISK) / sizeof(RISK[0]), &err};
    if (!check_map(cr, *v)) return false;
    if (!rd_text(cr, *v, 1, t.risk.src, 64) || !rd_text(cr, *v, 2, t.risk.category, 64) ||
        !rd_text(cr, *v, 3, t.risk.label, 64) || !rd_uint(cr, *v, 4, t.risk.ageDays))
      return false;
    t.risk.present = true;
  }
  if (const CborVal* v = cbor_get(m, 13)) {
    const Ctx ca = {"cosign-req.ai", AI, sizeof(AI) / sizeof(AI[0]), &err};
    if (!check_map(ca, *v)) return false;
    if (!rd_text(ca, *v, 1, t.ai.text, 100)) return false;
    if (const CborVal* cl = cbor_get(*v, 2)) {
      const Ctx cc = {"cosign-req.ai.claims", CLAIMS, sizeof(CLAIMS) / sizeof(CLAIMS[0]), &err};
      if (!check_map(cc, *cl)) return false;
      if (!rd_addr(cc, *cl, 1, t.ai.to, false) || !rd_addr(cc, *cl, 2, t.ai.token, false) ||
          !rd_u256(cc, *cl, 3, t.ai.amount))
        return false;
      t.ai.hasClaims = true;
    }
    t.ai.present = true;
  }
  if (cbor_get(m, 14)) {
    if (!rd_u256(c, m, 14, t.budgetLeft)) return false;
    t.hasBudget = true;
  }
  if (cbor_get(m, 15)) {
    uint64_t d;
    if (!rd_uint(c, m, 15, d)) return false;
    if (d > 255) return c.fail(15, "must be <= 255");
    t.decimals = int(d);
    t.hasDecimals = true;
  }
  if (cbor_get(m, 16)) {
    if (!rd_text(c, m, 16, t.symbol, 16)) return false;
    t.hasSymbol = true;
  }

  // derived by the device
  keccak256(t.calldata.empty() ? nullptr : t.calldata.data(), t.calldata.size(), t.h.callDataHash.v);
  t.call = abi_decode_erc20(t.calldata);
  // the asset of the amount: native coin for a plain send, otherwise the called contract (ERC-20)
  std::string terr;
  if (!token_resolve(t.chainId, t.call.kind == Erc20Call::None, t.h.target, t.hasDecimals ? &t.decimals : nullptr,
                     t.hasSymbol ? &t.symbol : nullptr, t.token, terr))
    return c.fail(terr);
  if (t.ai.hasClaims) {
    switch (t.call.kind) {
      case Erc20Call::None:  // native transfer: recipient = target, token = 0x0, amount = value
        t.aiMatches = t.ai.to == t.h.target && t.ai.token.is_zero() && t.ai.amount.cmp(t.h.value) == 0;
        break;
      case Erc20Call::Transfer:  // recipient / amount from the decode, token = target; no native value on the side
        t.aiMatches = t.h.value.is_zero() && t.ai.to == t.call.to && t.ai.token == t.h.target &&
                      t.ai.amount.cmp(t.call.amount) == 0;
        break;
      default:  // TransferFrom (moves someone's allowance), Approve (not a payment), Unknown: never "match"
        t.aiMatches = false;
        break;
    }
  }
  r = std::move(t);
  err.clear();
  return true;
}

// ---------------------------------------------------------------------------------------------------------------------
bool parse_mandate_req(const CborVal& m, MandateReq& r, std::string& err) {
  static const KeySpec SPEC[] = {{1, "req-id", true},    {2, "chainId", true},   {3, "DelegationManager", true},
                                 {4, "delegate", true},  {5, "delegator", true}, {6, "authority", true},
                                 {7, "caveats", true},   {8, "salt", true},      {9, "label", false},
                                 {10, "agentId", false}};
  const Ctx c = {"mandate-req", SPEC, sizeof(SPEC) / sizeof(SPEC[0]), &err};

  MandateReq t;
  if (!check_map(c, m)) return false;
  if (!rd_reqid(c, m, 1, t.reqId) || !rd_chain(c, m, 2, t.chainId) || !rd_addr(c, m, 3, t.manager, true) ||
      !rd_addr(c, m, 4, t.d.delegate, true) || !rd_addr(c, m, 5, t.d.delegator, true) ||
      !rd_b32(c, m, 6, t.d.authority))
    return false;
  if (!(t.d.authority == ROOT_AUTHORITY)) return c.fail(6, "is not ROOT_AUTHORITY (redelegation refused)");

  const CborVal* cav = cbor_get(m, 7);
  if (cav->type != CborVal::Array) return c.fail(7, "must be an array");
  if (cav->items.empty()) return c.fail(7, "is empty (a mandate without caveats is unlimited)");
  if (cav->items.size() > 16) return c.fail(7, "has more than 16 caveats");
  for (size_t i = 0; i < cav->items.size(); i++) {
    const CborVal& e = cav->items[i];
    const std::string idx = "caveat " + u64_str(i);
    if (e.type != CborVal::Array || e.items.size() != 2) return c.fail(idx + " must be [enforcer, terms]");
    if (e.items[0].type != CborVal::Bytes_ || e.items[0].b.size() != 20)
      return c.fail(idx + " enforcer must be a 20-byte address");
    if (e.items[1].type != CborVal::Bytes_) return c.fail(idx + " terms must be a bstr");
    Caveat cv;
    std::memcpy(cv.enforcer.v, e.items[0].b.data(), 20);
    cv.terms = e.items[1].b;
    t.d.caveats.push_back(std::move(cv));
  }
  if (!rd_u256(c, m, 8, t.d.salt)) return false;
  if (cbor_get(m, 9) && !rd_text(c, m, 9, t.label, 64)) return false;
  if (cbor_get(m, 10)) {
    if (!rd_uint(c, m, 10, t.agentId)) return false;
    t.hasAgentId = true;
  }
  r = std::move(t);
  err.clear();
  return true;
}

// ---------------------------------------------------------------------------------------------------------------------
bool parse_deny_req(const CborVal& m, DenyReq& r, std::string& err) {
  static const KeySpec SPEC[] = {
      {1, "req-id", true}, {2, "chainId", true}, {3, "relay", true}, {4, "agentId", true}, {5, "requestHash", true}};
  const Ctx c = {"deny-req", SPEC, sizeof(SPEC) / sizeof(SPEC[0]), &err};
  DenyReq t;
  if (!check_map(c, m)) return false;
  if (!rd_reqid(c, m, 1, t.reqId) || !rd_chain(c, m, 2, t.chainId) || !rd_addr(c, m, 3, t.relay, true) ||
      !rd_uint(c, m, 4, t.agentId) || !rd_b32(c, m, 5, t.requestHash))
    return false;
  r = std::move(t);
  err.clear();
  return true;
}

// ---------------------------------------------------------------------------------------------------------------------
// Privy authorization-signature payload (canonical JSON): {"body":..,"headers":{..},"method":..,"url":..,"version":1}
// restricted to the shapes in protocol.h (PrivyReq). Every refusal names the problem.
bool parse_privy_req(const CborVal& m, PrivyReq& r, std::string& err) {
  static const KeySpec SPEC[] = {{1, "req-id", true}, {2, "json", true}};
  const Ctx c = {"privy-req", SPEC, sizeof(SPEC) / sizeof(SPEC[0]), &err};
  PrivyReq t;
  if (!check_map(c, m)) return false;
  if (!rd_reqid(c, m, 1, t.reqId) || !rd_bytes(c, m, 2, t.json)) return false;
  if (t.json.empty()) return c.fail(2, "is empty");

  JsonVal doc;
  std::string jerr;
  if (!json_parse_strict(t.json.data(), t.json.size(), doc, &jerr)) return c.fail("JSON: " + jerr);
  if (doc.type != JsonVal::Object) return c.fail("JSON: top level is not an object");
  static const char* const TOP[] = {"version", "method", "url", "body", "headers"};
  std::string why;
  if (!members_allowed(doc, TOP, 5, "top-level", why)) return c.fail("JSON: " + why);
  const JsonVal* version = doc.get("version");
  const JsonVal* method = doc.get("method");
  const JsonVal* url = doc.get("url");
  const JsonVal* headers = doc.get("headers");
  const JsonVal* body = doc.get("body");
  if (!version || version->type != JsonVal::Number || version->str != "1")
    return c.fail("JSON: \"version\" must be the number 1");
  if (!method || method->type != JsonVal::String) return c.fail("JSON: \"method\" must be a string");
  if (!url || url->type != JsonVal::String) return c.fail("JSON: \"url\" must be a string");
  if (!headers || headers->type != JsonVal::Object) return c.fail("JSON: \"headers\" must be an object");
  if (!body) return c.fail("JSON: \"body\" is missing");

  // ---- allow-list: PATCH a wallet or a key quorum on api.privy.io, nothing else
  const std::string NOT = "not an allowed Privy request: ";
  if (method->str != "PATCH") return c.fail(NOT + "method must be PATCH (got \"" + safe(method->str, 16) + "\")");
  const std::string& u = url->str;
  const size_t lw = sizeof(PRIVY_WALLETS) - 1, lq = sizeof(PRIVY_QUORUMS) - 1;
  if (u.size() > lw && u.compare(0, lw, PRIVY_WALLETS) == 0) {
    t.kind = PrivyReq::WalletUpdate;
    t.resourceId = u.substr(lw);
  } else if (u.size() > lq && u.compare(0, lq, PRIVY_QUORUMS) == 0) {
    t.kind = PrivyReq::KeyQuorumUpdate;
    t.resourceId = u.substr(lq);
  } else {
    return c.fail(NOT + "url must be https://api.privy.io/v1/wallets/<id> or /v1/key_quorums/<id> (got \"" +
                  safe(u, 48) + "\")");
  }
  if (!id_ok(t.resourceId))
    return c.fail(NOT + "the id in the url must be 1..64 characters [A-Za-z0-9_:.-] (no query, no extra path)");
  t.method = method->str;
  t.path = u.substr(sizeof("https://api.privy.io") - 1);

  static const char* const HDR[] = {"privy-app-id", "privy-idempotency-key"};
  if (!members_allowed(*headers, HDR, 2, "header", why)) return c.fail(NOT + why);
  const JsonVal* app = headers->get("privy-app-id");
  if (!app || app->type != JsonVal::String || !id_ok(app->str))
    return c.fail(NOT + "header privy-app-id must be an id of 1..64 characters");
  t.appId = app->str;
  if (const JsonVal* idem = headers->get("privy-idempotency-key")) {
    if (idem->type != JsonVal::String || !id_ok(idem->str))
      return c.fail(NOT + "header privy-idempotency-key must be an id of 1..64 characters");
    t.idempotencyKey = idem->str;
  }

  if (body->type != JsonVal::Object || body->items.empty()) return c.fail(NOT + "body must be a non-empty object");
  if (t.kind == PrivyReq::WalletUpdate) {
    static const char* const WB[] = {"policy_ids", "additional_signers"};
    if (!members_allowed(*body, WB, 2, "wallet update body", why)) return c.fail(NOT + why);
    if (const JsonVal* v = body->get("policy_ids")) {
      if (!id_array(v, "policy_ids", t.policyIds, why)) return c.fail(NOT + why);
      t.hasPolicyIds = true;
    }
    if (const JsonVal* v = body->get("additional_signers")) {
      if (v->type != JsonVal::Array) return c.fail(NOT + "additional_signers must be an array");
      if (v->items.size() > PRIVY_MAX_ITEMS)
        return c.fail(NOT + "additional_signers has more than 8 entries (not shown in full: refused)");
      static const char* const SG[] = {"signer_id", "override_policy_ids"};
      for (const JsonVal& e : v->items) {
        if (e.type != JsonVal::Object) return c.fail(NOT + "additional_signers entries must be objects");
        if (!members_allowed(e, SG, 2, "additional_signers entry", why)) return c.fail(NOT + why);
        const JsonVal* sid = e.get("signer_id");
        if (!sid || sid->type != JsonVal::String || !id_ok(sid->str))
          return c.fail(NOT + "additional_signers entry needs a signer_id of 1..64 characters");
        PrivySigner ps;
        ps.signerId = sid->str;
        if (const JsonVal* ov = e.get("override_policy_ids")) {
          if (!id_array(ov, "override_policy_ids", ps.overridePolicyIds, why)) return c.fail(NOT + why);
          ps.hasOverride = true;
        }
        t.signers.push_back(ps);
      }
      t.hasSigners = true;
    }
  } else {
    static const char* const QB[] = {"public_keys", "authorization_threshold", "display_name", "user_ids",
                                     "key_quorum_ids"};
    if (!members_allowed(*body, QB, 5, "key quorum update body", why)) return c.fail(NOT + why);
    if (const JsonVal* v = body->get("public_keys")) {
      if (v->type != JsonVal::Array || v->items.empty() || v->items.size() > PRIVY_MAX_ITEMS)
        return c.fail(NOT + "public_keys must be an array of 1..8 keys");
      for (const JsonVal& e : v->items) {
        Bytes xy;
        if (e.type != JsonVal::String || !p256_spki_b64(e.str, xy))
          return c.fail(NOT + "public_keys entries must be base64 DER P-256 public keys (uncompressed)");
        t.publicKeys.push_back(e.str);
        t.publicKeyXY.push_back(xy);
      }
      t.hasPublicKeys = true;
    }
    if (const JsonVal* v = body->get("authorization_threshold")) {
      const std::string& n = v->str;
      bool digits = v->type == JsonVal::Number && !n.empty() && n.size() <= 2 && n[0] != '0';
      for (char ch : n) digits = digits && ch >= '0' && ch <= '9';
      if (!digits) return c.fail(NOT + "authorization_threshold must be an integer 1..99");
      t.threshold = n.size() == 1 ? uint64_t(n[0] - '0') : uint64_t((n[0] - '0') * 10 + (n[1] - '0'));
      t.hasThreshold = true;
    }
    if (const JsonVal* v = body->get("display_name")) {
      if (v->type != JsonVal::String || v->str.size() > PRIVY_MAX_NAME || !printable_ascii(v->str))
        return c.fail(NOT + "display_name must be printable ASCII of at most 64 bytes");
      t.displayName = v->str;
      t.hasDisplayName = true;
    }
    if (const JsonVal* v = body->get("user_ids")) {
      if (!id_array(v, "user_ids", t.userIds, why)) return c.fail(NOT + why);
      t.hasUserIds = true;
    }
    if (const JsonVal* v = body->get("key_quorum_ids")) {
      if (!id_array(v, "key_quorum_ids", t.keyQuorumIds, why)) return c.fail(NOT + why);
      t.hasKeyQuorumIds = true;
    }
  }
  r = std::move(t);
  err.clear();
  return true;
}

// =====================================================================================================================
// digests (rebuilt from parsed fields only)
B32 presence_hash(const uint8_t evidence12[12], const uint8_t salt16[16]) {
  Sha256 s;
  s.update(evidence12, 12);
  s.update(salt16, 16);
  B32 r;
  s.final(r.v);
  return r;
}

B32 cosign_digest(const CosignReq& r) {
  return eip712_digest(domain("RiparPulseCosign", r.chainId, r.enforcer), hash_human_approval(r.h));
}

B32 mandate_digest(const MandateReq& r) {
  return eip712_digest(domain("DelegationManager", r.chainId, r.manager), hash_delegation(r.d));
}

B32 deny_digest(const DenyReq& r, const B32& presenceHash) {
  return eip712_digest(domain("RiparReputationRelay", r.chainId, r.relay),
                       hash_deny(U256::from_u64(r.agentId), r.requestHash, presenceHash));
}

B32 pair_digest(uint64_t chainId, const Addr& registry, const Addr& k1, const uint8_t p1xy[64]) {
  B32 px, py;
  std::memcpy(px.v, p1xy, 32);
  std::memcpy(py.v, p1xy + 32, 32);
  return eip712_digest(domain("RiparDeviceRegistry", chainId, registry), hash_bind_device(k1, px, py));
}

B32 revoke_digest(uint64_t chainId, const Addr& cosignEnforcer, const B32& delegationHash) {
  return eip712_digest(domain("RiparPulseCosign", chainId, cosignEnforcer), hash_revoke(delegationHash));
}

B32 panic_digest(uint64_t chainId, const Addr& cosignEnforcer, uint64_t minEpoch) {
  return eip712_digest(domain("RiparPulseCosign", chainId, cosignEnforcer), hash_panic(minEpoch));
}

B32 reopen_digest(uint64_t chainId, const Addr& sentinel, const Addr& vault, const U256& nonce) {
  return eip712_digest(domain("RiparSentinel", chainId, sentinel), hash_reopen(vault, nonce));
}

B32 cosign_request_hash(const CosignReq& r) {
  HumanApproval h = r.h;  // the reviewed request, independent of any pulse evidence
  h.presenceHash = B32();
  return hash_human_approval(h);
}

// =====================================================================================================================
// responses: canonical CBOR maps, keys ascending, shortest heads
Bytes build_pair(const Bytes& reqId, const Addr& k1, const uint8_t p1xy[64], const uint8_t* p1sig64,
                 const uint8_t* k1sig65, const uint8_t fwid[8]) {
  const size_t n = 3u + (reqId.empty() ? 0u : 1u) + (p1sig64 ? 1u : 0u) + (k1sig65 ? 1u : 0u);
  CborWriter w;
  w.map(n);
  if (!reqId.empty()) {
    w.uint(1);
    w.bytes(reqId);
  }
  w.uint(2);
  w.bytes(k1.v, 20);
  w.uint(3);
  w.bytes(p1xy, 64);
  if (p1sig64) {
    w.uint(4);
    w.bytes(p1sig64, 64);
  }
  if (k1sig65) {
    w.uint(5);
    w.bytes(k1sig65, 65);
  }
  w.uint(6);
  w.bytes(fwid, 8);
  return w.take();
}

Bytes build_cosign(const Bytes& reqId, const uint8_t rs[64], const uint8_t ev12[12], const uint8_t salt16[16]) {
  CborWriter w;
  w.map(4);
  w.uint(1);
  w.bytes(reqId);
  w.uint(2);
  w.bytes(rs, 64);
  w.uint(3);
  w.bytes(ev12, 12);
  w.uint(4);
  w.bytes(salt16, 16);
  return w.take();
}

Bytes build_eth_signature(const Bytes& reqId, const uint8_t rsv[65]) {
  CborWriter w;
  w.map(2);
  w.uint(1);
  w.bytes(reqId);
  w.uint(2);
  w.bytes(rsv, 65);
  return w.take();
}

Bytes build_deny(const DenyReq& r, const uint8_t rs[64], const uint8_t ev12[12], const uint8_t salt16[16]) {
  CborWriter w;  // {1: req-id, 2: r||s, 3: evidence12, 4: salt16, 5: agentId, 6: requestHash}
  w.map(6);
  w.uint(1);
  w.bytes(r.reqId);
  w.uint(2);
  w.bytes(rs, 64);
  w.uint(3);
  w.bytes(ev12, 12);
  w.uint(4);
  w.bytes(salt16, 16);
  w.uint(5);
  w.uint(r.agentId);
  w.uint(6);
  w.bytes(r.requestHash.v, 32);
  return w.take();
}

Bytes build_revoke(const B32& delegationHash, const uint8_t rs[64]) {
  CborWriter w;
  w.map(2);
  w.uint(1);
  w.bytes(delegationHash.v, 32);
  w.uint(2);
  w.bytes(rs, 64);
  return w.take();
}

Bytes build_panic(uint64_t minEpoch, const uint8_t rs[64]) {
  CborWriter w;
  w.map(2);
  w.uint(1);
  w.uint(minEpoch);
  w.uint(2);
  w.bytes(rs, 64);
  return w.take();
}

Bytes build_reopen(const Addr& vault, const U256& nonce, const uint8_t rs[64]) {
  CborWriter w;
  w.map(3);
  w.uint(1);
  w.bytes(vault.v, 20);
  w.uint(2);
  put_u256_min(w, nonce);
  w.uint(3);
  w.bytes(rs, 64);
  return w.take();
}

Bytes build_der_sig(const Bytes& reqId, const Bytes& der) {
  CborWriter w;
  w.map(2);
  w.uint(1);
  w.bytes(reqId);
  w.uint(2);
  w.bytes(der);
  return w.take();
}

}  // namespace ripar
