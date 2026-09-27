// DEPS: hashes util cbor ur eip712 abi crypto protocol enforcers json_strict tokens policy review vault
// Host tests for src/protocol.cpp, src/json_strict.cpp, src/enforcers.cpp (tables) and the token checks of the parser.
// (The pinned-context policy, review lines and caveat decoders are tested in test_policy.cpp.)
//   - every request type parsed from CBOR built by tools/make_request.py (Python, ref_ur.cbor), field by field
//   - digests equal to tools/ref_eip712.py (generic EIP-712 + MetaMask EncoderLib), presence hash = sha256
//   - the full device pipeline: parse -> digest -> sign (crypto.cpp, demo keys) -> response CBOR, byte-equal to the
//     Python response (ref_crypto.py signatures, RFC 6979 so deterministic) and to the Python UR string
//   - 350+ malformed requests (missing keys, wrong types / lengths, unknown keys, non-ROOT authority, empty caveat
//     list, control characters, duplicate / escaped-duplicate JSON keys, keys 15/16 contradicting the firmware token
//     table (B3), every Privy request shape outside the allow-list incl. the review probes /rpc + padding keys (M1),
//     ...) must be refused, output untouched
//   - Privy requests: every allowed value parsed in full (compared with the independent Python parser, M1)
//   - deny: echo of agentId + requestHash; deny built from a co-sign review with the device-computed request hash (M7)
//   - strict JSON parser edge cases, multipart transport of Python-built QR parts, enforcer table
// Vectors: test/host/vectors_protocol.h (python tools/make_request.py gen-vectors / check-vectors).
#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <vector>

#include "abi.h"
#include "cbor.h"
#include "check.h"
#include "crypto.h"
#include "eip712.h"
#include "hashes.h"
#include "json_strict.h"
#include "policy.h"
#include "protocol.h"
#include "review.h"
#include "ur.h"
#include "util.h"
#include "vectors_protocol.h"

using namespace ripar;

// host-only hook in src/enforcers.cpp
namespace ripar {
namespace enforcers_test {
size_t count();
bool row(size_t i, int* table, uint64_t* chainId, const char** addr, const char** name);
}  // namespace enforcers_test
}  // namespace ripar

// ------------------------------------------------------------------ helpers
static int g_bad = 0;
static Bytes HX(const char* s) {
  Bytes b;
  if (!from_hex(s ? s : "", b)) {
    std::printf("bad hex in vector: %.60s\n", s ? s : "(null)");
    g_bad++;
  }
  return b;
}
static Addr A(const char* s) {
  Bytes b = HX(s);
  Addr a;
  if (b.size() == 20)
    std::memcpy(a.v, b.data(), 20);
  else
    g_bad++;
  return a;
}
static B32 B(const char* s) {
  Bytes b = HX(s);
  B32 r;
  if (b.size() == 32)
    std::memcpy(r.v, b.data(), 32);
  else
    g_bad++;
  return r;
}
static bool decode(const char* hex, CborVal& v) {
  Bytes b = HX(hex);
  std::string err;
  bool ok = cbor_decode(b, v, &err);
  if (!ok) std::printf("   cbor_decode failed: %s\n", err.c_str());
  return ok;
}
static std::string hexs(const Bytes& b) { return to_hex(b, false); }

static Bytes demo_k1() { return HX(pv::DEMO_K1_PRIV); }
static Bytes demo_p1() { return HX(pv::DEMO_P1_PRIV); }

static bool note(bool ok, const char* name) {
  if (!ok) std::printf("     vector: %s\n", name);
  return ok;
}

// ------------------------------------------------------------------ sections
static void test_req_type() {
  CHECK_SECTION("req_type_from_ur");
  CHECK_EQ(req_type_from_ur("ripar-pair-req"), ReqType::Pair);
  CHECK_EQ(req_type_from_ur("ripar-cosign-req"), ReqType::Cosign);
  CHECK_EQ(req_type_from_ur("ripar-mandate-req"), ReqType::Mandate);
  CHECK_EQ(req_type_from_ur("ripar-deny-req"), ReqType::Deny);
  CHECK_EQ(req_type_from_ur("ripar-privy-req"), ReqType::Privy);
  CHECK_EQ(req_type_from_ur("RIPAR-COSIGN-REQ"), ReqType::Cosign);
  CHECK_EQ(req_type_from_ur("Ripar-Privy-Req"), ReqType::Privy);
  CHECK_EQ(req_type_from_ur("ripar-cosign"), ReqType::Unknown);
  CHECK_EQ(req_type_from_ur("eth-signature"), ReqType::Unknown);
  CHECK_EQ(req_type_from_ur("thenar-cosign-req"), ReqType::Unknown);
  CHECK_EQ(req_type_from_ur("ripar-pair-req2"), ReqType::Unknown);
  CHECK_EQ(req_type_from_ur(""), ReqType::Unknown);
}

static void test_demo_keys() {
  CHECK_SECTION("demo keys (crypto.cpp vs Python)");
  Bytes k1 = demo_k1(), p1 = demo_p1();
  uint8_t xy[64];
  CHECK(ec_pubkey(Curve::P256, p1.data(), xy));
  CHECK_EQ_HEX(xy, 64, pv::DEMO_P1_XY);
  CHECK(ec_pubkey(Curve::Secp256k1, k1.data(), xy));
  Addr a = eth_address(xy);
  CHECK_EQ_HEX(a.v, 20, pv::DEMO_K1_ADDR);
}

static void test_cosign() {
  CHECK_SECTION("cosign-req: parse, digest, sign, response");
  const Bytes p1 = demo_p1();
  const Bytes p1xy = HX(pv::DEMO_P1_XY);
  for (const pv::Cosign& v : pv::COSIGN) {
    CborVal m;
    if (!note(CHECK(decode(v.cbor, m)), v.name)) continue;
    CosignReq r;
    std::string err;
    if (!note(CHECK(parse_cosign_req(m, r, err)), v.name)) {
      std::printf("     err: %s\n", err.c_str());
      continue;
    }
    CHECK(err.empty());
    CHECK_EQ(hexs(r.reqId), std::string(v.reqId));
    CHECK_EQ(r.chainId, v.chainId);
    CHECK_EQ_HEX(r.enforcer.v, 20, v.enforcer);
    CHECK_EQ_HEX(r.h.delegationHash.v, 32, v.delegationHash);
    CHECK_EQ_HEX(r.h.delegator.v, 20, v.delegator);
    CHECK_EQ_HEX(r.h.redeemer.v, 20, v.redeemer);
    CHECK_EQ_HEX(r.h.target.v, 20, v.target);
    CHECK_EQ_HEX(r.h.value.v, 32, v.value);
    CHECK_EQ(hexs(r.calldata), std::string(v.calldata));
    CHECK_EQ_HEX(r.h.nonce.v, 32, v.nonce);
    CHECK_EQ(r.h.expiry, v.expiry);
    CHECK_EQ(r.risk.present, v.riskPresent != 0);
    CHECK_EQ(r.risk.src, std::string(v.riskSrc));
    CHECK_EQ(r.risk.category, std::string(v.riskCategory));
    CHECK_EQ(r.risk.label, std::string(v.riskLabel));
    CHECK_EQ(r.risk.ageDays, v.riskAge);
    CHECK_EQ(r.ai.present, v.aiPresent != 0);
    CHECK_EQ(r.ai.text, std::string(v.aiText));
    CHECK_EQ(r.ai.hasClaims, v.aiHasClaims != 0);
    CHECK_EQ_HEX(r.ai.to.v, 20, v.aiTo);
    CHECK_EQ_HEX(r.ai.token.v, 20, v.aiToken);
    CHECK_EQ_HEX(r.ai.amount.v, 32, v.aiAmount);
    CHECK_EQ(r.hasBudget, v.hasBudget != 0);
    CHECK_EQ_HEX(r.budgetLeft.v, 32, v.budget);
    CHECK_EQ(r.decimals, v.decimals);
    CHECK_EQ(r.symbol, std::string(v.symbol));
    CHECK_EQ(r.hasDecimals, v.hasDecimals != 0);
    CHECK_EQ(r.hasSymbol, v.hasSymbol != 0);
    // firmware token table (B3): decimals / symbol of the amount come from the table, never from keys 15/16
    note(CHECK_EQ(r.token.listed, v.tokListed != 0), v.name);
    CHECK_EQ(r.token.decimals, v.tokDecimals);
    CHECK_EQ(r.token.symbol, std::string(v.tokSymbol));
    CHECK_EQ(r.token.native, r.call.kind == Erc20Call::None);
    CHECK_EQ_HEX(cosign_request_hash(r).v, 32, v.requestHash);
    // derived by the device
    CHECK_EQ(int(r.call.kind), v.callKind);
    CHECK_EQ_HEX(r.call.from.v, 20, v.callFrom);
    CHECK_EQ_HEX(r.call.to.v, 20, v.callTo);
    CHECK_EQ_HEX(r.call.amount.v, 32, v.callAmount);
    CHECK_EQ(r.call.selector, v.callSelector);
    if (!note(CHECK_EQ(r.aiMatches, v.aiMatches != 0), v.name)) continue;
    CHECK_EQ_HEX(r.h.callDataHash.v, 32, v.callDataHash);
    CHECK(r.h.presenceHash == B32());  // filled in at signing time, not by the parser
    // presence + digest (ref_eip712.py)
    Bytes ev = HX(v.ev12), salt = HX(v.salt16);
    r.h.presenceHash = presence_hash(ev.data(), salt.data());
    CHECK_EQ_HEX(r.h.presenceHash.v, 32, v.presenceHash);
    B32 d = cosign_digest(r);
    if (!note(CHECK_EQ_HEX(d.v, 32, v.digest), v.name)) continue;
    // sign like the device (P1, RFC 6979, low-s) -> identical to ref_crypto.py
    uint8_t rs[64];
    int recid = -1;
    CHECK(ecdsa_sign(Curve::P256, p1.data(), d.v, rs, &recid));
    CHECK_EQ_HEX(rs, 64, v.rs);
    CHECK(ecdsa_verify(Curve::P256, p1xy.data(), d.v, rs));
    Bytes resp = build_cosign(r.reqId, rs, ev.data(), salt.data());
    CHECK_EQ(hexs(resp), std::string(v.resp));
    CHECK_EQ(ur_encode("ripar-cosign", resp), std::string(v.respUr));
  }
}

static void test_mandate() {
  CHECK_SECTION("mandate-req: parse, EIP-712 Delegation, K1 sign, eth-signature");
  const Bytes k1 = demo_k1();
  for (const pv::Mandate& v : pv::MANDATE) {
    CborVal m;
    if (!note(CHECK(decode(v.cbor, m)), v.name)) continue;
    MandateReq r;
    std::string err;
    if (!note(CHECK(parse_mandate_req(m, r, err)), v.name)) {
      std::printf("     err: %s\n", err.c_str());
      continue;
    }
    CHECK_EQ(hexs(r.reqId), std::string(v.reqId));
    CHECK_EQ(r.chainId, v.chainId);
    CHECK_EQ_HEX(r.manager.v, 20, v.manager);
    CHECK_EQ_HEX(r.d.delegate.v, 20, v.delegate);
    CHECK_EQ_HEX(r.d.delegator.v, 20, v.delegator);
    CHECK(r.d.authority == ROOT_AUTHORITY);
    if (!CHECK_EQ(r.d.caveats.size(), v.ncaveats)) continue;
    for (size_t i = 0; i < v.ncaveats; i++) {
      CHECK_EQ_HEX(r.d.caveats[i].enforcer.v, 20, v.caveats[i].enforcer);
      CHECK_EQ(hexs(r.d.caveats[i].terms), std::string(v.caveats[i].terms));
    }
    CHECK_EQ_HEX(r.d.salt.v, 32, v.salt);
    CHECK_EQ(r.label, std::string(v.label));
    CHECK_EQ(r.hasAgentId, v.hasAgentId != 0);
    CHECK_EQ(r.agentId, v.agentId);
    B32 sh = hash_delegation(r.d);
    CHECK_EQ_HEX(sh.v, 32, v.delegationHash);
    B32 d = mandate_digest(r);
    if (!note(CHECK_EQ_HEX(d.v, 32, v.digest), v.name)) continue;
    uint8_t rsv[65];
    int recid = -1;
    CHECK(ecdsa_sign(Curve::Secp256k1, k1.data(), d.v, rsv, &recid));
    CHECK(recid == 0 || recid == 1);
    rsv[64] = uint8_t(27 + recid);
    CHECK_EQ_HEX(rsv, 65, v.rsv);
    uint8_t xy[64];
    CHECK(ecdsa_recover(Curve::Secp256k1, d.v, rsv, recid, xy));
    CHECK_EQ_HEX(eth_address(xy).v, 20, pv::DEMO_K1_ADDR);
    Bytes resp = build_eth_signature(r.reqId, rsv);
    CHECK_EQ(hexs(resp), std::string(v.resp));
    CHECK_EQ(ur_encode("eth-signature", resp), std::string(v.respUr));
  }
}

static void test_deny() {
  CHECK_SECTION("deny-req: parse, Deny digest, P1 sign, response");
  const Bytes p1 = demo_p1();
  for (const pv::Deny& v : pv::DENY) {
    CborVal m;
    if (!note(CHECK(decode(v.cbor, m)), v.name)) continue;
    DenyReq r;
    std::string err;
    if (!note(CHECK(parse_deny_req(m, r, err)), v.name)) {
      std::printf("     err: %s\n", err.c_str());
      continue;
    }
    CHECK_EQ(hexs(r.reqId), std::string(v.reqId));
    CHECK_EQ(r.chainId, v.chainId);
    CHECK_EQ_HEX(r.relay.v, 20, v.relay);
    CHECK_EQ(r.agentId, v.agentId);
    CHECK_EQ_HEX(r.requestHash.v, 32, v.requestHash);
    Bytes ev = HX(v.ev12), salt = HX(v.salt16);
    B32 ph = presence_hash(ev.data(), salt.data());
    CHECK_EQ_HEX(ph.v, 32, v.presenceHash);
    B32 d = deny_digest(r, ph);
    if (!note(CHECK_EQ_HEX(d.v, 32, v.digest), v.name)) continue;
    uint8_t rs[64];
    CHECK(ecdsa_sign(Curve::P256, p1.data(), d.v, rs, nullptr));
    CHECK_EQ_HEX(rs, 64, v.rs);
    Bytes resp = build_deny(r, rs, ev.data(), salt.data());
    CHECK_EQ(hexs(resp), std::string(v.resp));
    CHECK_EQ(ur_encode("ripar-deny", resp), std::string(v.respUr));
    CborVal back;
    CHECK(cbor_decode(resp, back));
    CHECK(cbor_get(back, 5) && cbor_get(back, 5)->type == CborVal::UInt && cbor_get(back, 5)->u == r.agentId);
    CHECK(cbor_get(back, 6) && cbor_get(back, 6)->b == Bytes(r.requestHash.v, r.requestHash.v + 32));
  }

  CHECK_SECTION("deny from a co-sign review: device-computed requestHash (MINOR 7)");
  for (const pv::DenyFromCosign& v : pv::DENY_FROM_COSIGN) {
    CborVal m;
    CHECK(decode(pv::COSIGN[v.cosign].cbor, m));
    CosignReq c;
    std::string err;
    if (!CHECK(parse_cosign_req(m, c, err))) continue;
    Context ctx;  // the device's pinned context
    ctx.chainId = v.chainId;
    ctx.relay = A(v.relay);
    ctx.hasAgentId = true;
    ctx.agentId = v.agentId;
    DenyReq d;
    if (!CHECK(deny_from_cosign(c, ctx, d, err))) continue;
    CHECK(d.reqId == c.reqId);
    CHECK_EQ(d.chainId, v.chainId);
    CHECK_EQ_HEX(d.relay.v, 20, v.relay);
    CHECK_EQ(d.agentId, v.agentId);
    CHECK_EQ_HEX(d.requestHash.v, 32, v.requestHash);
    // the hash is of the REVIEWED request: independent of any presenceHash set later
    CosignReq c2 = c;
    c2.h.presenceHash.v[0] ^= 0xFF;
    CHECK(cosign_request_hash(c2) == d.requestHash);
    c2 = c;
    c2.h.nonce.v[31] ^= 1;
    CHECK(!(cosign_request_hash(c2) == d.requestHash));
    Bytes ev = HX(v.ev12), salt = HX(v.salt16);
    B32 dg = deny_digest(d, presence_hash(ev.data(), salt.data()));
    CHECK_EQ_HEX(dg.v, 32, v.digest);
    uint8_t rs[64];
    CHECK(ecdsa_sign(Curve::P256, p1.data(), dg.v, rs, nullptr));
    CHECK_EQ_HEX(rs, 64, v.rs);
    Bytes resp = build_deny(d, rs, ev.data(), salt.data());
    CHECK_EQ(hexs(resp), std::string(v.resp));
    CHECK_EQ(ur_encode("ripar-deny", resp), std::string(v.respUr));
  }
}

static void test_pair() {
  CHECK_SECTION("pair-req: parse, BindDevice (P1 + K1), ripar-pair");
  const Bytes p1 = demo_p1(), k1 = demo_k1();
  const Bytes xy = HX(pv::DEMO_P1_XY);
  const Addr k1addr = A(pv::DEMO_K1_ADDR);
  for (const pv::Pair& v : pv::PAIR) {
    CborVal m;
    if (!note(CHECK(decode(v.cbor, m)), v.name)) continue;
    PairReq r;
    std::string err;
    if (!note(CHECK(parse_pair_req(m, r, err)), v.name)) {
      std::printf("     err: %s\n", err.c_str());
      continue;
    }
    CHECK_EQ(hexs(r.reqId), std::string(v.reqId));
    CHECK_EQ(r.chainId, v.chainId);
    CHECK_EQ_HEX(r.registry.v, 20, v.registry);
    CHECK_EQ_HEX(r.manager.v, 20, v.manager);
    CHECK_EQ_HEX(r.enforcer.v, 20, v.enforcer);
    CHECK_EQ_HEX(r.sentinel.v, 20, v.sentinel);
    CHECK_EQ_HEX(r.relay.v, 20, v.relay);
    CHECK_EQ_HEX(r.vault.v, 20, v.vault);
    CHECK_EQ(r.hasNow, v.hasNow != 0);
    CHECK_EQ(r.now, v.now);
    CHECK_EQ(r.hasMinEpoch, v.hasMinEpoch != 0);  // keys 10 / 11: counter floors (security review N1)
    CHECK_EQ(r.minEpoch, v.minEpoch);
    CHECK_EQ(r.hasReopenNonce, v.hasReopenNonce != 0);
    CHECK_EQ(r.reopenNonce, v.reopenNonce);
    B32 d = pair_digest(r.chainId, r.registry, k1addr, xy.data());
    if (!note(CHECK_EQ_HEX(d.v, 32, v.digest), v.name)) continue;
    uint8_t p1sig[64], k1sig[65];
    int recid = -1;
    CHECK(ecdsa_sign(Curve::P256, p1.data(), d.v, p1sig, nullptr));
    CHECK(ecdsa_sign(Curve::Secp256k1, k1.data(), d.v, k1sig, &recid));
    k1sig[64] = uint8_t(27 + recid);
    CHECK_EQ_HEX(p1sig, 64, v.p1sig);
    CHECK_EQ_HEX(k1sig, 65, v.k1sig);
    Bytes fw = HX(v.fwid);
    Bytes resp = build_pair(r.reqId, k1addr, xy.data(), p1sig, k1sig, fw.data());
    CHECK_EQ(hexs(resp), std::string(v.resp));
    CHECK_EQ(ur_encode("ripar-pair", resp), std::string(v.respUr));
    Bytes noreq = build_pair(Bytes(), k1addr, xy.data(), nullptr, nullptr, fw.data());  // home screen -> PAIR
    CHECK_EQ(hexs(noreq), std::string(v.respNoReq));
  }
}

// Canonical text of a parsed Privy request (same format as make_request.py privy_dump()).
static std::string join(const std::vector<std::string>& v, const char* sep) {
  std::string o;
  for (size_t i = 0; i < v.size(); i++) o += (i ? sep : "") + v[i];
  return o;
}
static std::string privy_dump(const PrivyReq& r) {
  std::string o = std::string("kind=") + (r.kind == PrivyReq::WalletUpdate ? "wallet" : "key_quorum") +
                  " id=" + r.resourceId + " app=" + r.appId + " idem=" + (r.idempotencyKey.empty() ? "-" : r.idempotencyKey);
  if (r.hasPolicyIds) o += "\npolicy_ids=" + join(r.policyIds, ",");
  if (r.hasSigners) {
    std::vector<std::string> sg;
    for (const PrivySigner& s : r.signers)
      sg.push_back(s.signerId + (s.hasOverride ? "[" + join(s.overridePolicyIds, ",") + "]" : std::string()));
    o += "\nsigners=" + join(sg, ";");
  }
  if (r.hasPublicKeys) {
    std::vector<std::string> ks;
    for (const Bytes& k : r.publicKeyXY) ks.push_back(to_hex(k, false));
    o += "\npublic_keys=" + join(ks, ",");
  }
  if (r.hasThreshold) o += "\nthreshold=" + std::to_string(static_cast<unsigned long long>(r.threshold));
  if (r.hasDisplayName) o += "\ndisplay_name=" + r.displayName;
  if (r.hasUserIds) o += "\nuser_ids=" + join(r.userIds, ",");
  if (r.hasKeyQuorumIds) o += "\nkey_quorum_ids=" + join(r.keyQuorumIds, ",");
  return o;
}

static void test_privy() {
  CHECK_SECTION("privy-req: allow-listed shapes parsed in full, sha256, DER, ripar-der-sig");
  const Bytes p1 = demo_p1();
  const Bytes xy = HX(pv::DEMO_P1_XY);
  for (const pv::Privy& v : pv::PRIVY) {
    CborVal m;
    if (!note(CHECK(decode(v.cbor, m)), v.name)) continue;
    PrivyReq r;
    std::string err;
    if (!note(CHECK(parse_privy_req(m, r, err)), v.name)) {
      std::printf("     err: %s\n", err.c_str());
      continue;
    }
    CHECK_EQ(hexs(r.reqId), std::string(v.reqId));
    CHECK_EQ(hexs(r.json), std::string(v.json));
    CHECK_EQ(r.method, std::string(v.method));
    CHECK_EQ(r.path, std::string(v.path));
    CHECK_EQ(int(r.kind), v.kind);
    if (!note(CHECK_EQ(privy_dump(r), std::string(v.dump)), v.name)) continue;
    // every public key is kept exactly as sent (base64) and decoded to x||y
    CHECK_EQ(r.publicKeys.size(), r.publicKeyXY.size());
    uint8_t sha[32];
    sha256(r.json.data(), r.json.size(), sha);
    CHECK_EQ_HEX(sha, 32, v.sha);
    uint8_t rs[64], der[72];
    CHECK(ecdsa_sign(Curve::P256, p1.data(), sha, rs, nullptr));
    CHECK(ecdsa_verify(Curve::P256, xy.data(), sha, rs));
    size_t n = ecdsa_der(rs, der);
    CHECK_EQ(hexs(Bytes(der, der + n)), std::string(v.der));
    Bytes resp = build_der_sig(r.reqId, Bytes(der, der + n));
    CHECK_EQ(hexs(resp), std::string(v.resp));
    CHECK_EQ(ur_encode("ripar-der-sig", resp), std::string(v.respUr));
  }
  CHECK_SECTION("privy-req: review probes (security review M1)");
  {  // the hidden second signer of the old summary is now a full value
    CborVal m;
    decode(pv::PRIVY[3].cbor, m);
    PrivyReq r;
    std::string err;
    CHECK(parse_privy_req(m, r, err));
    CHECK_EQ(r.signers.size(), size_t(2));
    if (r.signers.size() == 2) CHECK_EQ(r.signers[1].signerId, std::string("ATTACKERkq0000000000000000"));
  }
  size_t probes = 0;
  for (const pv::Invalid& v : pv::INVALID) {
    const std::string n(v.name);
    const bool probe = n.find("review probe M1") != std::string::npos;
    if (!probe) continue;
    probes++;
    CborVal m;
    decode(v.cbor, m);
    PrivyReq r;
    std::string err;
    CHECK(!parse_privy_req(m, r, err));
    CHECK(err.find("not an allowed Privy request") != std::string::npos);
  }
  CHECK_EQ(probes, size_t(2));  // /rpc eth_sendTransaction + padding keys
}

static void test_invalid() {
  CHECK_SECTION("malformed requests are refused (output untouched)");
  size_t n = 0;
  for (const pv::Invalid& v : pv::INVALID) {
    n++;
    CborVal m;
    if (!note(CHECK(decode(v.cbor, m)), v.name)) continue;  // must be well-formed CBOR: the PARSER refuses it
    std::string err;
    bool ok = true;
    Bytes sentinel(16, 0xA5);
    switch (v.type) {
      case 0: {
        PairReq r;
        r.reqId = sentinel;
        r.chainId = 777;
        ok = parse_pair_req(m, r, err);
        CHECK(r.reqId == sentinel && r.chainId == 777);
        break;
      }
      case 1: {
        CosignReq r;
        r.reqId = sentinel;
        r.decimals = 77;
        ok = parse_cosign_req(m, r, err);
        CHECK(r.reqId == sentinel && r.decimals == 77 && !r.aiMatches && r.calldata.empty());
        break;
      }
      case 2: {
        MandateReq r;
        r.reqId = sentinel;
        ok = parse_mandate_req(m, r, err);
        CHECK(r.reqId == sentinel && r.d.caveats.empty());
        break;
      }
      case 3: {
        DenyReq r;
        r.reqId = sentinel;
        ok = parse_deny_req(m, r, err);
        CHECK(r.reqId == sentinel);
        break;
      }
      case 4: {
        PrivyReq r;
        r.reqId = sentinel;
        ok = parse_privy_req(m, r, err);
        CHECK(r.reqId == sentinel && r.json.empty() && r.method.empty());
        break;
      }
      default:
        CHECK(false);
    }
    note(CHECK(!ok), v.name);
    note(CHECK(!err.empty()), v.name);
  }
  CHECK(n > 350);
  std::printf("   %u malformed requests refused\n", unsigned(n));

  // error messages name the problem
  CHECK_SECTION("error messages");
  {
    CborVal m;
    decode(pv::MANDATE[1].cbor, m);
    for (size_t i = 0; i + 1 < m.items.size(); i += 2)
      if (m.items[i].u == 6) m.items[i + 1].b.assign(32, 0);
    MandateReq r;
    std::string err;
    CHECK(!parse_mandate_req(m, r, err));
    CHECK(err.find("ROOT") != std::string::npos);
    CHECK(err.find("key 6") != std::string::npos);
  }
  {
    CborVal m;
    decode(pv::COSIGN[1].cbor, m);
    for (size_t i = 0; i + 1 < m.items.size(); i += 2)
      if (m.items[i].u == 7) m.items[i + 1].b.resize(19);
    CosignReq r;
    std::string err;
    CHECK(!parse_cosign_req(m, r, err));
    CHECK_EQ(err, std::string("cosign-req: key 7 (target) must be a 20-byte address"));
  }
  {  // review probe B3: AUSD with key 15 = 18 would show 1e12 base units as 0.000001
    CborVal m;
    decode(pv::COSIGN[15].cbor, m);
    CosignReq ok;
    std::string err;
    CHECK(parse_cosign_req(m, ok, err));
    CHECK(ok.token.listed && ok.token.decimals == 6 && ok.token.symbol == "AUSD");
    CHECK_EQ(token_amount(ok.token, ok.call.amount), std::string("1,000,000 AUSD"));
    m.items.push_back(CborVal());
    m.items.back().type = CborVal::UInt;
    m.items.back().u = 15;
    m.items.push_back(CborVal());
    m.items.back().type = CborVal::UInt;
    m.items.back().u = 18;
    CosignReq r;
    CHECK(!parse_cosign_req(m, r, err));
    CHECK(err.find("key 15 (decimals) = 18 disagrees with the firmware token table") != std::string::npos);
  }
  {
    CborVal m;  // wrong request type handed to a parser -> refused, not misread
    decode(pv::DENY[0].cbor, m);
    CosignReq r;
    std::string err;
    CHECK(!parse_cosign_req(m, r, err));
    MandateReq r2;
    CHECK(!parse_mandate_req(m, r2, err));
    PairReq r3;
    CHECK(!parse_pair_req(m, r3, err));
    PrivyReq r4;
    CHECK(!parse_privy_req(m, r4, err));
  }
  {
    CborVal m;  // pair-req counter floors: below 2^63 only
    decode(pv::PAIR[0].cbor, m);
    for (size_t i = 0; i + 1 < m.items.size(); i += 2)
      if (m.items[i].u == 10) m.items[i + 1].u = uint64_t(1) << 63;
    PairReq r;
    std::string err;
    CHECK(!parse_pair_req(m, r, err));
    CHECK(err.find("key 10 (minEpoch floor) must be below 2^63") != std::string::npos);
  }
}

static bool jparse(const std::string& s, JsonVal& v, std::string* err = nullptr) {
  return json_parse_strict(reinterpret_cast<const uint8_t*>(s.data()), s.size(), v, err);
}

static void test_json() {
  CHECK_SECTION("json_parse_strict: vectors");
  for (const pv::JsonDoc& d : pv::JSON_VALID) {
    Bytes b = HX(d.hex);
    JsonVal v;
    std::string err;
    if (!CHECK(json_parse_strict(b.data(), b.size(), v, &err))) std::printf("     doc %s: %s\n", d.hex, err.c_str());
  }
  for (const pv::JsonDoc& d : pv::JSON_INVALID) {
    Bytes b = HX(d.hex);
    JsonVal v;
    v.str = "keep";
    std::string err;
    if (!CHECK(!json_parse_strict(b.data(), b.size(), v, &err))) std::printf("     doc %s accepted\n", d.hex);
    CHECK(!err.empty());
    CHECK(v.type == JsonVal::Null && v.str == "keep");
  }

  CHECK_SECTION("json_parse_strict: values");
  JsonVal v;
  CHECK(jparse("{\"a\":\"x\\u00e9\\ud83d\\ude00\\n\\/\",\"b\":[1,-0.5e+3,true,false,null],\"c\":{}}", v));
  CHECK(v.type == JsonVal::Object);
  CHECK_EQ(v.keys.size(), size_t(3));
  const JsonVal* a = v.get("a");
  CHECK(a && a->type == JsonVal::String && a->str == "x\xc3\xa9\xf0\x9f\x98\x80\n/");
  const JsonVal* b = v.get("b");
  CHECK(b && b->type == JsonVal::Array && b->items.size() == 5);
  if (b && b->items.size() == 5) {
    CHECK(b->items[0].type == JsonVal::Number && b->items[0].str == "1");
    CHECK(b->items[1].type == JsonVal::Number && b->items[1].str == "-0.5e+3");
    CHECK(b->items[2].type == JsonVal::Bool && b->items[2].boolean);
    CHECK(b->items[3].type == JsonVal::Bool && !b->items[3].boolean);
    CHECK(b->items[4].type == JsonVal::Null);
  }
  CHECK(v.get("c") && v.get("c")->type == JsonVal::Object && v.get("c")->items.empty());
  CHECK(v.get("d") == nullptr);
  CHECK(v.get(nullptr) == nullptr);
  CHECK(v.get("b")->get("x") == nullptr);  // not an object

  CHECK_SECTION("json_parse_strict: limits");
  std::string d16 = std::string(16, '[') + std::string(16, ']');
  std::string d17 = std::string(17, '[') + std::string(17, ']');
  std::string o16, o17;
  for (int i = 0; i < 16; i++) o16 += "{\"k\":";
  o16 += "1" + std::string(16, '}');
  for (int i = 0; i < 17; i++) o17 += "{\"k\":";
  o17 += "1" + std::string(17, '}');
  CHECK(jparse(d16, v));
  CHECK(!jparse(d17, v));
  CHECK(jparse(o16, v));
  CHECK(!jparse(o17, v));
  std::string many = "[";
  for (int i = 0; i < 2047; i++) many += i ? ",0" : "0";
  many += "]";  // 2048 values incl. the array
  CHECK(jparse(many, v));
  std::string toomany = many.substr(0, many.size() - 1) + ",0]";
  CHECK(!jparse(toomany, v));
  std::string big = "\"" + std::string(16382, 'a') + "\"";  // 16384 bytes
  CHECK(jparse(big, v));
  CHECK(!jparse(big + " ", v));  // 16385 bytes
  CHECK(!jparse("{\"a\":1,\"\\u0061\":2}", v));
  CHECK(!jparse("{\"\\ud83d\\ude00\":1,\"\xf0\x9f\x98\x80\":2}", v));  // escaped vs raw astral key
  CHECK(jparse("{\"a\":{\"a\":1}}", v));                             // same name at different levels is fine
  CHECK(jparse("[{\"a\":1},{\"a\":2}]", v));
  std::string err;
  CHECK(!jparse("{\"a\":1,\"a\":1}", v, &err));
  CHECK(err.find("duplicate") != std::string::npos);
  CHECK(!json_parse_strict(nullptr, 1, v, &err));
  CHECK(!json_parse_strict(nullptr, 0, v, &err));
}

static void test_device_initiated() {
  CHECK_SECTION("revoke / panic / reopen: digests, signatures, CBOR");
  const Bytes p1 = demo_p1();
  for (const pv::Revoke& v : pv::REVOKE) {
    B32 dh = B(v.delegationHash);
    B32 d = revoke_digest(v.chainId, A(v.enforcer), dh);
    CHECK_EQ_HEX(d.v, 32, v.digest);
    uint8_t rs[64];
    CHECK(ecdsa_sign(Curve::P256, p1.data(), d.v, rs, nullptr));
    CHECK_EQ_HEX(rs, 64, v.rs);
    Bytes resp = build_revoke(dh, rs);
    CHECK_EQ(hexs(resp), std::string(v.resp));
    CHECK_EQ(ur_encode("ripar-revoke", resp), std::string(v.respUr));
  }
  for (const pv::Panic& v : pv::PANIC) {
    B32 d = panic_digest(v.chainId, A(v.enforcer), v.minEpoch);
    CHECK_EQ_HEX(d.v, 32, v.digest);
    uint8_t rs[64];
    CHECK(ecdsa_sign(Curve::P256, p1.data(), d.v, rs, nullptr));
    CHECK_EQ_HEX(rs, 64, v.rs);
    Bytes resp = build_panic(v.minEpoch, rs);
    CHECK_EQ(hexs(resp), std::string(v.resp));
    CHECK_EQ(ur_encode("ripar-panic", resp), std::string(v.respUr));
  }
  for (const pv::Reopen& v : pv::REOPEN) {
    Bytes nb = HX(v.nonce);
    U256 nonce;
    CHECK(U256::from_be(nb.data(), nb.size(), nonce));
    B32 d = reopen_digest(v.chainId, A(v.sentinel), A(v.vault), nonce);
    CHECK_EQ_HEX(d.v, 32, v.digest);
    uint8_t rs[64];
    CHECK(ecdsa_sign(Curve::P256, p1.data(), d.v, rs, nullptr));
    CHECK_EQ_HEX(rs, 64, v.rs);
    Bytes resp = build_reopen(A(v.vault), nonce, rs);
    CHECK_EQ(hexs(resp), std::string(v.resp));
    CHECK_EQ(ur_encode("ripar-reopen", resp), std::string(v.respUr));
  }
}

static void test_multipart() {
  CHECK_SECTION("multipart QR parts from make_request.py -> UrDecoder -> parser");
  for (const pv::Multi& v : pv::MULTI) {
    UrDecoder dec;
    size_t completedAt = 0;
    for (size_t i = 0; i < v.nparts; i++) {
      UrDecoder::Result res = dec.receive(v.parts[i]);
      if (res == UrDecoder::Complete) {
        completedAt = i + 1;
        break;
      }
      if (!CHECK(res == UrDecoder::Accepted)) std::printf("     %s part %u: %s\n", v.name, unsigned(i), dec.error().c_str());
    }
    note(CHECK_EQ(completedAt, v.completeAt), v.name);
    if (!CHECK(dec.complete())) continue;
    CHECK_EQ(hexs(dec.message()), std::string(v.cbor));
    CborVal m;
    CHECK(cbor_decode(dec.message(), m));
    std::string err;
    switch (req_type_from_ur(dec.type())) {
      case ReqType::Cosign: {
        CosignReq r;
        CHECK(parse_cosign_req(m, r, err));
        break;
      }
      case ReqType::Mandate: {
        MandateReq r;
        CHECK(parse_mandate_req(m, r, err));
        break;
      }
      case ReqType::Privy: {
        PrivyReq r;
        CHECK(parse_privy_req(m, r, err));
        break;
      }
      default:
        CHECK(false);
    }
  }
}

static void test_enforcers() {
  CHECK_SECTION("enforcer + pinned-contract tables");
  std::set<std::string> seen;
  size_t decoded = 0, refused = 0, placeholders = 0, managers = 0, ripar = 0;
  for (size_t i = 0; i < enforcers_test::count(); i++) {
    int table = -1;
    uint64_t chain = 0;
    const char *addr = nullptr, *name = nullptr;
    if (!CHECK(enforcers_test::row(i, &table, &chain, &addr, &name))) break;
    CHECK(name && std::strlen(name) > 0 && std::strlen(name) <= 40);
    for (const char* p = name; p && *p; p++) CHECK(*p >= 0x20 && *p < 0x7F);
    if (!addr || !*addr) {
      // firmware v1.2 (since its review): every Ripar contract but the sentinel is compiled in on both chains
      placeholders++;
      CHECK(false);
      continue;
    }
    Addr a = A(addr);
    CHECK_EQ(addr_checksum(a), std::string(addr));  // every address is a valid EIP-55 checksum (catches typos)
    Addr x;
    switch (table) {
      case 0:
        ripar++;
        CHECK(compiled_cosign_enforcer(chain, x) && x == a);
        CHECK(enforcer_name(chain, a) != nullptr);
        break;
      case 4:
        ripar++;
        CHECK(compiled_registry(chain, x) && x == a);
        CHECK(enforcer_name(chain, a) == nullptr);  // not an enforcer
        break;
      case 5:
        ripar++;
        CHECK(compiled_relay(chain, x) && x == a);
        CHECK(enforcer_name(chain, a) == nullptr);  // not an enforcer
        break;
      case 1:
        managers++;
        CHECK(compiled_delegation_manager(chain, x) && x == a);
        CHECK(enforcer_name(chain, a) == nullptr);  // not an enforcer
        break;
      case 2:
        decoded++;
        CHECK(seen.insert(addr).second);
        CHECK_EQ(std::string(enforcer_name(10143, a) ? enforcer_name(10143, a) : ""), std::string(name));
        CHECK_EQ(std::string(enforcer_name(143, a) ? enforcer_name(143, a) : ""), std::string(name));
        CHECK(enforcer_name(1, a) == nullptr);
        CHECK(enforcer_name(0, a) == nullptr);
        CHECK(enforcer_refused_name(10143, a) == nullptr);
        break;
      case 3:
        refused++;
        CHECK(seen.insert(addr).second);
        CHECK(enforcer_name(10143, a) == nullptr);  // known, but no terms decoder -> refused (M4)
        CHECK(enforcer_name(143, a) == nullptr);
        CHECK_EQ(std::string(enforcer_refused_name(10143, a) ? enforcer_refused_name(10143, a) : ""), std::string(name));
        CHECK(enforcer_refused_name(1, a) == nullptr);
        break;
      default:
        CHECK(false);
    }
  }
  CHECK_EQ(decoded, size_t(8));
  CHECK_EQ(refused, size_t(25));
  CHECK_EQ(managers, size_t(2));
  CHECK_EQ(ripar, size_t(6));         // enforcer, registry and relay on 10143 + 143
  CHECK_EQ(placeholders, size_t(0));  // (v1.2 before its review: the relay on 143 was a placeholder)
  CHECK(!enforcers_test::row(enforcers_test::count(), nullptr, nullptr, nullptr, nullptr));
  std::printf("   %u decoded + %u refused MetaMask v1.3.0 enforcers, %u Ripar contracts compiled in, %u placeholders\n",
              unsigned(decoded), unsigned(refused), unsigned(ripar), unsigned(placeholders));

  // independent copy of the firmware v1.2 Ripar addresses (CREATE2 from the bytecode frozen at main 5cea7cf)
  {
    Addr x;
    CHECK(compiled_cosign_enforcer(10143, x) && addr_checksum(x) == "0x64d61fe5438981DC803ED61250FEf024617ae7eE");
    CHECK(compiled_cosign_enforcer(143, x) && addr_checksum(x) == "0x64d61fe5438981DC803ED61250FEf024617ae7eE");
    CHECK(compiled_registry(10143, x) && addr_checksum(x) == "0xA08a47c9d645926615CF04D69b7a048133F68c9f");
    CHECK(compiled_registry(143, x) && addr_checksum(x) == "0xA08a47c9d645926615CF04D69b7a048133F68c9f");
    CHECK(compiled_relay(10143, x) && addr_checksum(x) == "0xE433dCA75CA6cd730b1006F51A26208B000eA9E2");
    // 143: other constructor arguments (the chain's ERC-8004 registries), all public constants of the deploy config
    CHECK(compiled_relay(143, x) && addr_checksum(x) == "0x108BA102F7D0915f51c93F128b96Bd24F647f06d");
    CHECK(x == A(pv::RELAY_143));  // == tools/make_request.py RIPAR_RELAY[143]
    CHECK(!compiled_cosign_enforcer(1, x) && !compiled_registry(1, x) && !compiled_relay(1, x));
    CHECK_EQ(std::string(enforcer_name(10143, A(pv::PULSE_ENFORCER))), std::string("Pulse co-sign + spend caps"));
  }

  struct Known {
    const char* addr;
    const char* name;
  };
  // independent copy of a few rows (MetaMask delegation-framework documents/Deployments.md v1.3.0)
  static const Known KNOWN[] = {
      {"0x7F20f61b1f09b08D970938F6fa563634d65c4EeB", "Only listed contracts"},
      {"0x474e3Ae7E169e940607cC624Da8A15Eb120139aB", "ERC-20 cap per period"},
      {"0xf100b0819427117EcF76Ed94B358B1A5b5C6D2Fc", "ERC-20 total spend cap"},
      {"0xF71af580b9c3078fbc2BBF16FbB8EEd82b330320", "MON total spend cap"},
      {"0x1046bb45C8d673d4ea75321280DB34899413c069", "Valid time window"},
      {"0x04658B29F6b82ed55274221a06Fc97D318E25416", "Limited number of calls"},
      {"0xE144b0b2618071B4E56f746313528a669c7E65c5", "Only listed redeemers"},
      {"0x92Bf12322527cAA612fd31a0e810472BBB106A8F", "Max MON value per call"},
  };
  for (const Known& k : KNOWN) {
    const char* n = enforcer_name(10143, A(k.addr));
    CHECK_EQ(std::string(n ? n : "(null)"), std::string(k.name));
  }
  static const char* const REFUSED[] = {
      "0xDE4f2FAC4B3D87A1d9953Ca5FC09FCa7F366254f",  // NonceEnforcer (review probe B2: nonce-only mandate)
      "0xc2b0d624c1c4319760C96503BA27C347F3260f55",  // AllowedCalldataEnforcer (no decoder)
      "0x2c21fD0Cb9DC8445CB3fb0DC5E7Bb0Aca01842B5",  // AllowedMethodsEnforcer (no decoder)
      "0x9BC0FAf4Aca5AE429F4c06aEEaC517520CB16BD9",  // NativeTokenPeriodTransferEnforcer (no decoder)
      "0xE1302607a3251AF54c3a6e69318d6aa07F5eB46c",  // LogicalOrWrapperEnforcer
      "0x24ff2AA430D53a8CD6788018E902E098083dcCd2",  // DeployedEnforcer
      "0x4803a326ddED6dDBc60e659e5ed12d85c7582811",  // NativeTokenPaymentEnforcer
      "0x1e141e455d08721Dd5BCDA1BaA6Ea5633Afd5017",  // ExactExecutionBatchEnforcer
      "0x982FD5C86BBF425d7d1451f974192d4525113DfD",  // ExactCalldataBatchEnforcer
      "0x6649b61c873F6F9686A1E1ae9ee98aC380c7bA13",  // SpecificActionERC20TransferBatchEnforcer
      "0x7EEf9734E7092032B5C56310Eb9BbD1f4A524681",  // OwnershipTransferEnforcer
      "0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3",  // DelegationManager (not an enforcer)
      "0x0000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000a11",  // ANY_DELEGATE
  };
  for (const char* r : REFUSED) CHECK(enforcer_name(10143, A(r)) == nullptr);
  Addr one = A("0x7F20f61b1f09b08D970938F6fa563634d65c4EeB");
  one.v[19] ^= 1;
  CHECK(enforcer_name(10143, one) == nullptr);
}

static void test_misc_builders() {
  CHECK_SECTION("builders: shapes");
  uint8_t rs[64], ev[12], salt[16];
  for (int i = 0; i < 64; i++) rs[i] = uint8_t(i);
  for (int i = 0; i < 12; i++) ev[i] = uint8_t(0x80 + i);
  for (int i = 0; i < 16; i++) salt[i] = uint8_t(0xC0 + i);
  Bytes rid(16, 0x11);
  Bytes c = build_cosign(rid, rs, ev, salt);
  CHECK_EQ(c.size(), size_t(1 + 1 + 1 + 16 + 1 + 2 + 64 + 1 + 1 + 12 + 1 + 1 + 16));  // map(4) with 4 bstr
  CHECK_EQ(int(c[0]), 0xA4);
  CborVal m;
  CHECK(cbor_decode(c, m));
  CHECK(cbor_get(m, 3) && cbor_get(m, 3)->b == Bytes(ev, ev + 12));
  DenyReq dr;
  dr.reqId = rid;
  dr.agentId = 24;  // CBOR head boundary: 24 needs a 1-byte argument
  dr.requestHash.v[0] = 0x77;
  Bytes dn = build_deny(dr, rs, ev, salt);
  CHECK_EQ(dn.size(), c.size() + 1 + 2 + 1 + 2 + 32);  // + 5: uint(24), 6: bstr(32)
  CHECK_EQ(int(dn[0]), 0xA6);
  CHECK(Bytes(dn.begin() + 1, dn.begin() + long(c.size())) == Bytes(c.begin() + 1, c.end()));
  U256 zero;
  Bytes ro = build_reopen(Addr(), zero, rs);
  CHECK(cbor_decode(ro, m) && cbor_get(m, 2) && cbor_get(m, 2)->b == Bytes(1, 0));  // 0 -> h'00'
  B32 pa = presence_hash(ev, salt);
  uint8_t cat[28], ref[32];
  std::memcpy(cat, ev, 12);
  std::memcpy(cat + 12, salt, 16);
  sha256(cat, 28, ref);
  CHECK_EQ_BYTES(pa.v, ref, 32);
}

int main() {
  test_req_type();
  test_demo_keys();
  test_cosign();
  test_mandate();
  test_deny();
  test_pair();
  test_privy();
  test_invalid();
  test_json();
  test_device_initiated();
  test_multipart();
  test_enforcers();
  test_misc_builders();
  CHECK_SECTION("vector sanity");
  CHECK_EQ(g_bad, 0);
  return CHECK_SUMMARY();
}
