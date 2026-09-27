// DEPS: hashes util cbor ur eip712 abi crypto protocol enforcers json_strict tokens policy review respond context vault
// Host tests for the SIGN step of every flow (src/respond.cpp, called by src/flows.cpp; security review B1):
//   - every response is byte-equal to the independent Python reference (tools/make_request.py simulate, RFC 6979
//     signatures with the demo seed -> test/host/vectors_protocol.h): pair, co-sign, mandate, deny request, deny built
//     from a co-sign review, Privy, revoke, panic, reopen - with the context pinned to each vector
//   - the policy is re-checked at SIGN time: a request the policy refuses is never signed (the signer is not even
//     called) and leaves no output; a failing signature leaves no output
//   - the context update that goes with each signature (Save::Required for pairing / mandate / reopen,
//     Save::BestEffort for co-sign / revoke, Save::Restrict for panic, none for deny / Privy) and the counters it
//     advances; a re-pairing that would abandon a live mandate is never signed (fork review N2)
//   - the co-sign presenceHash is sha256(evidence || salt) of exactly the evidence + salt that are returned
//   - firmware v1.2: the pairing pins the vault derived from K1 (a request naming another vault is never signed), the
//     mandate stores its pulse terms + sets unpanickedMandates, a panic clears it, a re-pairing that moves the chain
//     away from unpanicked mandates is never signed (PANIC FIRST)
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "cbor.h"
#include "check.h"
#include "context.h"
#include "crypto.h"
#include "policy.h"
#include "protocol.h"
#include "respond.h"
#include "ur.h"
#include "util.h"
#include "vault.h"
#include "vectors_protocol.h"

using namespace ripar;

namespace {

int g_bad = 0;
Bytes HX(const char* s) {
  Bytes b;
  if (!from_hex(s ? s : "", b)) g_bad++;
  return b;
}
Addr A(const char* s) {
  const Bytes b = HX(s);
  Addr a;
  if (b.size() == 20)
    std::memcpy(a.v, b.data(), 20);
  else
    g_bad++;
  return a;
}
B32 B(const char* s) {
  const Bytes b = HX(s);
  B32 r;
  if (b.size() == 32)
    std::memcpy(r.v, b.data(), 32);
  else
    g_bad++;
  return r;
}
bool decode(const char* hex, CborVal& v) { return cbor_decode(HX(hex), v); }
std::string hexs(const Bytes& b) { return to_hex(b, false); }

// Demo keys (sha256("ripar demo seed")), as the Python reference; counts calls; can be told to fail.
class DemoSigner : public Signer {
 public:
  DemoSigner() : k1_(HX(pv::DEMO_K1_PRIV)), p1_(HX(pv::DEMO_P1_PRIV)) {}
  bool p1(const B32& d, uint8_t rs[64]) override {
    p1Calls++;
    if (failP1) return false;
    return ecdsa_sign(Curve::P256, p1_.data(), d.v, rs, nullptr);
  }
  bool k1(const B32& d, uint8_t rsv[65]) override {
    k1Calls++;
    if (failK1) return false;
    int recid = -1;
    if (!ecdsa_sign(Curve::Secp256k1, k1_.data(), d.v, rsv, &recid)) return false;
    rsv[64] = uint8_t(27 + recid);
    return true;
  }
  int calls() const { return p1Calls + k1Calls; }
  int p1Calls = 0, k1Calls = 0;
  bool failP1 = false, failK1 = false;

 private:
  Bytes k1_, p1_;
};

bool same_ctx(const Context& a, const Context& b) {
  uint8_t x[CONTEXT_BLOB_SIZE], y[CONTEXT_BLOB_SIZE];
  context_serialize(a, x);
  context_serialize(b, y);
  return std::memcmp(x, y, CONTEXT_BLOB_SIZE) == 0;
}

bool empty(const Response& r) { return r.cbor.empty() && r.save == Save::None && std::strlen(r.urType) == 0; }

}  // namespace

int main() {
  const Bytes xy = HX(pv::DEMO_P1_XY);
  const Addr k1addr = A(pv::DEMO_K1_ADDR);

  // ------------------------------------------------------------------------------------------------------------------
  CHECK_SECTION("pair: BindDevice by P1 + K1, context pinned, Save::Required");
  {
    int signedN = 0;
    for (const pv::Pair& v : pv::PAIR) {
      CborVal m;
      PairReq r;
      std::string err;
      if (!CHECK(decode(v.cbor, m) && parse_pair_req(m, r, err))) continue;
      Context cur;
      cur.minEpoch = 5;
      cur.reopenNonce = 9;
      DemoSigner s;
      Response out;
      const bool want = check_pair(r, cur, k1addr, err);
      const bool ok = respond_pair(r, cur, k1addr, xy.data(), HX(v.fwid).data(), s, out, err);
      CHECK_EQ(ok, want);
      if (!ok) {
        CHECK(empty(out));
        CHECK_EQ(s.calls(), 0);
        CHECK(!err.empty());
        continue;
      }
      signedN++;
      CHECK_EQ(hexs(out.cbor), std::string(v.resp));
      CHECK_EQ(ur_encode(out.urType, out.cbor), std::string(v.respUr));
      CHECK_EQ(std::string(out.urType), std::string("ripar-pair"));
      CHECK(out.save == Save::Required);
      CHECK(same_ctx(out.next, context_after_pair(cur, r, k1addr)));
      CHECK_EQ(out.next.chainId, r.chainId);
      CHECK_EQ_HEX(out.next.vault.v, 20, pv::DEMO_VAULT);  // v1.2: the vault derived from the demo K1, key 8 or not
      CHECK_EQ_HEX(out.next.pulseCosignEnforcer.v, 20, pv::PULSE_ENFORCER);
      CHECK_EQ_HEX(out.next.registry.v, 20, pv::REGISTRY);
      if (r.chainId == 10143) CHECK_EQ_HEX(out.next.relay.v, 20, pv::RELAY_10143);
      if (r.chainId == 143) CHECK_EQ_HEX(out.next.relay.v, 20, pv::RELAY_143);
      // monotonic counters survive a pairing; a companion floor (keys 10 / 11) can only raise them
      CHECK_EQ(out.next.minEpoch, r.hasMinEpoch && r.minEpoch > 5 ? r.minEpoch : 5u);
      CHECK_EQ(out.next.reopenNonce, r.hasReopenNonce && r.reopenNonce > 9 ? r.reopenNonce : 9u);
      CHECK_EQ(s.p1Calls, 1);
      CHECK_EQ(s.k1Calls, 1);
    }
    CHECK(signedN >= 3);
    {
      // a re-pairing that moves the chain while mandates signed since the last panic may be live: refused (PANIC
      // FIRST), nothing signed; the same scope is fine; after a panic the move is signed
      CborVal m;
      PairReq r;
      std::string err;
      decode(pv::PAIR[0].cbor, m);
      parse_pair_req(m, r, err);
      Context cur = context_after_pair(Context(), r, k1addr);
      cur.lastDelegationHash.v[0] = 0x22;
      cur.unpanickedMandates = true;
      PairReq moved = r;
      moved.chainId = 143;
      moved.relay = Addr();  // (the relay compiled in for 143 is pinned)
      DemoSigner s;
      Response out;
      CHECK(!respond_pair(moved, cur, k1addr, xy.data(), HX(pv::PAIR[0].fwid).data(), s, out, err));
      CHECK(err.find("PANIC FIRST") == 0);
      CHECK_EQ(s.calls(), 0);
      CHECK(empty(out));
      CHECK(respond_pair(r, cur, k1addr, xy.data(), HX(pv::PAIR[0].fwid).data(), s, out, err));  // same scope: OK
      CHECK(out.next.lastDelegationHash == cur.lastDelegationHash && out.next.unpanickedMandates);
      Context panicked = cur;
      context_after_panic(panicked, panic_next_epoch(panicked));
      DemoSigner s2;
      CHECK(respond_pair(moved, panicked, k1addr, xy.data(), HX(pv::PAIR[0].fwid).data(), s2, out, err));
      CHECK(out.next.chainId == 143 && out.next.lastDelegationHash == B32() && !out.next.unpanickedMandates);
      // a request naming another vault (key 8) or registry (key 3): refused, nothing signed
      PairReq bad = r;
      bad.vault.v[0] ^= 1;
      DemoSigner s3;
      CHECK(!respond_pair(bad, Context(), k1addr, xy.data(), HX(pv::PAIR[0].fwid).data(), s3, out, err));
      CHECK(err.find("VAULT IS NOT THIS DEVICE'S VAULT") == 0 && s3.calls() == 0 && empty(out));
      bad = r;
      bad.registry.v[19] ^= 1;
      CHECK(!respond_pair(bad, Context(), k1addr, xy.data(), HX(pv::PAIR[0].fwid).data(), s3, out, err));
      CHECK(err.find("WRONG REGISTRY") == 0 && s3.calls() == 0 && empty(out));
      // the same pairing on another device (another K1) pins that device's vault: PAIR[0]'s key 8 is refused there
      Addr otherK1 = k1addr;
      otherK1.v[0] ^= 1;
      CHECK(!respond_pair(r, Context(), otherK1, xy.data(), HX(pv::PAIR[0].fwid).data(), s3, out, err));
      PairReq noVault = r;
      noVault.vault = Addr();
      CHECK(respond_pair(noVault, Context(), otherK1, xy.data(), HX(pv::PAIR[0].fwid).data(), s3, out, err));
      CHECK(out.next.vault == vault_address(otherK1) && !(out.next.vault == A(pv::DEMO_VAULT)));
    }
    // a failing K1 signature: nothing comes out
    CborVal m;
    PairReq r;
    std::string err;
    decode(pv::PAIR[0].cbor, m);
    parse_pair_req(m, r, err);
    DemoSigner s;
    s.failK1 = true;
    Response out;
    const bool ok = respond_pair(r, Context(), k1addr, xy.data(), HX(pv::PAIR[0].fwid).data(), s, out, err);
    CHECK(!ok);
    CHECK(empty(out));
    CHECK(err.find("signature") != std::string::npos);
  }

  // ------------------------------------------------------------------------------------------------------------------
  CHECK_SECTION("co-sign: HumanApproval by P1, presenceHash of the returned evidence + salt, Save::BestEffort");
  {
    int signedN = 0, refusedN = 0;
    for (const pv::Cosign& v : pv::COSIGN) {
      CborVal m;
      CosignReq r;
      std::string err;
      if (!CHECK(decode(v.cbor, m) && parse_cosign_req(m, r, err))) continue;
      Context c;  // pinned to the vector (as test_policy.cpp does)
      c.chainId = r.chainId;
      c.pulseCosignEnforcer = r.enforcer;
      c.vault = r.h.delegator;
      c.notBefore = r.h.expiry < EXPIRY_LIMIT ? r.h.expiry : 0;  // a device time at which the expiry is in range
      const Bytes ev = HX(v.ev12), salt = HX(v.salt16);
      DemoSigner s;
      Response out;
      std::string perr;
      const bool want = check_cosign(r, c, perr);
      const bool ok = respond_cosign(r, c, ev.data(), salt.data(), s, out, err);
      CHECK_EQ(ok, want);
      if (!ok) {
        refusedN++;
        CHECK(empty(out));
        CHECK_EQ(s.calls(), 0);
        CHECK_EQ(err, perr);
        continue;
      }
      signedN++;
      CHECK_EQ_HEX(r.h.presenceHash.v, 32, v.presenceHash);
      CHECK_EQ(hexs(out.cbor), std::string(v.resp));
      CHECK_EQ(ur_encode(out.urType, out.cbor), std::string(v.respUr));
      CHECK(out.save == Save::BestEffort);
      {
        const uint64_t step = effective_not_before(c.notBefore) + NOT_BEFORE_STEP;  // at most 1 day per co-sign
        const uint64_t t = r.h.expiry < step ? r.h.expiry : step;
        CHECK_EQ(out.next.notBefore, t > c.notBefore ? t : c.notBefore);
      }
      CHECK_EQ(s.p1Calls, 1);
      CHECK_EQ(s.k1Calls, 0);  // K1 never signs a co-sign
    }
    CHECK(signedN >= 8);
    CHECK(refusedN >= 1);  // unknown calldata / native value on an ERC-20 call / expiry >= 2^40
    // not paired: refused, never signed
    CborVal m;
    CosignReq r;
    std::string err;
    decode(pv::COSIGN[0].cbor, m);
    parse_cosign_req(m, r, err);
    DemoSigner s;
    Response out;
    const Bytes ev = HX(pv::COSIGN[0].ev12), salt = HX(pv::COSIGN[0].salt16);
    CHECK(!respond_cosign(r, Context(), ev.data(), salt.data(), s, out, err));
    CHECK(err.find("NOT PAIRED") != std::string::npos);
    CHECK_EQ(s.calls(), 0);
    CHECK(empty(out));
  }

  // ------------------------------------------------------------------------------------------------------------------
  CHECK_SECTION("mandate: Delegation by K1 only under the pinned policy, lastDelegationHash, Save::Required");
  {
    for (const pv::PolicyMandate& pm : pv::POLICY_MANDATE) {
      const pv::Mandate& v = pv::MANDATE[pm.mandate];
      CborVal m;
      MandateReq r;
      std::string err;
      if (!CHECK(decode(v.cbor, m) && parse_mandate_req(m, r, err))) continue;
      Context c;
      c.chainId = pm.chainId;
      c.delegationManager = A(pm.manager);
      c.pulseCosignEnforcer = A(pm.pulseEnforcer);
      c.vault = A(pm.vault);
      c.sentinel = A(pm.sentinel);
      c.minEpoch = pm.minEpoch;
      DemoSigner s;
      Response out;
      CHECK(respond_mandate(r, c, xy.data(), s, out, err));
      CHECK_EQ(hexs(out.cbor), std::string(v.resp));
      CHECK_EQ(ur_encode(out.urType, out.cbor), std::string(v.respUr));
      CHECK(out.save == Save::Required);
      CHECK_EQ_HEX(out.next.lastDelegationHash.v, 32, v.delegationHash);
      CHECK_EQ(out.next.hasAgentId, v.hasAgentId != 0);
      CHECK_EQ(out.next.agentId, v.hasAgentId ? v.agentId : 0u);
      CHECK(!c.unpanickedMandates && out.next.unpanickedMandates);  // v3: PANIC FIRST until the next panic
      CHECK_EQ_HEX(out.next.pulseToken.v, 20, "a9012a055bd4e0edff8ce09f960291c09d5322dc");  // the vector's pulse terms
      CHECK(out.next.perTxAutoCap.low_u64() == 25000000 && out.next.periodAutoCap.low_u64() == 50000000);
      CHECK(out.next.period == 86400 && out.next.newPayeeNeedsHuman);
      CHECK_EQ(s.k1Calls, 1);
      CHECK_EQ(s.p1Calls, 0);
      // another vault than the device's: refused, not signed
      Context cv = c;
      cv.vault.v[0] ^= 1;
      DemoSigner s3;
      Response out3;
      CHECK(!respond_mandate(r, cv, xy.data(), s3, out3, err));
      CHECK(err.find("NOT THIS DEVICE'S VAULT") == 0 && s3.calls() == 0 && empty(out3));
      // another device's P1 key in the pulse terms: refused, not signed
      uint8_t other[64];
      std::memcpy(other, xy.data(), 64);
      other[63] ^= 1;
      DemoSigner s2;
      Response out2;
      CHECK(!respond_mandate(r, c, other, s2, out2, err));
      CHECK_EQ(s2.calls(), 0);
      CHECK(empty(out2));
      // a newer panic epoch than the terms carry: refused
      Context c2 = c;
      c2.minEpoch = pm.minEpoch + 1000;
      CHECK(!respond_mandate(r, c2, xy.data(), s2, out2, err));
      CHECK_EQ(s2.calls(), 0);
    }
    // the plain Python mandates are not signable without their pinned context (B2: no pulse caveat / not pinned)
    int refused = 0;
    for (const pv::Mandate& v : pv::MANDATE) {
      CborVal m;
      MandateReq r;
      std::string err;
      if (!decode(v.cbor, m) || !parse_mandate_req(m, r, err)) continue;
      Context c;
      c.chainId = r.chainId;
      c.delegationManager = r.manager;
      DemoSigner s;
      Response out;
      if (!respond_mandate(r, c, xy.data(), s, out, err)) {
        refused++;
        CHECK_EQ(s.calls(), 0);
      }
    }
    CHECK(refused >= 5);
  }

  // ------------------------------------------------------------------------------------------------------------------
  CHECK_SECTION("deny: requests + built from a co-sign review, pinned relay + agent, no context change");
  {
    for (const pv::Deny& v : pv::DENY) {
      CborVal m;
      DenyReq r;
      std::string err;
      if (!CHECK(decode(v.cbor, m) && parse_deny_req(m, r, err))) continue;
      Context c;
      c.chainId = r.chainId;
      c.relay = r.relay;
      c.hasAgentId = true;
      c.agentId = r.agentId;
      DemoSigner s;
      Response out;
      const Bytes ev = HX(v.ev12), salt = HX(v.salt16);
      CHECK(respond_deny(r, c, ev.data(), salt.data(), s, out, err));
      CHECK_EQ(hexs(out.cbor), std::string(v.resp));
      CHECK_EQ(ur_encode(out.urType, out.cbor), std::string(v.respUr));
      CHECK(out.save == Save::None);
      // another agent than the pinned one: refused (MINOR 7)
      c.agentId = r.agentId ^ 1;
      DemoSigner s2;
      CHECK(!respond_deny(r, c, ev.data(), salt.data(), s2, out, err));
      CHECK_EQ(s2.calls(), 0);
      CHECK(empty(out));
    }
    for (const pv::DenyFromCosign& v : pv::DENY_FROM_COSIGN) {
      CborVal m;
      CosignReq cr;
      std::string err;
      if (!CHECK(decode(pv::COSIGN[v.cosign].cbor, m) && parse_cosign_req(m, cr, err))) continue;
      Context c;
      c.chainId = v.chainId;
      c.relay = A(v.relay);
      c.hasAgentId = true;
      c.agentId = v.agentId;
      DenyReq d;
      CHECK(deny_from_cosign(cr, c, d, err));
      CHECK_EQ_HEX(d.requestHash.v, 32, v.requestHash);
      DemoSigner s;
      Response out;
      const Bytes ev = HX(v.ev12), salt = HX(v.salt16);
      CHECK(respond_deny(d, c, ev.data(), salt.data(), s, out, err));
      CHECK_EQ(hexs(out.cbor), std::string(v.resp));
      CHECK_EQ(ur_encode(out.urType, out.cbor), std::string(v.respUr));
    }
  }

  // ------------------------------------------------------------------------------------------------------------------
  CHECK_SECTION("privy: sha256(exact JSON) by P1, DER");
  {
    int n = 0;
    for (const pv::Privy& v : pv::PRIVY) {
      CborVal m;
      PrivyReq r;
      std::string err;
      if (!CHECK(decode(v.cbor, m) && parse_privy_req(m, r, err))) continue;
      DemoSigner s;
      Response out;
      CHECK(respond_privy(r, s, out, err));
      CHECK_EQ(hexs(out.cbor), std::string(v.resp));
      CHECK_EQ(ur_encode(out.urType, out.cbor), std::string(v.respUr));
      CHECK(out.save == Save::None);
      n++;
    }
    CHECK(n >= 5);
    PrivyReq none;  // not an allow-listed shape (kind None): refused
    DemoSigner s;
    Response out;
    std::string err;
    CHECK(!respond_privy(none, s, out, err));
    CHECK_EQ(s.calls(), 0);
    CHECK(empty(out));
  }

  // ------------------------------------------------------------------------------------------------------------------
  CHECK_SECTION("revoke / panic / reopen: pinned contracts only, counters");
  {
    for (const pv::Revoke& v : pv::REVOKE) {
      Context c;
      c.chainId = v.chainId;
      c.pulseCosignEnforcer = A(v.enforcer);
      c.lastDelegationHash = B(v.delegationHash);
      DemoSigner s;
      Response out;
      std::string err;
      CHECK(respond_revoke(c, s, out, err));
      CHECK_EQ(hexs(out.cbor), std::string(v.resp));
      CHECK_EQ(ur_encode(out.urType, out.cbor), std::string(v.respUr));
      CHECK(out.save == Save::BestEffort);  // the revoked mandate is forgotten; PANIC FIRST stays until a panic
      CHECK(out.next.lastDelegationHash == B32());
      Context expect = c;
      context_after_revoke(expect);
      CHECK(same_ctx(out.next, expect));
      DemoSigner s2;  // nothing left to revoke
      Response out2;
      CHECK(!respond_revoke(out.next, s2, out2, err));
      CHECK_EQ(s2.calls(), 0);
    }
    int panics = 0;
    for (const pv::Panic& v : pv::PANIC) {
      if (v.minEpoch == 0) continue;  // the device never signs epoch 0 (next = last + 1 >= 1)
      Context c;
      c.chainId = v.chainId;
      c.pulseCosignEnforcer = A(v.enforcer);
      c.minEpoch = v.minEpoch - 1;
      c.unpanickedMandates = true;
      DemoSigner s;
      Response out;
      std::string err;
      CHECK(respond_panic(c, s, out, err));
      CHECK(!out.next.unpanickedMandates);  // every mandate the device signed is killed by this panic
      CHECK_EQ(hexs(out.cbor), std::string(v.resp));
      CHECK_EQ(ur_encode(out.urType, out.cbor), std::string(v.respUr));
      CHECK(out.save == Save::Restrict);  // used in RAM even when NVS fails (fork review m4)
      CHECK_EQ(out.next.minEpoch, v.minEpoch);
      panics++;
    }
    CHECK(panics >= 8);
    int reopens = 0;
    for (const pv::Reopen& v : pv::REOPEN) {
      const Bytes nb = HX(v.nonce);
      U256 nonce;
      if (!U256::from_be(nb.data(), nb.size(), nonce) || !nonce.fits_u64() || nonce.low_u64() == 0) continue;
      Context c;
      c.chainId = v.chainId;
      c.sentinel = A(v.sentinel);
      c.vault = A(v.vault);
      CHECK_EQ_HEX(c.vault.v, 20, pv::DEMO_VAULT);  // v1.2: the device reopens its own (derived) vault
      c.reopenNonce = nonce.low_u64() - 1;
      DemoSigner s;
      Response out;
      std::string err;
      CHECK(respond_reopen(c, s, out, err));
      CHECK_EQ(hexs(out.cbor), std::string(v.resp));
      CHECK_EQ(ur_encode(out.urType, out.cbor), std::string(v.respUr));
      CHECK(out.save == Save::Required);
      CHECK_EQ(out.next.reopenNonce, nonce.low_u64());
      reopens++;
    }
    CHECK(reopens >= 3);
    // unpaired / missing pinned contracts: refused before any signature
    Context none;
    DemoSigner s;
    Response out;
    std::string err;
    CHECK(!respond_revoke(none, s, out, err));
    CHECK(!respond_panic(none, s, out, err));
    CHECK(err.find("NOT PAIRED") != std::string::npos);
    CHECK(!respond_reopen(none, s, out, err));
    Context paired;
    paired.chainId = 10143;
    paired.pulseCosignEnforcer = A(pv::REVOKE[0].enforcer);
    CHECK(!respond_revoke(paired, s, out, err));  // no mandate signed yet
    CHECK(err.find("NO MANDATE") != std::string::npos);
    CHECK(!respond_reopen(paired, s, out, err));  // no sentinel / vault pinned
    CHECK_EQ(s.calls(), 0);
    CHECK(empty(out));
    paired.minEpoch = ~uint64_t(0);  // exhausted counter
    CHECK(!respond_panic(paired, s, out, err));
    CHECK_EQ(s.calls(), 0);
    paired.minEpoch = 0;
    s.failP1 = true;
    CHECK(!respond_panic(paired, s, out, err));
    CHECK(empty(out));
    CHECK(err.find("signature") != std::string::npos);
  }

  CHECK_EQ(g_bad, 0);
  return CHECK_SUMMARY();
}
