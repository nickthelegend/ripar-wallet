// The SIGN step of every flow (security review B1): policy re-check, digest rebuilt from the parsed request, signature,
// response CBOR and the context update that goes with it. Portable C++14 (host + device).
//
// src/flows.cpp calls these with the device keys (keys.cpp) at the moment the user confirmed; test/host/
// test_respond.cpp calls them with the demo seed and compares every response byte for byte with the independent
// Python reference (tools/make_request.py -> test/host/vectors_protocol.h).
//
// Every respond_*():
//   1. re-runs the policy.h check of the request against `ctx` (the same check that decided Review::ok): refused ->
//      false + err, and the signer is never called;
//   2. rebuilds the digest from the SAME parsed struct the review was built from, immediately before signing;
//   3. signs with the one key the protocol names (docs/PROTOCOL.md section 2);
//   4. builds the response CBOR (wrap it with ur_encode(out.urType, out.cbor));
//   5. says what must happen to the context (enum Save below): the driver stores out.next and, depending on the
//      kind, withholds the response or keeps using the new context in RAM when that fails.
// Signature buffers are wiped before returning; on false, `out` is left empty.
#pragma once
#include <cstdint>
#include <string>

#include "context.h"
#include "protocol.h"

namespace ripar {

// The device's signing keys. Each call derives, signs, checks and wipes (keys.cpp); false = no signature.
class Signer {
 public:
  virtual ~Signer() {}
  virtual bool p1(const B32& digest, uint8_t rs[64]) = 0;   // P-256, RFC 6979, low-s
  virtual bool k1(const B32& digest, uint8_t rsv[65]) = 0;  // secp256k1, RFC 6979, low-s, v = 27 / 28
};

enum class Save : uint8_t {
  None,        // nothing to store (deny, Privy)
  BestEffort,  // store it; if that fails the response is still shown and the device keeps its OLD context (co-sign
               // "not before" time; revoke forgetting the revoked mandate - keeping it is the stricter outcome)
  Restrict,    // store it; if that fails the response is still shown (with a warning) and the NEW context is used in
               // RAM anyway, because it only restricts (panic epoch: a second panic in the same session must not
               // repeat the epoch the chain already has, security review m4)
  Required,    // store it BEFORE the response is shown; withhold the response if that fails (pairing, mandate, reopen)
};

struct Response {
  const char* urType = "";  // "ripar-cosign", "eth-signature", ...
  Bytes cbor;               // the response map
  Save save = Save::None;
  Context next;             // the context after this signature (meaningful when save != None)
};

// ripar-pair-req: check_pair(r, ctx); P1 and K1 both sign BindDevice(k1, p1xy) (RiparDeviceRegistry domain of the request's
// chain + registry, as shown on the review); next = context_after_pair(ctx, r), Save::Required.
bool respond_pair(const PairReq& r, const Context& ctx, const Addr& k1, const uint8_t p1xy[64], const uint8_t fwid[8],
                  Signer& s, Response& out, std::string& err);
// ripar-cosign-req: check_cosign; r.h.presenceHash = presence_hash(ev12, salt16) (ev12 = the evidence of the pulse
// that passed in the pass of the SIGN press, salt16 = fresh TRNG bytes); P1 signs HumanApproval;
// next = context_after_cosign, Save::BestEffort.
bool respond_cosign(CosignReq& r, const Context& ctx, const uint8_t ev12[12], const uint8_t salt16[16], Signer& s,
                    Response& out, std::string& err);
// ripar-mandate-req: check_mandate (p1xy = this device's P1 key); K1 signs the Delegation; next =
// context_after_mandate (lastDelegationHash of THIS mandate), Save::Required.
bool respond_mandate(const MandateReq& r, const Context& ctx, const uint8_t p1xy[64], Signer& s, Response& out,
                     std::string& err);
// Deny (a ripar-deny-req, or one built by policy.h deny_from_cosign): check_deny; P1 signs
// Deny(agentId, requestHash, presence_hash(ev12, salt16)). The device passes all-zero evidence (no pulse).
bool respond_deny(const DenyReq& r, const Context& ctx, const uint8_t ev12[12], const uint8_t salt16[16], Signer& s,
                  Response& out, std::string& err);
// ripar-privy-req (already restricted to the allow-listed shapes by parse_privy_req): P1 signs sha256(exact JSON
// bytes); DER signature.
bool respond_privy(const PrivyReq& r, Signer& s, Response& out, std::string& err);
// Device-initiated, pinned contracts only (policy.h pinned_cosign_enforcer / ctx.sentinel / ctx.vault).
// Revoke(lastDelegationHash); next = context_after_revoke (the mandate is forgotten), Save::BestEffort
bool respond_revoke(const Context& ctx, Signer& s, Response& out, std::string& err);
// Panic(panic_next_epoch(ctx)); next.minEpoch = that epoch, Save::Restrict (panic works even when NVS does not)
bool respond_panic(const Context& ctx, Signer& s, Response& out, std::string& err);
// Reopen(vault, reopen_next_nonce(ctx)); next.reopenNonce = that nonce, Save::Required (a nonce is never reused)
bool respond_reopen(const Context& ctx, Signer& s, Response& out, std::string& err);

}  // namespace ripar
