// The SIGN step of every flow (include/respond.h). Portable C++14 (host + device), host-tested in
// test/host/test_respond.cpp against the Python reference responses.
#include "respond.h"

#include <cstring>

#include "crypto.h"
#include "hashes.h"
#include "policy.h"

namespace ripar {

namespace {

void wipe(void* p, size_t n) {
  volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
  while (n--) *v++ = 0;
}

bool fail(Response& out, std::string& err, const std::string& why) {
  out = Response();
  err = why;
  return false;
}

const char* const kSigFailed = "signature failed (self-check)";

}  // namespace

bool respond_pair(const PairReq& r, const Context& ctx, const Addr& k1, const uint8_t p1xy[64], const uint8_t fwid[8],
                  Signer& s, Response& out, std::string& err) {
  out = Response();
  if (!check_pair(r, ctx, err)) return fail(out, err, err);
  const B32 digest = pair_digest(r.chainId, r.registry, k1, p1xy);  // BindDevice(owner = K1, P1 key)
  uint8_t rs[64], rsv[65];
  const bool ok = s.p1(digest, rs) && s.k1(digest, rsv);
  if (ok) out.cbor = build_pair(r.reqId, k1, p1xy, rs, rsv, fwid);
  wipe(rs, sizeof rs);
  wipe(rsv, sizeof rsv);
  if (!ok) return fail(out, err, kSigFailed);
  out.urType = "ripar-pair";
  out.save = Save::Required;
  out.next = context_after_pair(ctx, r);  // pins exactly what review_pair showed
  err.clear();
  return true;
}

bool respond_cosign(CosignReq& r, const Context& ctx, const uint8_t ev12[12], const uint8_t salt16[16], Signer& s,
                    Response& out, std::string& err) {
  out = Response();
  if (!check_cosign(r, ctx, err)) return fail(out, err, err);
  r.h.presenceHash = presence_hash(ev12, salt16);
  const B32 digest = cosign_digest(r);  // HumanApproval of the reviewed request, rebuilt right before signing
  uint8_t rs[64];
  const bool ok = s.p1(digest, rs);
  if (ok) out.cbor = build_cosign(r.reqId, rs, ev12, salt16);
  wipe(rs, sizeof rs);
  if (!ok) return fail(out, err, kSigFailed);
  out.urType = "ripar-cosign";
  out.save = Save::BestEffort;
  out.next = ctx;
  context_after_cosign(out.next, r);
  err.clear();
  return true;
}

bool respond_mandate(const MandateReq& r, const Context& ctx, const uint8_t p1xy[64], Signer& s, Response& out,
                     std::string& err) {
  out = Response();
  if (!check_mandate(r, ctx, p1xy, err)) return fail(out, err, err);
  const B32 digest = mandate_digest(r);
  uint8_t rsv[65];
  const bool ok = s.k1(digest, rsv);
  if (ok) out.cbor = build_eth_signature(r.reqId, rsv);
  wipe(rsv, sizeof rsv);
  if (!ok) return fail(out, err, kSigFailed);
  out.urType = "eth-signature";
  out.save = Save::Required;
  out.next = ctx;
  context_after_mandate(out.next, r);  // lastDelegationHash = the mandate THIS device signed
  err.clear();
  return true;
}

bool respond_deny(const DenyReq& r, const Context& ctx, const uint8_t ev12[12], const uint8_t salt16[16], Signer& s,
                  Response& out, std::string& err) {
  out = Response();
  if (!check_deny(r, ctx, err)) return fail(out, err, err);
  const B32 digest = deny_digest(r, presence_hash(ev12, salt16));
  uint8_t rs[64];
  const bool ok = s.p1(digest, rs);
  if (ok) out.cbor = build_deny(r, rs, ev12, salt16);
  wipe(rs, sizeof rs);
  if (!ok) return fail(out, err, kSigFailed);
  out.urType = "ripar-deny";
  err.clear();
  return true;
}

bool respond_privy(const PrivyReq& r, Signer& s, Response& out, std::string& err) {
  out = Response();
  if (r.kind != PrivyReq::WalletUpdate && r.kind != PrivyReq::KeyQuorumUpdate)
    return fail(out, err, "NOT AN ALLOWED PRIVY REQUEST");
  B32 digest;
  sha256(r.json.data(), r.json.size(), digest.v);  // the exact bytes that were parsed and shown
  uint8_t rs[64], der[72];
  bool ok = s.p1(digest, rs);
  const size_t n = ok ? ecdsa_der(rs, der) : 0;
  ok = ok && n > 0 && n <= sizeof der;
  if (ok) out.cbor = build_der_sig(r.reqId, Bytes(der, der + n));
  wipe(rs, sizeof rs);
  wipe(der, sizeof der);
  if (!ok) return fail(out, err, kSigFailed);
  out.urType = "ripar-der-sig";
  err.clear();
  return true;
}

bool respond_revoke(const Context& ctx, Signer& s, Response& out, std::string& err) {
  out = Response();
  Addr enforcer;
  if (!check_revoke(ctx, err) || !pinned_cosign_enforcer(ctx, ctx.chainId, enforcer, err)) return fail(out, err, err);
  const B32 digest = revoke_digest(ctx.chainId, enforcer, ctx.lastDelegationHash);
  uint8_t rs[64];
  const bool ok = s.p1(digest, rs);
  if (ok) out.cbor = build_revoke(ctx.lastDelegationHash, rs);
  wipe(rs, sizeof rs);
  if (!ok) return fail(out, err, kSigFailed);
  out.urType = "ripar-revoke";
  out.save = Save::BestEffort;
  out.next = ctx;
  context_after_revoke(out.next);  // the revoked mandate is no longer tracked (a re-pairing may change contracts)
  err.clear();
  return true;
}

bool respond_panic(const Context& ctx, Signer& s, Response& out, std::string& err) {
  out = Response();
  Addr enforcer;
  if (!check_panic(ctx, err) || !pinned_cosign_enforcer(ctx, ctx.chainId, enforcer, err)) return fail(out, err, err);
  const uint64_t epoch = panic_next_epoch(ctx);
  const B32 digest = panic_digest(ctx.chainId, enforcer, epoch);
  uint8_t rs[64];
  const bool ok = s.p1(digest, rs);
  if (ok) out.cbor = build_panic(epoch, rs);
  wipe(rs, sizeof rs);
  if (!ok) return fail(out, err, kSigFailed);
  out.urType = "ripar-panic";
  out.save = Save::Restrict;
  out.next = ctx;
  context_after_panic(out.next, epoch);
  err.clear();
  return true;
}

bool respond_reopen(const Context& ctx, Signer& s, Response& out, std::string& err) {
  out = Response();
  if (!check_reopen(ctx, err)) return fail(out, err, err);
  const uint64_t nonce = reopen_next_nonce(ctx);
  const U256 n = U256::from_u64(nonce);
  const B32 digest = reopen_digest(ctx.chainId, ctx.sentinel, ctx.vault, n);
  uint8_t rs[64];
  const bool ok = s.p1(digest, rs);
  if (ok) out.cbor = build_reopen(ctx.vault, n, rs);
  wipe(rs, sizeof rs);
  if (!ok) return fail(out, err, kSigFailed);
  out.urType = "ripar-reopen";
  out.save = Save::Required;
  out.next = ctx;
  context_after_reopen(out.next, nonce);
  err.clear();
  return true;
}

}  // namespace ripar
