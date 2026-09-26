// Signing policy against the pinned context (include/policy.h). Portable C++14 (host + device).
#include "policy.h"

#include <cstring>

#include "abi.h"
#include "review.h"
#include "tokens.h"

namespace ripar {

namespace {

const uint64_t kMax64 = ~uint64_t(0);

std::string u64_text(uint64_t v) {
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

bool fail(std::string& err, const std::string& m) {
  err = m;
  return false;
}

}  // namespace

// ---------------------------------------------------------------------------------------------------------- pinned
bool check_pinned_chain(const Context& ctx, uint64_t chainId, std::string& err) {
  err.clear();
  if (!ctx.paired()) return fail(err, "NOT PAIRED - pair the device first (home -> PAIR)");
  if (chainId != ctx.chainId)
    return fail(err, "WRONG CHAIN: request is for " + chain_text(chainId) + ", device is paired to " +
                         chain_text(ctx.chainId));
  return true;
}

bool check_pinned_manager(const Context& ctx, uint64_t chainId, const Addr& manager, std::string& err) {
  err.clear();
  if (!check_pinned_chain(ctx, chainId, err)) return false;
  if (ctx.delegationManager.is_zero()) return fail(err, "NO DELEGATION MANAGER PINNED - pair again");
  if (manager != ctx.delegationManager)
    return fail(err, "WRONG DELEGATION MANAGER: " + addr_checksum(manager) + " is not the pinned " +
                         addr_checksum(ctx.delegationManager));
  return true;
}

bool check_pinned_enforcer(const Context& ctx, uint64_t chainId, const Addr& enforcer, std::string& err) {
  err.clear();
  Addr pinned;
  if (!pinned_cosign_enforcer(ctx, chainId, pinned, err)) return false;
  if (enforcer != pinned)
    return fail(err, "ENFORCER NOT PINNED: " + addr_checksum(enforcer) + " is not the paired PulseCosignEnforcer " +
                         addr_checksum(pinned));
  return true;
}

bool check_pinned_relay(const Context& ctx, uint64_t chainId, const Addr& relay, std::string& err) {
  err.clear();
  if (!check_pinned_chain(ctx, chainId, err)) return false;
  if (ctx.relay.is_zero()) return fail(err, "NO REPUTATION RELAY PINNED - pair again");
  if (relay != ctx.relay)
    return fail(err, "RELAY NOT PINNED: " + addr_checksum(relay) + " is not the paired " + addr_checksum(ctx.relay));
  return true;
}

bool check_pinned_vault(const Context& ctx, const Addr& delegator, std::string& err) {
  err.clear();
  if (!ctx.vault.is_zero() && delegator != ctx.vault)
    return fail(err, "NOT THE PAIRED VAULT: delegator " + addr_checksum(delegator) + " is not the pinned vault " +
                         addr_checksum(ctx.vault));
  return true;
}

Addr any_delegate() {
  Addr a;
  a.v[18] = 0x0a;
  a.v[19] = 0x11;
  return a;
}

bool pinned_cosign_enforcer(const Context& ctx, uint64_t chainId, Addr& out, std::string& err) {
  err.clear();
  if (!check_pinned_chain(ctx, chainId, err)) return false;
  Addr compiled;
  if (compiled_cosign_enforcer(chainId, compiled)) {
    if (!ctx.pulseCosignEnforcer.is_zero() && ctx.pulseCosignEnforcer != compiled)
      return fail(err, "PINNED ENFORCER DIFFERS FROM FIRMWARE TABLE - pair again");
    out = compiled;
    return true;
  }
  if (ctx.pulseCosignEnforcer.is_zero())
    return fail(err, "NO PULSE CO-SIGN ENFORCER PINNED - pair again with the PulseCosignEnforcer address");
  out = ctx.pulseCosignEnforcer;
  return true;
}

// ---------------------------------------------------------------------------------------------------------- time
uint64_t effective_not_before(uint64_t notBefore) {
  return notBefore > RIPAR_TIME_FLOOR ? notBefore : uint64_t(RIPAR_TIME_FLOOR);
}

bool expiry_check(uint64_t expiry, uint64_t notBefore, std::string& err) {
  err.clear();
  if (expiry >= EXPIRY_LIMIT) return fail(err, "EXPIRY TOO FAR: " + u64_text(expiry) + " is not below 2^40");
  const uint64_t nb = effective_not_before(notBefore);
  if (expiry > nb + EXPIRY_WINDOW)
    return fail(err, "EXPIRY TOO FAR: " + utc_text(expiry) + " is more than 7 days after the device time " +
                         utc_text(nb) + " (pair again to update the device time)");
  return true;
}

// ---------------------------------------------------------------------------------------------------------- pair
bool same_mandate_scope(const Context& cur, const Context& next) {
  return cur.paired() && cur.chainId == next.chainId && cur.delegationManager == next.delegationManager &&
         cur.pulseCosignEnforcer == next.pulseCosignEnforcer && cur.vault == next.vault;
}

bool check_pair(const PairReq& r, const Context& cur, std::string& err) {
  err.clear();
  if (!chain_find(r.chainId)) return fail(err, "UNSUPPORTED CHAIN " + u64_text(r.chainId));
  Addr fw;
  if (compiled_delegation_manager(r.chainId, fw) && !r.manager.is_zero() && r.manager != fw)
    return fail(err, "WRONG DELEGATION MANAGER: " + addr_checksum(r.manager) + " (firmware: " + addr_checksum(fw) +
                         ")");
  if (compiled_cosign_enforcer(r.chainId, fw) && !r.enforcer.is_zero() && r.enforcer != fw)
    return fail(err, "WRONG PULSE CO-SIGN ENFORCER: " + addr_checksum(r.enforcer) + " (firmware: " +
                         addr_checksum(fw) + ")");
  if (r.hasNow && r.now >= EXPIRY_LIMIT) return fail(err, "BAD TIME");
  if ((r.hasMinEpoch && r.minEpoch >= PAIR_FLOOR_LIMIT) || (r.hasReopenNonce && r.reopenNonce >= PAIR_FLOOR_LIMIT))
    return fail(err, "BAD COUNTER FLOOR");
  // security review N2: never abandon a mandate this device signed while it may still be live on chain
  if (cur.paired() && !(cur.lastDelegationHash == B32()) && !same_mandate_scope(cur, context_after_pair(cur, r)))
    return fail(err, "REVOKE FIRST: this pairing changes the chain, DelegationManager, PulseCosignEnforcer or vault of "
                     "mandate " + to_hex(cur.lastDelegationHash.v, 32) +
                     ", which this device signed; the device would forget it and could no longer revoke it. Revoke "
                     "it (home: hold 2 s + release, hold 2 s -> REVOKE), then pair again");
  return true;
}

// ---------------------------------------------------------------------------------------------------------- cosign
bool check_cosign(const CosignReq& r, const Context& ctx, std::string& err) {
  err.clear();
  if (!check_pinned_enforcer(ctx, r.chainId, r.enforcer, err)) return false;
  if (!check_pinned_vault(ctx, r.h.delegator, err)) return false;
  if (r.call.kind == Erc20Call::Unknown)
    return fail(err, "UNKNOWN CALLDATA (selector " + to_hex(r.calldata.data(), r.calldata.size() < 4 ? r.calldata.size() : 4) +
                         ", " + u64_text(r.calldata.size()) + " bytes) - cannot show or meter it");
  if (r.call.kind != Erc20Call::None && !r.h.value.is_zero())
    return fail(err, "ERC-20 CALL WITH NATIVE VALUE attached - refused");
  return expiry_check(r.h.expiry, ctx.notBefore, err);
}

// ---------------------------------------------------------------------------------------------------------- mandate
bool check_mandate(const MandateReq& r, const Context& ctx, const uint8_t p1xy[64], std::string& err) {
  err.clear();
  if (!check_pinned_manager(ctx, r.chainId, r.manager, err)) return false;
  if (!check_pinned_vault(ctx, r.d.delegator, err)) return false;
  if (r.d.delegate == any_delegate())
    return fail(err, "OPEN DELEGATION: the delegate is ANY_DELEGATE " + addr_checksum(r.d.delegate) +
                         " - anyone could redeem it");
  // B2 first: exactly one caveat must use THE pinned PulseCosignEnforcer (checked before decoding anything else, so
  // a mandate without it is always refused with this reason)
  Addr pulse;
  std::string why;
  if (!pinned_cosign_enforcer(ctx, r.chainId, pulse, why)) return fail(err, "MANDATE WITHOUT PULSE CO-SIGN: " + why);
  size_t pulses = 0, pulseAt = 0;
  for (size_t i = 0; i < r.d.caveats.size(); i++)
    if (r.d.caveats[i].enforcer == pulse) {
      pulses++;
      pulseAt = i;
    }
  if (pulses != 1)
    return fail(err, pulses == 0 ? "MANDATE WITHOUT PULSE CO-SIGN (no caveat uses the pinned PulseCosignEnforcer " +
                                       addr_checksum(pulse) + ")"
                                 : "MANDATE WITHOUT PULSE CO-SIGN (" + u64_text(pulses) +
                                       " pulse co-sign caveats; exactly one is allowed)");
  // M4: every caveat must decode strictly (unknown / undecodable enforcers are refused)
  CaveatView pv;
  for (size_t i = 0; i < r.d.caveats.size(); i++) {
    CaveatView v;
    std::string e;
    if (!decode_caveat(r.chainId, r.d.caveats[i], ctx, v, e)) return fail(err, "RULE " + u64_text(i + 1) + ": " + e);
    if (i == pulseAt) pv = v;
  }
  if (pv.kind != EnfKind::PulseCosign)  // cannot happen: enforcer_kind() resolves the same pinned address
    return fail(err, "MANDATE WITHOUT PULSE CO-SIGN (internal: pinned enforcer not decoded as pulse co-sign)");
  const std::string at = "RULE " + u64_text(pulseAt + 1) + ": ";
  if (!p1xy || std::memcmp(pv.pulse.px.v, p1xy, 32) != 0 || std::memcmp(pv.pulse.py.v, p1xy + 32, 32) != 0)
    return fail(err, at + "PULSE CO-SIGN KEY IS NOT THIS DEVICE");
  // security review N1: exactly the panic floor, so that the device's next Panic(minEpoch + 1) kills this mandate
  if (pv.pulse.epoch < ctx.minEpoch)
    return fail(err, at + "STALE EPOCH " + u64_text(pv.pulse.epoch) + " (after the last panic it must be exactly " +
                         u64_text(ctx.minEpoch) + ")");
  if (pv.pulse.epoch > ctx.minEpoch)
    return fail(err, at + "EPOCH " + u64_text(pv.pulse.epoch) + " IS ABOVE THE PANIC FLOOR " + u64_text(ctx.minEpoch) +
                         " (a panic from this device could not kill it; it must be exactly " +
                         u64_text(ctx.minEpoch) + ")");
  // security review m3: the sentinel lane is part of the pinned set; none pinned -> the terms must name none
  if (pv.pulse.sentinel != ctx.sentinel)
    return fail(err, at + (ctx.sentinel.is_zero()
                               ? "SENTINEL NOT PINNED: " + addr_checksum(pv.pulse.sentinel) +
                                     " was not confirmed at pairing (pair with it, or use the zero address)"
                               : "SENTINEL IS NOT THE PINNED " + addr_checksum(ctx.sentinel)));
  return true;
}

// ---------------------------------------------------------------------------------------------------------- deny
bool check_deny(const DenyReq& r, const Context& ctx, std::string& err) {
  err.clear();
  if (!check_pinned_relay(ctx, r.chainId, r.relay, err)) return false;
  if (!ctx.hasAgentId) return fail(err, "NO AGENT PINNED - sign a mandate with an agent id first");
  if (r.agentId != ctx.agentId)
    return fail(err, "NOT THE PINNED AGENT: agent " + u64_text(r.agentId) + " (this device's mandate is for agent " +
                         u64_text(ctx.agentId) + ")");
  return true;
}

bool deny_from_cosign(const CosignReq& c, const Context& ctx, DenyReq& out, std::string& err) {
  if (!ctx.paired()) return fail(err, "NOT PAIRED - cannot file a deny");
  if (ctx.relay.is_zero()) return fail(err, "NO REPUTATION RELAY PINNED - cannot file a deny");
  if (!ctx.hasAgentId) return fail(err, "NO AGENT PINNED - cannot file a deny");
  DenyReq d;
  d.reqId = c.reqId;
  d.chainId = ctx.chainId;
  d.relay = ctx.relay;
  d.agentId = ctx.agentId;
  d.requestHash = cosign_request_hash(c);
  out = d;
  err.clear();
  return true;
}

// ---------------------------------------------------------------------------------------------------------- device-initiated
bool check_revoke(const Context& ctx, std::string& err) {
  err.clear();
  Addr e;
  if (!pinned_cosign_enforcer(ctx, ctx.chainId, e, err)) return false;
  if (ctx.lastDelegationHash == B32()) return fail(err, "NO MANDATE TO REVOKE - this device has not signed one");
  return true;
}

bool check_panic(const Context& ctx, std::string& err) {
  err.clear();
  Addr e;
  if (!pinned_cosign_enforcer(ctx, ctx.chainId, e, err)) return false;
  if (ctx.minEpoch == kMax64) return fail(err, "EPOCH COUNTER EXHAUSTED");
  return true;
}

bool check_reopen(const Context& ctx, std::string& err) {
  err.clear();
  if (!ctx.paired()) return fail(err, "NOT PAIRED - pair the device first (home -> PAIR)");
  if (ctx.sentinel.is_zero()) return fail(err, "NO SENTINEL PINNED - pair again with the sentinel address");
  if (ctx.vault.is_zero()) return fail(err, "NO VAULT PINNED - pair again with the vault address");
  if (ctx.reopenNonce == kMax64) return fail(err, "NONCE COUNTER EXHAUSTED");
  return true;
}

// ---------------------------------------------------------------------------------------------------------- writers
Context context_after_pair(const Context& cur, const PairReq& r) {
  Context c;
  c.chainId = r.chainId;
  c.registry = r.registry;
  Addr fw;
  c.delegationManager = !r.manager.is_zero() ? r.manager : (compiled_delegation_manager(r.chainId, fw) ? fw : Addr());
  c.pulseCosignEnforcer = !r.enforcer.is_zero() ? r.enforcer : (compiled_cosign_enforcer(r.chainId, fw) ? fw : Addr());
  c.sentinel = r.sentinel;
  c.relay = r.relay;
  c.vault = r.vault;
  if (same_mandate_scope(cur, c)) {
    c.lastDelegationHash = cur.lastDelegationHash;
    c.hasAgentId = cur.hasAgentId;
    c.agentId = cur.agentId;
  }
  // never go back: a later Panic must exceed every epoch signed before, a nonce is never reused. A floor from the
  // companion (keys 10 / 11, e.g. the on-chain values after the context was lost) can only raise them.
  c.minEpoch = cur.minEpoch;
  if (r.hasMinEpoch && r.minEpoch < PAIR_FLOOR_LIMIT && r.minEpoch > c.minEpoch) c.minEpoch = r.minEpoch;
  c.reopenNonce = cur.reopenNonce;
  if (r.hasReopenNonce && r.reopenNonce < PAIR_FLOOR_LIMIT && r.reopenNonce > c.reopenNonce)
    c.reopenNonce = r.reopenNonce;
  c.notBefore = cur.notBefore;
  if (r.hasNow && r.now > c.notBefore) c.notBefore = r.now;
  return c;
}

void context_after_mandate(Context& ctx, const MandateReq& r) {
  ctx.lastDelegationHash = hash_delegation(r.d);
  ctx.hasAgentId = r.hasAgentId;
  ctx.agentId = r.hasAgentId ? r.agentId : 0;
}

void context_after_cosign(Context& ctx, const CosignReq& r) {
  if (r.h.expiry >= EXPIRY_LIMIT) return;
  const uint64_t step = effective_not_before(ctx.notBefore) + NOT_BEFORE_STEP;  // security review m2
  const uint64_t t = r.h.expiry < step ? r.h.expiry : step;
  if (t > ctx.notBefore) ctx.notBefore = t;
}

void context_after_revoke(Context& ctx) { ctx.lastDelegationHash = B32(); }

uint64_t panic_next_epoch(const Context& ctx) { return ctx.minEpoch == kMax64 ? kMax64 : ctx.minEpoch + 1; }

void context_after_panic(Context& ctx, uint64_t signedMinEpoch) {
  if (signedMinEpoch > ctx.minEpoch) ctx.minEpoch = signedMinEpoch;
}

uint64_t reopen_next_nonce(const Context& ctx) {
  return ctx.reopenNonce == kMax64 ? kMax64 : ctx.reopenNonce + 1;
}

void context_after_reopen(Context& ctx, uint64_t signedNonce) {
  if (signedNonce > ctx.reopenNonce) ctx.reopenNonce = signedNonce;
}

}  // namespace ripar
