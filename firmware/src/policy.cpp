// Signing policy against the pinned context (include/policy.h). Portable C++14 (host + device).
#include "policy.h"

#include <cstring>

#include "abi.h"
#include "review.h"
#include "tokens.h"
#include "vault.h"

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

// "WRONG <what>: key <k> = <given> is not the <contract> this firmware pins on <chain>: <compiled>"
std::string wrong_pinned(const char* what, int key, const Addr& given, const char* contract, uint64_t chainId,
                         const Addr& compiled) {
  return std::string("WRONG ") + what + ": key " + u64_text(uint64_t(key)) + " = " + addr_checksum(given) +
         " is not the " + contract + " this firmware pins on " + chain_text(chainId) + ": " + addr_checksum(compiled);
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
  Addr compiled;  // like the enforcer and the relay: a stored manager other than the firmware's is not trusted
  if (compiled_delegation_manager(chainId, compiled) && ctx.delegationManager != compiled)
    return fail(err, "PINNED DELEGATION MANAGER DIFFERS FROM FIRMWARE TABLE - pair again");
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
  Addr pinned;
  if (!pinned_relay(ctx, chainId, pinned, err)) return false;
  if (relay != pinned)
    return fail(err, "RELAY NOT PINNED: " + addr_checksum(relay) + " is not the paired " + addr_checksum(pinned));
  return true;
}

bool check_pinned_vault(const Context& ctx, const Addr& delegator, std::string& err) {
  err.clear();
  // since v1.2 every pairing pins the vault derived from K1 (context_after_pair), so a paired context always has one;
  // fail closed if it does not
  if (ctx.vault.is_zero()) return fail(err, "NO VAULT PINNED - pair again");
  if (delegator != ctx.vault)
    return fail(err, "NOT THIS DEVICE'S VAULT: delegator " + addr_checksum(delegator) + " is not the vault " +
                         addr_checksum(ctx.vault) + " derived from this device's K1");
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

bool pinned_relay(const Context& ctx, uint64_t chainId, Addr& out, std::string& err) {
  err.clear();
  if (!check_pinned_chain(ctx, chainId, err)) return false;
  if (ctx.relay.is_zero()) return fail(err, "NO REPUTATION RELAY PINNED - pair again");
  Addr compiled;
  if (compiled_relay(chainId, compiled) && ctx.relay != compiled)
    return fail(err, "PINNED RELAY DIFFERS FROM FIRMWARE TABLE - pair again");
  out = ctx.relay;
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

bool check_pair(const PairReq& r, const Context& cur, const Addr& k1, std::string& err) {
  err.clear();
  if (!chain_find(r.chainId)) return fail(err, "UNSUPPORTED CHAIN " + u64_text(r.chainId));
  // firmware v1.2: every contract the firmware has compiled in for this chain is the only one a pairing may name
  Addr fw;
  if (compiled_registry(r.chainId, fw) && r.registry != fw)
    return fail(err, wrong_pinned("REGISTRY", 3, r.registry, "RiparDeviceRegistry", r.chainId, fw));
  if (compiled_delegation_manager(r.chainId, fw) && !r.manager.is_zero() && r.manager != fw)
    return fail(err, wrong_pinned("DELEGATION MANAGER", 4, r.manager, "MetaMask DelegationManager", r.chainId, fw));
  if (compiled_cosign_enforcer(r.chainId, fw) && !r.enforcer.is_zero() && r.enforcer != fw)
    return fail(err, wrong_pinned("PULSE CO-SIGN ENFORCER", 5, r.enforcer, "PulseCosignEnforcer", r.chainId, fw));
  if (compiled_relay(r.chainId, fw) && !r.relay.is_zero() && r.relay != fw)
    return fail(err, wrong_pinned("REPUTATION RELAY", 7, r.relay, "RiparReputationRelay", r.chainId, fw));
  // the vault is derived from this device's K1 (vault.h); the companion can only confirm it
  const Addr vault = vault_address(k1);
  if (!r.vault.is_zero() && r.vault != vault)
    return fail(err, "VAULT IS NOT THIS DEVICE'S VAULT: key 8 = " + addr_checksum(r.vault) + ", but this device's K1 " +
                         addr_checksum(k1) + " owns the vault " + addr_checksum(vault) +
                         " (MetaMask SimpleFactory CREATE2, salt 0; leave key 8 out to pin it)");
  if (r.hasNow && r.now >= EXPIRY_LIMIT) return fail(err, "BAD TIME");
  if ((r.hasMinEpoch && r.minEpoch >= PAIR_FLOOR_LIMIT) || (r.hasReopenNonce && r.reopenNonce >= PAIR_FLOOR_LIMIT))
    return fail(err, "BAD COUNTER FLOOR");
  // PANIC FIRST (v1.2; replaces v1.1's REVOKE FIRST): never move the chain / contracts away from mandates this device
  // signed that its last panic did not kill. After such a pairing its PANIC would be signed for the new chain /
  // enforcer and no longer cover them.
  if (cur.paired() && cur.unpanickedMandates && !same_mandate_scope(cur, context_after_pair(cur, r, k1))) {
    Addr enf;
    std::string why;
    const std::string enfText = pinned_cosign_enforcer(cur, cur.chainId, enf, why) ? addr_checksum(enf)
                                : cur.pulseCosignEnforcer.is_zero()               ? std::string("none")
                                                                                  : addr_checksum(cur.pulseCosignEnforcer);
    return fail(err, "PANIC FIRST: mandates signed on " + chain_text(cur.chainId) + " (PulseCosignEnforcer " +
                         enfText + ", vault " + addr_checksum(cur.vault) +
                         ") would not be covered by PANIC after re-pairing. Sign a PANIC (home: hold 5 s) and relay "
                         "it, then pair again");
  }
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

// The payee a signed co-sign would pass to the enforcer's known-payee rule when the mandate's asset is native (a native
// send with value > 0: the target) or the token `token` (a transfer on it, no native value, amount > 0: the recipient).
namespace {
bool meterable_payee(const CosignReq& r, bool native, const Addr& token, Addr& payee) {
  Addr p;
  if (native) {
    if (r.call.kind != Erc20Call::None || r.h.value.is_zero()) return false;
    p = r.h.target;
  } else {
    if (r.call.kind != Erc20Call::Transfer || r.h.target != token || !r.h.value.is_zero() || r.call.amount.is_zero())
      return false;
    p = r.call.to;
  }
  if (p.is_zero()) return false;
  payee = p;
  return true;
}
}  // namespace

bool cosign_whitelists_payee(const CosignReq& r, const Context& ctx, Addr& payee) {
  std::string err;
  if (!check_cosign(r, ctx, err)) return false;  // refused: nothing is signed, nothing whitelisted (v1.2 review)
  if (ctx.lastDelegationHash == B32() || !(r.h.delegationHash == ctx.lastDelegationHash)) return false;
  if (!ctx.newPayeeNeedsHuman) return false;  // every payee may use the AUTO path anyway
  // native terms: a native send with value > 0; token terms: transfer on that token, no native value, amount > 0
  return meterable_payee(r, ctx.pulseToken.is_zero(), ctx.pulseToken, payee);
}

bool cosign_may_whitelist_payee(const CosignReq& r, const Context& ctx, Addr& payee) {
  std::string err;
  if (!check_cosign(r, ctx, err)) return false;
  if (!(ctx.lastDelegationHash == B32()) && r.h.delegationHash == ctx.lastDelegationHash) return false;  // known
  // the mandate's asset is unknown: meterable if it is native, or if it is the token this call transfers
  return meterable_payee(r, true, Addr(), payee) || meterable_payee(r, false, r.h.target, payee);
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
  Addr relay;
  std::string why;
  if (!pinned_relay(ctx, ctx.chainId, relay, why)) return fail(err, "CANNOT FILE A DENY: " + why);
  if (!ctx.hasAgentId) return fail(err, "NO AGENT PINNED - cannot file a deny");
  DenyReq d;
  d.reqId = c.reqId;
  d.chainId = ctx.chainId;
  d.relay = relay;
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
  if (ctx.vault.is_zero()) return fail(err, "NO VAULT PINNED - pair again");
  if (ctx.reopenNonce == kMax64) return fail(err, "NONCE COUNTER EXHAUSTED");
  return true;
}

// ---------------------------------------------------------------------------------------------------------- writers
Context context_after_pair(const Context& cur, const PairReq& r, const Addr& k1) {
  Context c;
  c.chainId = r.chainId;
  c.registry = r.registry;
  Addr fw;
  c.delegationManager = !r.manager.is_zero() ? r.manager : (compiled_delegation_manager(r.chainId, fw) ? fw : Addr());
  c.pulseCosignEnforcer = !r.enforcer.is_zero() ? r.enforcer : (compiled_cosign_enforcer(r.chainId, fw) ? fw : Addr());
  c.sentinel = r.sentinel;
  c.relay = !r.relay.is_zero() ? r.relay : (compiled_relay(r.chainId, fw) ? fw : Addr());
  c.vault = vault_address(k1);  // never the companion's key 8 (check_pair refuses one that differs)
  if (same_mandate_scope(cur, c)) {
    c.lastDelegationHash = cur.lastDelegationHash;
    c.hasAgentId = cur.hasAgentId;
    c.agentId = cur.agentId;
    c.pulseToken = cur.pulseToken;
    c.perTxAutoCap = cur.perTxAutoCap;
    c.periodAutoCap = cur.periodAutoCap;
    c.period = cur.period;
    c.newPayeeNeedsHuman = cur.newPayeeNeedsHuman;
  }
  // PANIC FIRST: the flag follows the device, not the pairing (check_pair refuses to move the scope while it is set)
  c.unpanickedMandates = cur.unpanickedMandates;
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
  // the pulse terms of the (single, check_mandate) PulseCosignEnforcer caveat, decoded against the context the mandate
  // was checked with
  PulseTerms t;
  bool found = false;
  for (const Caveat& c : r.d.caveats) {
    CaveatView v;
    std::string e;
    if (enforcer_kind(r.chainId, c.enforcer, ctx) == EnfKind::PulseCosign && decode_caveat(r.chainId, c, ctx, v, e)) {
      t = v.pulse;
      found = true;
      break;
    }
  }
  ctx.lastDelegationHash = hash_delegation(r.d);
  ctx.hasAgentId = r.hasAgentId;
  ctx.agentId = r.hasAgentId ? r.agentId : 0;
  ctx.pulseToken = found ? t.token : Addr();
  ctx.perTxAutoCap = found ? t.perTxAutoCap : U256();
  ctx.periodAutoCap = found ? t.periodAutoCap : U256();
  ctx.period = found ? t.period : 0;
  ctx.newPayeeNeedsHuman = found && t.newPayeeNeedsHuman;
  ctx.unpanickedMandates = true;  // PANIC FIRST: covered only by the next panic
}

void context_after_cosign(Context& ctx, const CosignReq& r) {
  if (r.h.expiry >= EXPIRY_LIMIT) return;
  const uint64_t step = effective_not_before(ctx.notBefore) + NOT_BEFORE_STEP;  // security review m2
  const uint64_t t = r.h.expiry < step ? r.h.expiry : step;
  if (t > ctx.notBefore) ctx.notBefore = t;
}

void context_after_revoke(Context& ctx) {
  ctx.lastDelegationHash = B32();
  ctx.pulseToken = Addr();
  ctx.perTxAutoCap = U256();
  ctx.periodAutoCap = U256();
  ctx.period = 0;
  ctx.newPayeeNeedsHuman = false;
}

uint64_t panic_next_epoch(const Context& ctx) { return ctx.minEpoch == kMax64 ? kMax64 : ctx.minEpoch + 1; }

void context_after_panic(Context& ctx, uint64_t signedMinEpoch) {
  if (signedMinEpoch > ctx.minEpoch) {
    ctx.minEpoch = signedMinEpoch;
    ctx.unpanickedMandates = false;  // every mandate this device signed has an epoch <= the old minEpoch: all killed
  }
}

uint64_t reopen_next_nonce(const Context& ctx) {
  return ctx.reopenNonce == kMax64 ? kMax64 : ctx.reopenNonce + 1;
}

void context_after_reopen(Context& ctx, uint64_t signedNonce) {
  if (signedNonce > ctx.reopenNonce) ctx.reopenNonce = signedNonce;
}

}  // namespace ripar
