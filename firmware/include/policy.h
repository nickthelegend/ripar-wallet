// Signing policy: may this parsed request be signed with the device's pinned context? Portable C++14 (host + device).
//
// protocol.h parsers only check the FORMAT of a request. Every check that depends on what the device has pinned at
// pairing (security review M3), on the mandate caveats (B2 / M4), on the clock (MINOR 2) or on the agent a deny is
// filed against (MINOR 7) lives here, is host-tested (test/host/test_policy.cpp) and is also what review.h shows as
// the REFUSED line. flows.cpp must call the check_*() of a request before arming SIGN and must never sign when it
// returns false.
//
// The context_after_*() helpers are the ONLY code that produces a new Context (see context.h): flows.cpp calls them
// after the user confirmed a pairing / after the device made the corresponding signature, then store_save_context().
#pragma once
#include <cstdint>
#include <string>

#include "context.h"
#include "protocol.h"

namespace ripar {

// Earliest "now" the firmware accepts before it has seen any time (unix s). Build-time constant; a device paired
// with a companion clock (pair-req key 9) or that signed co-signs since then uses the later of the two.
#ifndef RIPAR_TIME_FLOOR
#define RIPAR_TIME_FLOOR 1790380800ull  // 2026-09-26 00:00:00 UTC
#endif
const uint64_t EXPIRY_LIMIT = uint64_t(1) << 40;  // co-sign expiry must be below 2^40 (year 36812)
const uint64_t EXPIRY_WINDOW = 7ull * 86400;      // ... and at most 7 days after the device's "not before" time
// A signed co-sign moves the device's "not before" time to its expiry, but by at most this much per signature
// (security review m2: otherwise each approved co-sign could push the device time, and with it the 7-day window,
// a week further; with a 1-day step the device time can only run ahead of real time by one day per approval, and a
// device that co-signs about once a day still keeps up with real time).
const uint64_t NOT_BEFORE_STEP = 86400;
// A pairing clock (key 9) this far past the device time is shown in red on the pairing review.
const uint64_t PAIR_TIME_JUMP_WARN = 30ull * 86400;

// ---- compiled-in contract table (src/enforcers.cpp). false = none for that chain (e.g. not deployed yet).
bool compiled_cosign_enforcer(uint64_t chainId, Addr& out);     // Ripar PulseCosignEnforcer (TODO after deploy)
bool compiled_delegation_manager(uint64_t chainId, Addr& out);  // MetaMask DelegationManager v1.3.0

// The PulseCosignEnforcer every mandate / co-sign on `chainId` must use: the compiled-in address when there is one
// (a pinned address that differs is an error), otherwise the address pinned at pairing. false + err when the device
// is not paired to `chainId` or no enforcer is known.
bool pinned_cosign_enforcer(const Context& ctx, uint64_t chainId, Addr& out, std::string& err);

// ---- pinned-context validation (security review M3). Every request check below is built from these, and flows.cpp
// may call them directly (e.g. to pick the refusal text before the review screen). true = the request value is the
// one pinned at pairing; false + err (the REFUSED text) otherwise. Nothing here ever writes the Context.
// paired, and chainId == the pinned chain ("NOT PAIRED ..." / "WRONG CHAIN ...")
bool check_pinned_chain(const Context& ctx, uint64_t chainId, std::string& err);
// check_pinned_chain + a DelegationManager is pinned + manager == it
bool check_pinned_manager(const Context& ctx, uint64_t chainId, const Addr& manager, std::string& err);
// check_pinned_chain + enforcer == pinned_cosign_enforcer() (the domain of HumanApproval / Revoke / Panic)
bool check_pinned_enforcer(const Context& ctx, uint64_t chainId, const Addr& enforcer, std::string& err);
// check_pinned_chain + a RiparReputationRelay is pinned + relay == it
bool check_pinned_relay(const Context& ctx, uint64_t chainId, const Addr& relay, std::string& err);
// delegator == the pinned vault; true when no vault is pinned (pairing without key 8: any delegator is shown)
bool check_pinned_vault(const Context& ctx, const Addr& delegator, std::string& err);

// MetaMask ANY_DELEGATE (address(0xa11)): a delegation to it can be redeemed by anyone -> mandates to it are refused
Addr any_delegate();

// ---- time (MINOR 2). The device has no clock; notBefore only moves forward (context_after_pair / _cosign).
uint64_t effective_not_before(uint64_t notBefore);  // max(notBefore, RIPAR_TIME_FLOOR)
// false + err when expiry >= 2^40 or expiry > effective_not_before(notBefore) + 7 days
bool expiry_check(uint64_t expiry, uint64_t notBefore, std::string& err);

// ---- request checks (true = may be signed; err = the refusal shown on the review screen)
// pairing: supported chain, pinned contracts consistent with the compiled-in table (the DelegationManager and a
// deployed PulseCosignEnforcer must match it); and (security review N2) while `cur` still holds a mandate this device
// signed (lastDelegationHash != 0), a pairing that would change its chain, DelegationManager, PulseCosignEnforcer or
// vault is refused ("REVOKE FIRST"): the device would forget that mandate while it stays live on chain, and its
// Revoke / Panic would then target the new contract. Revoke it first (context_after_revoke forgets it).
bool check_pair(const PairReq& r, const Context& cur, std::string& err);
// true when `next` keeps the scope of cur's mandate (same chain, DelegationManager, PulseCosignEnforcer and vault)
bool same_mandate_scope(const Context& cur, const Context& next);
// co-sign: paired to r.chainId; r.enforcer == pinned PulseCosignEnforcer; delegator == pinned vault (when pinned);
// calldata decodes (no Unknown); no native value on an ERC-20 call; expiry_check
bool check_cosign(const CosignReq& r, const Context& ctx, std::string& err);
// mandate (B2 / M4): paired to r.chainId; manager == pinned DelegationManager; delegator == pinned vault (when
// pinned); delegate is not ANY_DELEGATE; EXACTLY ONE caveat uses the pinned PulseCosignEnforcer (compiled-in
// address, else the one pinned at pairing) - "MANDATE WITHOUT PULSE CO-SIGN ..." otherwise, also when no enforcer is
// pinned; every caveat decodes strictly (review.h decode_caveat: unknown / undecodable enforcers refused); the pulse
// terms name THIS device's P1 key (p1xy), an epoch EQUAL to ctx.minEpoch (security review N1: the chain kills a
// mandate only when its epoch is below the panic floor, and the device's next panic is ctx.minEpoch + 1, so a higher
// epoch would survive every panic this device can sign) and exactly the pinned sentinel (the zero address when none
// is pinned: a mandate cannot name a sentinel the user never confirmed at pairing, security review m3)
bool check_mandate(const MandateReq& r, const Context& ctx, const uint8_t p1xy[64], std::string& err);
// deny request (ripar-deny-req): paired to r.chainId; relay == pinned relay; agentId == the agent of the last
// mandate this device signed (MINOR 7: the companion cannot pick another agent)
bool check_deny(const DenyReq& r, const Context& ctx, std::string& err);
// deny from a co-sign review (MINOR 7): the device builds the Deny itself - reqId of the co-sign request, pinned
// chain + relay, agentId of the pinned mandate, requestHash = cosign_request_hash(c) computed on the device
bool deny_from_cosign(const CosignReq& c, const Context& ctx, DenyReq& out, std::string& err);
// device-initiated messages need their pinned contracts (and revoke a signed mandate; panic / reopen a free counter)
bool check_revoke(const Context& ctx, std::string& err);
bool check_panic(const Context& ctx, std::string& err);
bool check_reopen(const Context& ctx, std::string& err);

// ---- the only writers of Context (call AFTER the confirmation / signature)
// pairing confirmed: pins chain + contracts (compiled-in ones fill gaps); minEpoch / reopenNonce = max(old, key 10 /
// key 11 floor) (monotonic: a floor can only raise them); notBefore = max(old, r.now); forgets the last mandate when
// the chain, manager, enforcer or vault changed (check_pair refuses that while a mandate is remembered)
Context context_after_pair(const Context& cur, const PairReq& r);
// the device signed this mandate: lastDelegationHash = hash_delegation(r.d), agentId = key 10 (or none)
void context_after_mandate(Context& ctx, const MandateReq& r);
// the device signed this co-sign: notBefore moves towards its expiry (the user saw that time on the review), but by at
// most NOT_BEFORE_STEP past effective_not_before(notBefore); it never goes back
void context_after_cosign(Context& ctx, const CosignReq& r);
// the device signed Revoke(lastDelegationHash): that mandate is no longer tracked (lastDelegationHash = 0; the agent
// id stays for denies), so a pairing may change the contracts again (check_pair)
void context_after_revoke(Context& ctx);
uint64_t panic_next_epoch(const Context& ctx);  // ctx.minEpoch + 1 (check_panic refuses at UINT64_MAX)
void context_after_panic(Context& ctx, uint64_t signedMinEpoch);
uint64_t reopen_next_nonce(const Context& ctx);  // ctx.reopenNonce + 1
void context_after_reopen(Context& ctx, uint64_t signedNonce);

}  // namespace ripar
