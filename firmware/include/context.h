// The device's pinned context (security review M3): chain + contracts pinned at pairing, the last mandate this device
// signed, and the monotonic counters of its own signatures. Portable C++14 (host + device); stored in NVS by
// src/store.cpp as the blob built by context_serialize().
//
// WHO MAY WRITE IT: only the helpers in include/policy.h (context_after_pair / _mandate / _cosign / _revoke / _panic /
// _reopen), and flows.cpp only calls them AFTER the user confirmed that screen with pulse + SIGN (pairing, a mandate
// the device itself signed) or after the device produced its own revoke / panic / reopen / co-sign signature (a
// co-sign only advances notBefore, a revoke only forgets lastDelegationHash). Nothing is ever copied into
// the context from a request that was not confirmed like that (a co-sign, deny or Privy request never changes the
// pinned contracts).
#pragma once
#include <cstddef>
#include <cstdint>

#include "util.h"

namespace ripar {

struct Context {
  // ---- pinned at pairing (ripar-pair-req keys 2..8, shown in full and confirmed with pulse + SIGN)
  uint64_t chainId = 0;  // 0 = not paired: every request that needs a pinned contract is refused
  Addr delegationManager;    // MetaMask DelegationManager (domain of Delegation)
  Addr pulseCosignEnforcer;  // Ripar PulseCosignEnforcer (domain of HumanApproval / Revoke / Panic)
  Addr sentinel;             // RiparSentinel (domain of Reopen); zero = not deployed / not pinned
  Addr relay;                // RiparReputationRelay (domain of Deny); zero = not pinned
  Addr registry;             // RiparDeviceRegistry (domain of BindDevice)
  Addr vault;                // HybridDeleGator owned by K1 (every mandate / co-sign delegator): since v1.2 always
                             // vault_address(K1) (vault.h), derived on the device; zero only when not paired
  // ---- from the last mandate this device signed (K1)
  B32 lastDelegationHash;    // hash_delegation() of that mandate (what ripar-revoke revokes); zero = none
  bool hasAgentId = false;   // its key 10: the ERC-8004 agent a deny is filed against
  uint64_t agentId = 0;
  // ---- monotonic: only ever move forward (also across re-pairing)
  uint64_t minEpoch = 0;     // last Panic(minEpoch) this device signed, or a pairing floor (key 10); new mandates
                             // need terms.epoch == minEpoch, so the next Panic(minEpoch + 1) kills every one of them
  uint64_t reopenNonce = 0;  // last Reopen nonce this device signed, or a pairing floor (key 11) (next = +1)
  uint64_t notBefore = 0;    // latest trusted "now" seen (unix s): pairing time, expiry of signed co-signs (<= 1 day
                             // per co-sign)
  // ---- (v3) the pulse terms of the last mandate (meaningful while lastDelegationHash != 0), for the co-sign review:
  // which payee a co-sign whitelists for the AUTO path, and up to which caps (review.h review_cosign)
  Addr pulseToken;           // terms.token (zero = native coin)
  U256 perTxAutoCap;         // terms.perTxAutoCap (uint128: the high 16 bytes are always zero)
  U256 periodAutoCap;        // terms.periodAutoCap (uint128)
  uint32_t period = 0;       // terms.period (s; 0 = the AUTO cap never resets)
  bool newPayeeNeedsHuman = false;
  // ---- (v3) PANIC FIRST: set when the device signs a mandate, cleared when it signs a panic. While set, a mandate
  // this device signed may still be live on the pinned chain / enforcer, so a pairing that would move them is refused
  // (policy.h check_pair): after such a pairing the device's PANIC would no longer cover those mandates.
  bool unpanickedMandates = false;

  bool paired() const { return chainId != 0; }
};

// NVS blob layout (explicit bytes, big-endian, no struct padding):
//   [0] version = 3 | chainId u64 | delegationManager 20 | pulseCosignEnforcer 20 | sentinel 20 | relay 20 |
//   registry 20 | vault 20 | lastDelegationHash 32 | hasAgentId u8 (0/1) | agentId u64 | minEpoch u64 |
//   reopenNonce u64 | notBefore u64 | pulseToken 20 | perTxAutoCap u128 (16) | periodAutoCap u128 (16) |
//   period u32 | newPayeeNeedsHuman u8 (0/1) | unpanickedMandates u8 (0/1) | crc32 (zlib) of everything before it, u32
// Versions 1 and 2 (firmware before v1.2: no derived vault, no PANIC FIRST flag) are refused like any other version:
// the device counts as unpaired (PAIRING LOST at boot) and must be paired again, with the counter floors.
const uint8_t CONTEXT_VERSION = 3;
const size_t CONTEXT_BODY_SIZE = 1 + 8 + 6 * 20 + 32 + 1 + 8 + 8 + 8 + 8 + 20 + 16 + 16 + 4 + 1 + 1;  // 252
const size_t CONTEXT_BLOB_SIZE = CONTEXT_BODY_SIZE + 4;                                                 // 256

void context_serialize(const Context& c, uint8_t out[CONTEXT_BLOB_SIZE]);
// false (and `out` untouched) on a wrong size / version / CRC or a flag byte other than 0/1 (hasAgentId,
// newPayeeNeedsHuman, unpanickedMandates). The two caps are stored as their low 16 bytes (uint128: decode_pulse_terms
// guarantees the high 16 bytes are zero).
bool context_deserialize(const uint8_t* p, size_t n, Context& out);

}  // namespace ripar
