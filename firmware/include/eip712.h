// EIP-712 hashing for every struct the device signs (see docs/PROTOCOL.md §3). Host + device.
#pragma once
#include <vector>

#include "util.h"

namespace ripar {

B32 eip712_domain(const char* name, const char* version, uint64_t chainId, const Addr& verifyingContract);
B32 eip712_digest(const B32& domainSeparator, const B32& structHash);  // keccak(0x1901 || ds || sh)

struct Caveat {
  Addr enforcer;
  Bytes terms;
};
struct Delegation {
  Addr delegate, delegator;
  B32 authority;
  std::vector<Caveat> caveats;
  U256 salt;
};
struct HumanApproval {
  B32 delegationHash;
  Addr delegator, redeemer, target;
  U256 value;
  B32 callDataHash;
  U256 nonce;
  uint64_t expiry = 0;
  B32 presenceHash;
};

B32 hash_caveat(const Caveat& c);
B32 hash_delegation(const Delegation& d);
B32 hash_human_approval(const HumanApproval& h);
B32 hash_revoke(const B32& delegationHash);
B32 hash_panic(uint64_t minEpoch);
B32 hash_reopen(const Addr& vault, const U256& nonce);
B32 hash_deny(const U256& agentId, const B32& requestHash, const B32& presenceHash);
B32 hash_bind_device(const Addr& owner, const B32& px, const B32& py);

extern const B32 ROOT_AUTHORITY;  // 32 x 0xff

}  // namespace ripar
