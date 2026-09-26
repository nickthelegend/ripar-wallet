// EIP-712 hashing for every struct the device signs (docs/PROTOCOL.md §3). Host (g++ -std=c++14) + device.
//
// digest     = keccak256(0x19 0x01 || domainSeparator || structHash)
// hashStruct = keccak256(typeHash || enc(field_1) || ... || enc(field_n)), typeHash = keccak256(typeString)
//   address        -> left-padded to 32 bytes (12 zero bytes + 20)
//   uint64/uint256 -> 32-byte big-endian word
//   bytes32        -> as is
//   bytes / string -> keccak256(contents)
//   Caveat[]       -> keccak256(hashStruct(c_0) || hashStruct(c_1) || ...)   (keccak256("") when empty)
// Matches MetaMask delegation-framework EncoderLib (_getDelegationHash / _getCaveatArrayPacketHash /
// _getCaveatPacketHash). The type strings below are byte-exact copies of PROTOCOL.md §3; tools/ref_eip712.py
// derives them independently from field lists (EIP-712 encodeType) and the host test cross-checks every hash.
//
// These functions only hash. Policy checks (ROOT authority, known enforcers, ...) belong to the caller.
#include "eip712.h"

#include <cstring>

#include "hashes.h"

namespace ripar {

namespace {

const char TYPE_DOMAIN[] = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const char TYPE_DELEGATION[] =
    "Delegation(address delegate,address delegator,bytes32 authority,Caveat[] caveats,uint256 salt)"
    "Caveat(address enforcer,bytes terms)";
const char TYPE_CAVEAT[] = "Caveat(address enforcer,bytes terms)";
const char TYPE_HUMAN_APPROVAL[] =
    "HumanApproval(bytes32 delegationHash,address delegator,address redeemer,address target,uint256 value,"
    "bytes32 callDataHash,uint256 nonce,uint64 expiry,bytes32 presenceHash)";
const char TYPE_REVOKE[] = "Revoke(bytes32 delegationHash)";
const char TYPE_PANIC[] = "Panic(uint64 minEpoch)";
const char TYPE_REOPEN[] = "Reopen(address vault,uint256 nonce)";
const char TYPE_DENY[] = "Deny(uint256 agentId,bytes32 requestHash,bytes32 presenceHash)";
const char TYPE_BIND_DEVICE[] = "BindDevice(address owner,bytes32 px,bytes32 py)";

// Streams keccak256(typeHash || word || word || ...) without building the encoded buffer.
class StructHasher {
 public:
  explicit StructHasher(const char* typeString) {
    uint8_t th[32];
    keccak256(reinterpret_cast<const uint8_t*>(typeString), std::strlen(typeString), th);
    k_.update(th, 32);
  }
  void word(const uint8_t w[32]) { k_.update(w, 32); }
  void b32(const B32& b) { word(b.v); }
  void u256(const U256& u) { word(u.v); }
  void u64(uint64_t x) {
    U256 u = U256::from_u64(x);
    word(u.v);
  }
  void addr(const Addr& a) {
    uint8_t w[32] = {0};
    std::memcpy(w + 12, a.v, 20);
    word(w);
  }
  void bytes(const uint8_t* p, size_t n) {
    uint8_t h[32];
    keccak256(n ? p : nullptr, n, h);
    word(h);
  }
  void str(const char* s) { bytes(reinterpret_cast<const uint8_t*>(s ? s : ""), s ? std::strlen(s) : 0); }
  B32 finish() {
    B32 r;
    k_.final(r.v);
    return r;
  }

 private:
  Keccak256 k_;
};

}  // namespace

// 32 x 0xff (MetaMask DelegationManager.ROOT_AUTHORITY). Aggregate init -> constant-initialised, so it is
// safe to use from other translation units' static initialisers.
const B32 ROOT_AUTHORITY = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};

B32 eip712_domain(const char* name, const char* version, uint64_t chainId, const Addr& verifyingContract) {
  StructHasher s(TYPE_DOMAIN);
  s.str(name);
  s.str(version);
  s.u64(chainId);
  s.addr(verifyingContract);
  return s.finish();
}

B32 eip712_digest(const B32& domainSeparator, const B32& structHash) {
  static const uint8_t PREFIX[2] = {0x19, 0x01};
  Keccak256 k;
  k.update(PREFIX, 2);
  k.update(domainSeparator.v, 32);
  k.update(structHash.v, 32);
  B32 r;
  k.final(r.v);
  return r;
}

B32 hash_caveat(const Caveat& c) {
  StructHasher s(TYPE_CAVEAT);
  s.addr(c.enforcer);
  s.bytes(c.terms.data(), c.terms.size());
  return s.finish();
}

B32 hash_delegation(const Delegation& d) {
  Keccak256 arr;  // Caveat[]: keccak256 of the concatenated caveat struct hashes (keccak256("") if none)
  for (const Caveat& c : d.caveats) {
    B32 ch = hash_caveat(c);
    arr.update(ch.v, 32);
  }
  uint8_t caveatsHash[32];
  arr.final(caveatsHash);

  StructHasher s(TYPE_DELEGATION);
  s.addr(d.delegate);
  s.addr(d.delegator);
  s.b32(d.authority);
  s.word(caveatsHash);
  s.u256(d.salt);
  return s.finish();
}

B32 hash_human_approval(const HumanApproval& h) {
  StructHasher s(TYPE_HUMAN_APPROVAL);
  s.b32(h.delegationHash);
  s.addr(h.delegator);
  s.addr(h.redeemer);
  s.addr(h.target);
  s.u256(h.value);
  s.b32(h.callDataHash);
  s.u256(h.nonce);
  s.u64(h.expiry);
  s.b32(h.presenceHash);
  return s.finish();
}

B32 hash_revoke(const B32& delegationHash) {
  StructHasher s(TYPE_REVOKE);
  s.b32(delegationHash);
  return s.finish();
}

B32 hash_panic(uint64_t minEpoch) {
  StructHasher s(TYPE_PANIC);
  s.u64(minEpoch);
  return s.finish();
}

B32 hash_reopen(const Addr& vault, const U256& nonce) {
  StructHasher s(TYPE_REOPEN);
  s.addr(vault);
  s.u256(nonce);
  return s.finish();
}

B32 hash_deny(const U256& agentId, const B32& requestHash, const B32& presenceHash) {
  StructHasher s(TYPE_DENY);
  s.u256(agentId);
  s.b32(requestHash);
  s.b32(presenceHash);
  return s.finish();
}

B32 hash_bind_device(const Addr& owner, const B32& px, const B32& py) {
  StructHasher s(TYPE_BIND_DEVICE);
  s.addr(owner);
  s.b32(px);
  s.b32(py);
  return s.finish();
}

}  // namespace ripar
