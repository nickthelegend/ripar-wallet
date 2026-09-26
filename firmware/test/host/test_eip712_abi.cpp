// DEPS: hashes util eip712 abi
// Host tests for src/eip712.cpp + src/abi.cpp.
//   - EIP-712 spec "Mail" example (assets/eip-712/Example.js) through a test-only struct encoder built on the same
//     primitives (Keccak256, eip712_domain, eip712_digest).
//   - Every Ripar struct re-encoded by hand in this file from the literal PROTOCOL.md §3 type strings.
//   - Generated vectors (test/host/vectors_eip712_abi.h, written by tools/ref_eip712.py: generic EIP-712 encoder +
//     MetaMask EncoderLib port + integer-arithmetic format_units), random inputs incl. edge values.
//   - Hand-written ERC-20 decode positives/negatives, format_units, EIP-55, fingerprint cases.
#include <cstdio>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "abi.h"
#include "check.h"
#include "eip712.h"
#include "hashes.h"
#include "util.h"
#include "vectors_eip712_abi.h"

using namespace ripar;

// ------------------------------------------------------------------ parsing helpers
static int g_bad_vectors = 0;

static Bytes HX(const char* s) {
  Bytes b;
  if (!from_hex(s ? s : "", b)) {
    std::printf("bad hex in vector: %s\n", s ? s : "(null)");
    g_bad_vectors++;
  }
  return b;
}
static Addr A(const char* s) {
  Bytes b = HX(s);
  Addr a;
  if (b.size() == 20)
    std::memcpy(a.v, b.data(), 20);
  else
    g_bad_vectors++;
  return a;
}
static B32 B(const char* s) {
  Bytes b = HX(s);
  B32 r;
  if (b.size() == 32)
    std::memcpy(r.v, b.data(), 32);
  else
    g_bad_vectors++;
  return r;
}
static U256 U(const char* s) {
  Bytes b = HX(s);
  U256 r;
  if (!U256::from_be(b.data(), b.size(), r)) g_bad_vectors++;
  return r;
}
static U256 U64(uint64_t x) { return U256::from_u64(x); }

// ------------------------------------------------------------------ test-only EIP-712 encoder
// Buffers the whole encodeData (typeHash || words) and hashes it in one go - a different code path from the
// streaming encoder in eip712.cpp.
class Enc {
 public:
  explicit Enc(const char* typeString) { word(keccak_str(typeString)); }
  static B32 keccak_bytes(const uint8_t* p, size_t n) {
    B32 r;
    keccak256(p, n, r.v);
    return r;
  }
  static B32 keccak_str(const char* s) { return keccak_bytes(reinterpret_cast<const uint8_t*>(s), std::strlen(s)); }
  Enc& word(const B32& w) {
    buf_.insert(buf_.end(), w.v, w.v + 32);
    return *this;
  }
  Enc& u256(const U256& u) {
    buf_.insert(buf_.end(), u.v, u.v + 32);
    return *this;
  }
  Enc& u64(uint64_t x) { return u256(U256::from_u64(x)); }
  Enc& addr(const Addr& a) {
    buf_.insert(buf_.end(), 12, uint8_t(0));
    buf_.insert(buf_.end(), a.v, a.v + 20);
    return *this;
  }
  Enc& str(const char* s) { return word(keccak_str(s)); }
  Enc& bytes(const Bytes& b) { return word(keccak_bytes(b.data(), b.size())); }
  B32 hash() const { return keccak_bytes(buf_.data(), buf_.size()); }
  size_t size() const { return buf_.size(); }

 private:
  Bytes buf_;
};

// PROTOCOL.md §3, byte-exact (independent copy from the one in src/eip712.cpp)
static const char* const T_DELEGATION =
    "Delegation(address delegate,address delegator,bytes32 authority,Caveat[] caveats,uint256 salt)"
    "Caveat(address enforcer,bytes terms)";
static const char* const T_CAVEAT = "Caveat(address enforcer,bytes terms)";
static const char* const T_HUMAN =
    "HumanApproval(bytes32 delegationHash,address delegator,address redeemer,address target,uint256 value,"
    "bytes32 callDataHash,uint256 nonce,uint64 expiry,bytes32 presenceHash)";
static const char* const T_REVOKE = "Revoke(bytes32 delegationHash)";
static const char* const T_PANIC = "Panic(uint64 minEpoch)";
static const char* const T_REOPEN = "Reopen(address vault,uint256 nonce)";
static const char* const T_DENY = "Deny(uint256 agentId,bytes32 requestHash,bytes32 presenceHash)";
static const char* const T_BIND = "BindDevice(address owner,bytes32 px,bytes32 py)";
static const char* const T_DOMAIN = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

// byte i = (i*k + c)
static B32 fill32(uint8_t k, uint8_t c) {
  B32 r;
  for (int i = 0; i < 32; i++) r.v[i] = uint8_t(i * k + c);
  return r;
}
static Addr fill20(uint8_t k, uint8_t c) {
  Addr r;
  for (int i = 0; i < 20; i++) r.v[i] = uint8_t(i * k + c);
  return r;
}
static U256 fillU(uint8_t k, uint8_t c) {
  U256 r;
  B32 b = fill32(k, c);
  std::memcpy(r.v, b.v, 32);
  return r;
}
static Bytes fillN(size_t n, uint8_t k, uint8_t c) {
  Bytes b(n);
  for (size_t i = 0; i < n; i++) b[i] = uint8_t(i * k + c);
  return b;
}

// ================================================================== EIP-712
static void test_mail_example() {
  CHECK_SECTION("EIP-712 spec Mail example");
  const char* PERSON = "Person(string name,address wallet)";
  const char* MAIL = "Mail(Person from,Person to,string contents)Person(string name,address wallet)";
  B32 th = Enc::keccak_str(MAIL);
  CHECK_EQ_HEX(th.v, 32, "a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2");

  Addr cow = A("CD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826");
  Addr bob = A("bBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB");
  B32 from = Enc(PERSON).str("Cow").addr(cow).hash();
  B32 to = Enc(PERSON).str("Bob").addr(bob).hash();
  B32 mail = Enc(MAIL).word(from).word(to).str("Hello, Bob!").hash();
  CHECK_EQ_HEX(mail.v, 32, "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e");

  Addr vc = A("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC");
  B32 ds = eip712_domain("Ether Mail", "1", 1, vc);
  CHECK_EQ_HEX(ds.v, 32, "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f");
  B32 dg = eip712_digest(ds, mail);
  CHECK_EQ_HEX(dg.v, 32, "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2");

  // the test-only domain encoder agrees with eip712_domain()
  B32 ds2 = Enc(T_DOMAIN).str("Ether Mail").str("1").u64(1).addr(vc).hash();
  CHECK_EQ_BYTES(ds2.v, ds.v, 32);
}

static void test_typehashes() {
  CHECK_SECTION("typehashes / ROOT_AUTHORITY");
  // MetaMask delegation-framework Constants.sol typehashes (strings verified against the framework source)
  B32 t = Enc::keccak_str(T_DELEGATION);
  CHECK_EQ_HEX(t.v, 32, "88c1d2ecf185adf710588203a5f263f0ff61be0d33da39792cde19ba9aa4331e");
  t = Enc::keccak_str(T_CAVEAT);
  CHECK_EQ_HEX(t.v, 32, "80ad7e1b04ee6d994a125f4714ca0720908bd80ed16063ec8aee4b88e9253e2d");
  t = Enc::keccak_str(T_DOMAIN);
  CHECK_EQ_HEX(t.v, 32, "8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f");
  CHECK_EQ_HEX(ROOT_AUTHORITY.v, 32, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
}

// Each library hash == manual re-encoding from the literal PROTOCOL.md type string (fixed, non-trivial inputs).
static void test_manual_reencode() {
  CHECK_SECTION("manual re-encoding from PROTOCOL.md type strings");
  // Caveat
  Caveat c1{fill20(3, 1), fillN(33, 5, 7)};
  B32 hc1 = Enc(T_CAVEAT).addr(c1.enforcer).bytes(c1.terms).hash();
  B32 lib = hash_caveat(c1);
  CHECK_EQ_BYTES(lib.v, hc1.v, 32);

  // Delegation with 0 / 1 / 3 caveats
  Delegation d;
  d.delegate = fill20(11, 2);
  d.delegator = fill20(13, 9);
  d.authority = ROOT_AUTHORITY;
  d.salt = U64(0x1234567890ull);
  const uint8_t EMPTY_KECCAK[] = {0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d,
                                  0xb2, 0xdc, 0xc7, 0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82,
                                  0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70};
  B32 emptyArr;
  std::memcpy(emptyArr.v, EMPTY_KECCAK, 32);
  B32 want0 = Enc(T_DELEGATION).addr(d.delegate).addr(d.delegator).word(d.authority).word(emptyArr).u256(d.salt).hash();
  lib = hash_delegation(d);
  CHECK_EQ_BYTES(lib.v, want0.v, 32);

  d.caveats.push_back(c1);
  B32 arr1 = Enc::keccak_bytes(hc1.v, 32);
  B32 want1 = Enc(T_DELEGATION).addr(d.delegate).addr(d.delegator).word(d.authority).word(arr1).u256(d.salt).hash();
  lib = hash_delegation(d);
  CHECK_EQ_BYTES(lib.v, want1.v, 32);

  Caveat c2{fill20(1, 0xa0), Bytes()};             // empty terms
  Caveat c3{fill20(7, 0x33), fillN(137, 1, 0x80)};  // terms longer than one keccak block
  d.caveats.push_back(c2);
  d.caveats.push_back(c3);
  Bytes cat;
  B32 hc2 = Enc(T_CAVEAT).addr(c2.enforcer).bytes(c2.terms).hash();
  B32 hc3 = Enc(T_CAVEAT).addr(c3.enforcer).bytes(c3.terms).hash();
  cat.insert(cat.end(), hc1.v, hc1.v + 32);
  cat.insert(cat.end(), hc2.v, hc2.v + 32);
  cat.insert(cat.end(), hc3.v, hc3.v + 32);
  B32 arr3 = Enc::keccak_bytes(cat.data(), cat.size());
  B32 want3 = Enc(T_DELEGATION).addr(d.delegate).addr(d.delegator).word(d.authority).word(arr3).u256(d.salt).hash();
  lib = hash_delegation(d);
  CHECK_EQ_BYTES(lib.v, want3.v, 32);
  CHECK(!(want0 == want1) && !(want1 == want3) && !(want0 == want3));

  // caveat order matters; empty terms != one zero byte; authority is hashed
  Delegation swapped = d;
  std::swap(swapped.caveats[0], swapped.caveats[2]);
  CHECK(!(hash_delegation(swapped) == hash_delegation(d)));
  Caveat z0{c2.enforcer, Bytes()}, z1{c2.enforcer, Bytes(1, 0)};
  CHECK(!(hash_caveat(z0) == hash_caveat(z1)));
  Delegation nonroot = d;
  nonroot.authority.v[31] = 0xfe;
  CHECK(!(hash_delegation(nonroot) == hash_delegation(d)));

  // HumanApproval (expiry = uint64 max -> 24 zero bytes + 8 x ff)
  HumanApproval h;
  h.delegationHash = fill32(3, 0x11);
  h.delegator = fill20(5, 0x22);
  h.redeemer = fill20(7, 0x33);
  h.target = fill20(9, 0x44);
  h.value = fillU(11, 0x55);
  h.callDataHash = fill32(13, 0x66);
  h.nonce = fillU(15, 0x77);
  h.expiry = 0xffffffffffffffffull;
  h.presenceHash = fill32(17, 0x88);
  Enc eh(T_HUMAN);
  eh.word(h.delegationHash).addr(h.delegator).addr(h.redeemer).addr(h.target).u256(h.value).word(h.callDataHash);
  eh.u256(h.nonce).u64(h.expiry).word(h.presenceHash);
  CHECK_EQ(eh.size(), size_t(32 * 10));
  B32 wantH = eh.hash();
  lib = hash_human_approval(h);
  CHECK_EQ_BYTES(lib.v, wantH.v, 32);
  HumanApproval h2 = h;
  h2.expiry = 0x7fffffffffffffffull;
  CHECK(!(hash_human_approval(h2) == hash_human_approval(h)));

  B32 x = fill32(19, 0x99);
  B32 w = Enc(T_REVOKE).word(x).hash();
  lib = hash_revoke(x);
  CHECK_EQ_BYTES(lib.v, w.v, 32);

  w = Enc(T_PANIC).u64(0x0123456789abcdefull).hash();
  lib = hash_panic(0x0123456789abcdefull);
  CHECK_EQ_BYTES(lib.v, w.v, 32);
  w = Enc(T_PANIC).u64(0).hash();
  lib = hash_panic(0);
  CHECK_EQ_BYTES(lib.v, w.v, 32);

  Addr vault = fill20(23, 0xaa);
  U256 nonce = fillU(29, 0xbb);
  w = Enc(T_REOPEN).addr(vault).u256(nonce).hash();
  lib = hash_reopen(vault, nonce);
  CHECK_EQ_BYTES(lib.v, w.v, 32);

  U256 agent = U64(42);
  B32 rq = fill32(31, 0xcc), ph = fill32(37, 0xdd);
  w = Enc(T_DENY).u256(agent).word(rq).word(ph).hash();
  lib = hash_deny(agent, rq, ph);
  CHECK_EQ_BYTES(lib.v, w.v, 32);

  Addr owner = fill20(41, 0xee);
  B32 px = fill32(43, 0x01), py = fill32(47, 0x02);
  w = Enc(T_BIND).addr(owner).word(px).word(py).hash();
  lib = hash_bind_device(owner, px, py);
  CHECK_EQ_BYTES(lib.v, w.v, 32);
  CHECK(!(hash_bind_device(owner, py, px) == lib));  // px / py order matters

  // digest = keccak(0x19 0x01 || ds || sh)
  B32 ds = fill32(53, 0x03), sh = fill32(59, 0x04);
  uint8_t pre[66];
  pre[0] = 0x19;
  pre[1] = 0x01;
  std::memcpy(pre + 2, ds.v, 32);
  std::memcpy(pre + 34, sh.v, 32);
  B32 wantD = Enc::keccak_bytes(pre, 66);
  lib = eip712_digest(ds, sh);
  CHECK_EQ_BYTES(lib.v, wantD.v, 32);

  // null name/version are treated as ""
  B32 dn = eip712_domain(nullptr, nullptr, 7, vault);
  B32 de = eip712_domain("", "", 7, vault);
  CHECK_EQ_BYTES(dn.v, de.v, 32);
}

static Delegation to_delegation(const vec::Delegation& v) {
  Delegation d;
  d.delegate = A(v.delegate);
  d.delegator = A(v.delegator);
  d.authority = B(v.authority);
  d.salt = U(v.salt);
  for (unsigned i = 0; i < v.ncaveats && i < 5; i++) {
    Caveat c;
    c.enforcer = A(v.caveats[i].enforcer);
    c.terms = HX(v.caveats[i].terms);
    d.caveats.push_back(c);
  }
  return d;
}

static void test_vectors_eip712() {
  CHECK_SECTION("vectors: domains");
  for (const vec::Domain& v : vec::DOMAINS) {
    B32 ds = eip712_domain(v.name, v.version, v.chainId, A(v.contract));
    CHECK_EQ_HEX(ds.v, 32, v.separator);
  }

  CHECK_SECTION("vectors: Delegation (0..5 caveats)");
  unsigned seen[6] = {0, 0, 0, 0, 0, 0};
  for (const vec::Delegation& v : vec::DELEGATIONS) {
    Delegation d = to_delegation(v);
    if (v.ncaveats < 6) seen[v.ncaveats]++;
    for (size_t i = 0; i < d.caveats.size(); i++) {
      B32 ch = hash_caveat(d.caveats[i]);
      CHECK_EQ_HEX(ch.v, 32, v.caveats[i].hash);
    }
    B32 sh = hash_delegation(d);
    CHECK_EQ_HEX(sh.v, 32, v.hash);
    B32 dg = eip712_digest(eip712_domain("DelegationManager", "1", v.chainId, A(v.manager)), sh);
    CHECK_EQ_HEX(dg.v, 32, v.digest);
  }
  CHECK(seen[0] >= 3 && seen[1] >= 3 && seen[3] >= 3);

  CHECK_SECTION("vectors: HumanApproval");
  for (const vec::HumanApproval& v : vec::HUMAN_APPROVALS) {
    HumanApproval h;
    h.delegationHash = B(v.delegationHash);
    h.delegator = A(v.delegator);
    h.redeemer = A(v.redeemer);
    h.target = A(v.target);
    h.value = U(v.value);
    h.callDataHash = B(v.callDataHash);
    h.nonce = U(v.nonce);
    h.expiry = v.expiry;
    h.presenceHash = B(v.presenceHash);
    B32 sh = hash_human_approval(h);
    CHECK_EQ_HEX(sh.v, 32, v.hash);
    B32 dg = eip712_digest(eip712_domain("RiparPulseCosign", "1", v.chainId, A(v.enforcer)), sh);
    CHECK_EQ_HEX(dg.v, 32, v.digest);
  }

  CHECK_SECTION("vectors: Revoke / Panic");
  for (const vec::Revoke& v : vec::REVOKES) {
    B32 sh = hash_revoke(B(v.delegationHash));
    CHECK_EQ_HEX(sh.v, 32, v.hash);
    B32 dg = eip712_digest(eip712_domain("RiparPulseCosign", "1", v.chainId, A(v.enforcer)), sh);
    CHECK_EQ_HEX(dg.v, 32, v.digest);
  }
  for (const vec::Panic& v : vec::PANICS) {
    B32 sh = hash_panic(v.minEpoch);
    CHECK_EQ_HEX(sh.v, 32, v.hash);
    B32 dg = eip712_digest(eip712_domain("RiparPulseCosign", "1", v.chainId, A(v.enforcer)), sh);
    CHECK_EQ_HEX(dg.v, 32, v.digest);
  }

  CHECK_SECTION("vectors: Reopen / Deny / BindDevice");
  for (const vec::Reopen& v : vec::REOPENS) {
    B32 sh = hash_reopen(A(v.vault), U(v.nonce));
    CHECK_EQ_HEX(sh.v, 32, v.hash);
    B32 dg = eip712_digest(eip712_domain("RiparSentinel", "1", v.chainId, A(v.sentinel)), sh);
    CHECK_EQ_HEX(dg.v, 32, v.digest);
  }
  for (const vec::Deny& v : vec::DENIES) {
    B32 sh = hash_deny(U(v.agentId), B(v.requestHash), B(v.presenceHash));
    CHECK_EQ_HEX(sh.v, 32, v.hash);
    B32 dg = eip712_digest(eip712_domain("RiparReputationRelay", "1", v.chainId, A(v.relay)), sh);
    CHECK_EQ_HEX(dg.v, 32, v.digest);
  }
  for (const vec::BindDevice& v : vec::BIND_DEVICES) {
    B32 sh = hash_bind_device(A(v.owner), B(v.px), B(v.py));
    CHECK_EQ_HEX(sh.v, 32, v.hash);
    B32 dg = eip712_digest(eip712_domain("RiparDeviceRegistry", "1", v.chainId, A(v.registry)), sh);
    CHECK_EQ_HEX(dg.v, 32, v.digest);
  }
}

// ================================================================== ABI
static Bytes cd_transfer(uint32_t sel, const Addr& to, const U256& amt) {
  Bytes b;
  for (int i = 3; i >= 0; i--) b.push_back(uint8_t(sel >> (8 * i)));
  b.insert(b.end(), 12, uint8_t(0));
  b.insert(b.end(), to.v, to.v + 20);
  b.insert(b.end(), amt.v, amt.v + 32);
  return b;
}

static void test_abi_handwritten() {
  CHECK_SECTION("abi: hand-written");
  // transfer(0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045, 1_000_000)
  Bytes cd = HX(
      "a9059cbb"
      "000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045"
      "00000000000000000000000000000000000000000000000000000000000f4240");
  Erc20Call c = abi_decode_erc20(cd);
  CHECK_EQ(c.kind, Erc20Call::Transfer);
  CHECK_EQ(c.selector, 0xa9059cbbu);
  CHECK_EQ_HEX(c.to.v, 20, "d8da6bf26964af9d7eed9e03e53415d37aa96045");
  CHECK(c.from.is_zero());
  CHECK_EQ(c.amount.fits_u64(), true);
  CHECK_EQ(c.amount.low_u64(), 1000000ull);
  CHECK_EQ(format_units(c.amount, 6), std::string("1"));
  CHECK_EQ(addr_checksum(c.to), std::string("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"));

  // approve(spender, 2^256-1)
  cd = HX(
      "095ea7b3"
      "0000000000000000000000001111111254eeb25477b68fb85ed929f73a960582"
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
  c = abi_decode_erc20(cd);
  CHECK_EQ(c.kind, Erc20Call::Approve);
  CHECK_EQ_HEX(c.to.v, 20, "1111111254eeb25477b68fb85ed929f73a960582");
  CHECK_EQ_HEX(c.amount.v, 32, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

  // transferFrom(a, b, 5)
  cd = HX(
      "23b872dd"
      "000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      "0000000000000000000000000000000000000000000000000000000000000005");
  c = abi_decode_erc20(cd);
  CHECK_EQ(c.kind, Erc20Call::TransferFrom);
  CHECK_EQ(c.selector, 0x23b872ddu);
  CHECK_EQ_HEX(c.from.v, 20, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  CHECK_EQ_HEX(c.to.v, 20, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
  CHECK_EQ(c.amount.low_u64(), 5ull);

  // empty -> None; 1..3 bytes -> Unknown with selector 0
  c = abi_decode_erc20(Bytes());
  CHECK_EQ(c.kind, Erc20Call::None);
  CHECK_EQ(c.selector, 0u);
  for (size_t n = 1; n <= 3; n++) {
    c = abi_decode_erc20(Bytes(n, 0xa9));
    CHECK_EQ(c.kind, Erc20Call::Unknown);
    CHECK_EQ(c.selector, 0u);
  }

  // every truncation / extension of a valid transfer is rejected, and nothing leaks into to/amount
  Addr to = fill20(3, 0x10);
  U256 amt = U64(777);
  Bytes good = cd_transfer(0xa9059cbbu, to, amt);
  CHECK_EQ(abi_decode_erc20(good).kind, Erc20Call::Transfer);
  bool allUnknown = true, allClean = true;
  for (size_t n = 4; n < good.size(); n++) {
    Bytes b(good.begin(), good.begin() + std::ptrdiff_t(n));
    Erc20Call r = abi_decode_erc20(b);
    if (r.kind != Erc20Call::Unknown) allUnknown = false;
    if (!r.to.is_zero() || !r.amount.is_zero() || !r.from.is_zero()) allClean = false;
  }
  CHECK(allUnknown);
  CHECK(allClean);
  Bytes longer = good;
  longer.push_back(0);
  CHECK_EQ(abi_decode_erc20(longer).kind, Erc20Call::Unknown);

  // any non-zero byte in the 12-byte address padding is rejected
  bool dirtyRejected = true;
  for (int i = 0; i < 12; i++) {
    Bytes b = good;
    b[size_t(4 + i)] = 0x01;
    Erc20Call r = abi_decode_erc20(b);
    if (r.kind != Erc20Call::Unknown || !r.to.is_zero()) dirtyRejected = false;
  }
  CHECK(dirtyRejected);
  // transferFrom: dirty 'to' word (second address) rejected too
  cd[4 + 32 + 11] = 0x80;
  CHECK_EQ(abi_decode_erc20(cd).kind, Erc20Call::Unknown);

  // high bits of the amount word are fine (uint256)
  U256 big = fillU(1, 0x80);
  c = abi_decode_erc20(cd_transfer(0xa9059cbbu, to, big));
  CHECK_EQ(c.kind, Erc20Call::Transfer);
  CHECK_EQ_BYTES(c.amount.v, big.v, 32);

  // unknown selector keeps the selector for display
  c = abi_decode_erc20(cd_transfer(0x39509351u, to, amt));  // increaseAllowance(address,uint256)
  CHECK_EQ(c.kind, Erc20Call::Unknown);
  CHECK_EQ(c.selector, 0x39509351u);
  CHECK(c.to.is_zero() && c.amount.is_zero());
}

static void test_vectors_abi() {
  CHECK_SECTION("vectors: ERC-20 calldata");
  for (const vec::Erc20& v : vec::ERC20S) {
    Erc20Call c = abi_decode_erc20(HX(v.calldata));
    bool ok = CHECK_EQ(c.kind, v.kind);
    ok &= CHECK_EQ(c.selector, v.selector);
    ok &= CHECK_EQ_HEX(c.from.v, 20, v.from);
    ok &= CHECK_EQ_HEX(c.to.v, 20, v.to);
    ok &= CHECK_EQ_HEX(c.amount.v, 32, v.amount);
    if (!ok) std::printf("     (vector: %s)\n", v.note);
  }
}

// ================================================================== formatting
static void test_checksum_fingerprint() {
  CHECK_SECTION("addr_checksum (EIP-55) + short_addr consistency");
  for (const vec::Checksum& v : vec::CHECKSUMS) {
    Addr a = A(v.lower);
    std::string cs = addr_checksum(a);
    CHECK_EQ(cs, std::string(v.checksum));
    CHECK_EQ(short_addr(a), cs.substr(0, 6) + "..." + cs.substr(38));
  }
  // EIP-55 spec vectors, written out here too
  const char* SPEC[] = {"0x52908400098527886E0F7030069857D2E4169EE7", "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
                        "0xde709f2102306220921060314715629080e2fb77", "0x27b1fdb04752bbc536007a920d24acb045561c26",
                        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
                        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"};
  for (const char* s : SPEC) CHECK_EQ(addr_checksum(A(s)), std::string(s));

  CHECK_SECTION("addr_fingerprint");
  for (const vec::Checksum& v : vec::CHECKSUMS) {
    uint8_t idx[4] = {0xff, 0xff, 0xff, 0xff};
    addr_fingerprint(A(v.lower), idx);
    CHECK_EQ_BYTES(idx, v.fp, 4);
  }
  std::set<std::string> names;
  bool shortLower = true;
  for (int i = 0; i < 16; i++) {
    const char* n = FINGERPRINT_NAMES[i];
    if (!n || !*n || std::strlen(n) > 6) {
      shortLower = false;
      continue;
    }
    for (const char* p = n; *p; p++)
      if (*p < 'a' || *p > 'z') shortLower = false;
    names.insert(n);
  }
  CHECK(shortLower);
  CHECK_EQ(names.size(), size_t(16));
  CHECK_EQ(std::string(FINGERPRINT_NAMES[0]), std::string("sun"));
}

static void test_format_units() {
  CHECK_SECTION("format_units: hand-written");
  CHECK_EQ(format_units(U64(0), 18), std::string("0"));
  CHECK_EQ(format_units(U64(12500000), 6), std::string("12.5"));
  CHECK_EQ(format_units(U64(1), 6), std::string("0.000001"));
  CHECK_EQ(format_units(U64(1234500000), 6), std::string("1,234.5"));
  CHECK_EQ(format_units(U64(1000000000000000000ull), 18), std::string("1"));
  CHECK_EQ(format_units(U64(1500000000000000000ull), 18), std::string("1.5"));
  CHECK_EQ(format_units(U64(1), 18), std::string("0.000000..."));  // never shown as a plain 0
  CHECK_EQ(format_units(U64(1234567), 6, 2), std::string("1.23..."));
  CHECK_EQ(format_units(U64(1230000), 6, 2), std::string("1.23"));
  CHECK_EQ(format_units(U64(1500000), 6, 0), std::string("1..."));
  CHECK_EQ(format_units(U64(1000000), 6, 0), std::string("1"));
  CHECK_EQ(format_units(U64(123456789), 0), std::string("123,456,789"));
  CHECK_EQ(format_units(U64(999), 0), std::string("999"));
  CHECK_EQ(format_units(U64(1000), 0), std::string("1,000"));
  CHECK_EQ(format_units(U64(100000), 0), std::string("100,000"));
  CHECK_EQ(format_units(U64(1000000), 0), std::string("1,000,000"));
  CHECK_EQ(format_units(U64(18446744073709551615ull), 0), std::string("18,446,744,073,709,551,615"));
  CHECK_EQ(format_units(U64(7), -3), std::string("7"));
  CHECK_EQ(format_units(U64(12345), 2, -1), std::string("123..."));
  CHECK_EQ(format_units(U64(1), 1000000000), std::string("0.000000..."));  // huge decimals: no big allocation

  CHECK_SECTION("vectors: format_units");
  for (const vec::Units& v : vec::UNITS) {
    std::string got = format_units(U(v.value), v.decimals, v.maxFrac);
    if (!CHECK_EQ(got, std::string(v.text))) std::printf("     (value %s dec %d maxFrac %d)\n", v.value, v.decimals, v.maxFrac);
  }
}

int main() {
  test_mail_example();
  test_typehashes();
  test_manual_reencode();
  test_vectors_eip712();
  test_abi_handwritten();
  test_vectors_abi();
  test_checksum_fingerprint();
  test_format_units();
  CHECK_SECTION("vector parsing");
  CHECK_EQ(g_bad_vectors, 0);
  return CHECK_SUMMARY();
}
