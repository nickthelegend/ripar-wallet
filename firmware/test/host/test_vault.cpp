// DEPS: hashes util abi vault
// Host tests for the canonical vault derivation (src/vault.cpp, firmware v1.2):
//   - the embedded ERC1967Proxy creation code is exactly the 1008 bytes of @metamask/delegation-abis@2.0.0
//     (keccak256 compared with the Python copy of contracts/.work/ERC1967Proxy.creation.hex)
//   - known answer checked on Monad testnet (SimpleFactory.computeAddress + eth_call of SimpleFactory.deploy): the demo
//     K1 0x753454832754c071704be47915d4DeC6339624Eb owns the vault 0xc36F625D426eBa8f1e0129276B284a939CD3A57D,
//     initCodeHash 0x9694a695...60ce
//   - every intermediate (initialize calldata, constructor args, initCodeHash, address) byte-equal to the independent
//     Python implementation (tools/make_request.py vault_address -> test/host/vectors_protocol.h VAULT) for 8 owners
//   - ABI layout of the initialize call and of abi.encode(address, bytes) checked word by word
//   - every one of the 160 owner bits changes the vault (no bit of K1 is ignored)
#include <cstdio>
#include <cstring>
#include <set>
#include <string>

#include "abi.h"
#include "check.h"
#include "hashes.h"
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
std::string hexs(const Bytes& b) { return to_hex(b, false); }
std::string word_hex(const Bytes& b, size_t off) { return to_hex(b.data() + off, 32, false); }

}  // namespace

int main() {
  CHECK_SECTION("constants: proxy creation code, factory, implementation");
  {
    CHECK_EQ(VAULT_PROXY_CREATION_SIZE, size_t(1008));
    uint8_t k[32];
    keccak256(VAULT_PROXY_CREATION_CODE, VAULT_PROXY_CREATION_SIZE, k);
    CHECK_EQ_HEX(k, 32, pv::PROXY_CREATION_KECCAK);
    CHECK_EQ_HEX(k, 32, "c8fb9314d27cddb08b374dd2bf47cd06c6fb879756ddfbedf522a8c58756a8e0");
    // the code starts with the Solidity free-memory prologue and its constructor copies the 0x3f0 = 1008-byte image
    CHECK_EQ_HEX(VAULT_PROXY_CREATION_CODE, 13, "60806040526040516103f03803");
    Addr f, i;
    CHECK(addr_from_hex(VAULT_SIMPLE_FACTORY, f) && addr_checksum(f) == VAULT_SIMPLE_FACTORY);
    CHECK(addr_from_hex(VAULT_IMPLEMENTATION, i) && addr_checksum(i) == VAULT_IMPLEMENTATION);
    CHECK_EQ(std::string(VAULT_SIMPLE_FACTORY), std::string("0x69Aa2f9fe1572F1B640E1bbc512f5c3a734fc77c"));
    CHECK_EQ(std::string(VAULT_IMPLEMENTATION), std::string("0x48dBe696A4D990079e039489bA2053B36E8FFEC4"));
    CHECK_EQ(std::string(VAULT_INITIALIZE_SIGNATURE), std::string("initialize(address,string[],uint256[],uint256[])"));
  }

  CHECK_SECTION("known answer (Monad testnet, 2026-09-27): demo K1 -> vault 0xc36F...A57D");
  {
    const Addr k1 = A("753454832754c071704be47915d4DeC6339624Eb");
    CHECK_EQ_HEX(k1.v, 20, pv::DEMO_K1_ADDR);  // the demo seed's K1 (make_request.py demo-keys)
    const B32 ich = vault_init_code_hash(k1);
    CHECK_EQ_HEX(ich.v, 32, "9694a6959734c65d55361f8f8d333c8534d1e808dbfbb2694fab6c7c8cbd60ce");
    const Addr v = vault_address(k1);
    CHECK_EQ(addr_checksum(v), std::string("0xc36F625D426eBa8f1e0129276B284a939CD3A57D"));
    CHECK_EQ_HEX(v.v, 20, pv::DEMO_VAULT);
  }

  CHECK_SECTION("ABI layout: initialize(owner, [], [], []) and abi.encode(impl, bytes)");
  {
    const Addr owner = A("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    const Bytes init = vault_initialize_calldata(owner);
    CHECK_EQ(init.size(), size_t(228));
    uint8_t sel[32];
    static const char kSig[] = "initialize(address,string[],uint256[],uint256[])";
    keccak256(reinterpret_cast<const uint8_t*>(kSig), sizeof kSig - 1, sel);
    CHECK_EQ_HEX(sel, 4, "8ebf9533");
    CHECK_EQ_BYTES(init.data(), sel, 4);
    const Bytes body(init.begin() + 4, init.end());
    CHECK_EQ(word_hex(body, 0), std::string("0000000000000000000000005aaeb6053f3e94c9b9a09f33669435e7ef1beaed"));
    CHECK_EQ(word_hex(body, 32), std::string(62, '0') + "80");  // offset of string[]
    CHECK_EQ(word_hex(body, 64), std::string(62, '0') + "a0");  // offset of the first uint256[]
    CHECK_EQ(word_hex(body, 96), std::string(62, '0') + "c0");  // offset of the second uint256[]
    for (size_t off = 128; off < 224; off += 32) CHECK_EQ(word_hex(body, off), std::string(64, '0'));  // lengths 0
    const Bytes args = vault_constructor_args(owner);
    CHECK_EQ(args.size(), size_t(352));
    CHECK_EQ(word_hex(args, 0), std::string("00000000000000000000000048dbe696a4d990079e039489ba2053b36e8ffec4"));
    CHECK_EQ(word_hex(args, 32), std::string(62, '0') + "40");  // offset of bytes
    CHECK_EQ(word_hex(args, 64), std::string(62, '0') + "e4");  // 228 bytes
    CHECK(Bytes(args.begin() + 96, args.begin() + 96 + 228) == init);
    CHECK(Bytes(args.begin() + 96 + 228, args.end()) == Bytes(28, 0));  // right-padded to 256
    // initCodeHash = keccak256(creation code || args), streamed in the firmware
    Bytes creation(VAULT_PROXY_CREATION_CODE, VAULT_PROXY_CREATION_CODE + VAULT_PROXY_CREATION_SIZE);
    creation.insert(creation.end(), args.begin(), args.end());
    CHECK_EQ(creation.size(), size_t(1360));
    uint8_t h[32];
    keccak256(creation.data(), creation.size(), h);
    CHECK_EQ_BYTES(h, vault_init_code_hash(owner).v, 32);
    // CREATE2: keccak256(0xff || factory || salt 0 || initCodeHash)[12:]
    Bytes pre(1, 0xff);
    const Bytes fac = HX(VAULT_SIMPLE_FACTORY);
    pre.insert(pre.end(), fac.begin(), fac.end());
    pre.insert(pre.end(), 32, 0);
    pre.insert(pre.end(), h, h + 32);
    uint8_t a[32];
    keccak256(pre.data(), pre.size(), a);
    CHECK_EQ_BYTES(a + 12, vault_address(owner).v, 20);
  }

  CHECK_SECTION("independent Python implementation (vectors_protocol.h VAULT)");
  {
    size_t n = 0;
    for (const pv::Vault& v : pv::VAULT) {
      const Addr owner = A(v.owner);
      CHECK_EQ(hexs(vault_initialize_calldata(owner)), std::string(v.initcode));
      CHECK_EQ(hexs(vault_constructor_args(owner)), std::string(v.args));
      CHECK_EQ_HEX(vault_init_code_hash(owner).v, 32, v.initCodeHash);
      const Addr va = vault_address(owner);
      CHECK_EQ_HEX(va.v, 20, v.vault);
      CHECK_EQ(addr_checksum(va), std::string(v.vaultEip55));
      n++;
    }
    CHECK(n >= 8);
  }

  CHECK_SECTION("every owner bit matters; the vault is never the owner");
  {
    const Addr k1 = A(pv::DEMO_K1_ADDR);
    const Addr base = vault_address(k1);
    std::set<std::string> seen;
    seen.insert(hexs(Bytes(base.v, base.v + 20)));
    for (int bit = 0; bit < 160; bit++) {
      Addr o = k1;
      o.v[bit / 8] ^= uint8_t(1u << (bit % 8));
      const Addr v = vault_address(o);
      CHECK(v != base);
      seen.insert(hexs(Bytes(v.v, v.v + 20)));
    }
    CHECK_EQ(seen.size(), size_t(161));
    CHECK(base != k1);
    CHECK(vault_address(k1) == base);  // deterministic
  }

  CHECK_SECTION("vector sanity");
  CHECK_EQ(g_bad, 0);
  return CHECK_SUMMARY();
}
