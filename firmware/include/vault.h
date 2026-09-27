// The device's canonical vault (firmware v1.2): the address of the MetaMask HybridDeleGator owned by K1, derived on
// the device from K1 alone. Portable C++14 (host + device), host-tested in test/host/test_vault.cpp against a
// known answer checked on Monad testnet and against the independent Python implementation in
// tools/make_request.py (vault_address()).
//
// Why: before v1.2 the vault was whatever address the (untrusted) companion put in pair-req key 8, and a pairing
// without key 8 accepted ANY delegator. A companion could pin a vault it controls (or none) and have mandates signed
// for it. Since v1.2 the device pins only the vault it derives itself: key 8, when present, must equal it, and every
// mandate / co-sign delegator must equal it (policy.h).
//
// Derivation (MetaMask delegation-framework v1.3.0, @metamask/smart-accounts-kit 2.0.0 getCounterfactualAccountData;
// same factory and implementation on Monad testnet 10143 and Monad 143):
//   initcode = abi.encodeWithSignature("initialize(address,string[],uint256[],uint256[])", K1, [], [], [])  228 bytes
//   args     = abi.encode(address HybridDeleGatorImpl, bytes initcode)                                   352 bytes
//   creation = ERC1967Proxy creation code (1008 bytes, @metamask/delegation-abis 2.0.0) || args
//   vault    = address(keccak256(0xff || SimpleFactory || bytes32(0) || keccak256(creation))[12:])
// Demo K1 0x753454832754c071704be47915d4DeC6339624Eb -> vault 0xc36F625D426eBa8f1e0129276B284a939CD3A57D
// (checked on chain with SimpleFactory.computeAddress and an eth_call of SimpleFactory.deploy, 2026-09-27).
#pragma once
#include <cstddef>
#include <cstdint>

#include "util.h"

namespace ripar {

extern const char VAULT_SIMPLE_FACTORY[];  // "0x69Aa2f9fe1572F1B640E1bbc512f5c3a734fc77c" (MetaMask SimpleFactory)
extern const char VAULT_IMPLEMENTATION[];  // "0x48dBe696A4D990079e039489bA2053B36E8FFEC4" (HybridDeleGator v1.3.0)
extern const char VAULT_INITIALIZE_SIGNATURE[];  // "initialize(address,string[],uint256[],uint256[])"
const size_t VAULT_PROXY_CREATION_SIZE = 1008;
extern const uint8_t VAULT_PROXY_CREATION_CODE[VAULT_PROXY_CREATION_SIZE];  // ERC1967Proxy creation code

// abi.encodeWithSignature(VAULT_INITIALIZE_SIGNATURE, owner, [], [], []): 4 + 7 * 32 = 228 bytes
Bytes vault_initialize_calldata(const Addr& owner);
// abi.encode(address VAULT_IMPLEMENTATION, bytes vault_initialize_calldata(owner)): 352 bytes
Bytes vault_constructor_args(const Addr& owner);
// keccak256(VAULT_PROXY_CREATION_CODE || vault_constructor_args(owner))
B32 vault_init_code_hash(const Addr& owner);
// CREATE2 by VAULT_SIMPLE_FACTORY with salt bytes32(0): the vault this device's K1 owns
Addr vault_address(const Addr& owner);

}  // namespace ripar
