// Portable crypto (host-tested against tools/ripar_ref.py): SHA-512, HMAC, secp256k1 + P-256 ECDSA
// (RFC 6979 deterministic nonces over SHA-256 digests, low-s), public-key recovery, DER,
// BIP-32 (secp256k1) and SLIP-10 (nist256p1) private derivation. Host + device.
// NOTE: not constant-time; acceptable for an air-gapped prototype (documented in docs/FIRMWARE.md).
#pragma once
#include <cstddef>
#include <cstdint>

#include "util.h"

namespace ripar {

void sha512(const uint8_t* data, size_t len, uint8_t out[64]);
void hmac_sha256(const uint8_t* key, size_t klen, const uint8_t* msg, size_t mlen, uint8_t out[32]);
void hmac_sha512(const uint8_t* key, size_t klen, const uint8_t* msg, size_t mlen, uint8_t out[64]);

enum class Curve { Secp256k1, P256 };

// xy64 = X||Y big-endian (no 0x04 prefix). false if priv is 0 or >= n.
bool ec_pubkey(Curve c, const uint8_t priv[32], uint8_t xy64[64]);
// RFC 6979 (HMAC-SHA256) nonce from (priv, digest); s normalised to low-s; recid (0/1) refers to the final
// (normalised) signature so that ecdsa_recover(digest, rs, recid) returns the signer's key.
bool ecdsa_sign(Curve c, const uint8_t priv[32], const uint8_t digest[32], uint8_t rs[64], int* recid);
bool ecdsa_verify(Curve c, const uint8_t xy64[64], const uint8_t digest[32], const uint8_t rs[64]);
bool ecdsa_recover(Curve c, const uint8_t digest[32], const uint8_t rs[64], int recid, uint8_t xy64[64]);
size_t ecdsa_der(const uint8_t rs[64], uint8_t out[72]);  // strict DER SEQUENCE{INTEGER r, INTEGER s}

struct ExtKey {
  uint8_t key[32];
  uint8_t chain[32];
};
// master: HMAC-SHA512 key "Bitcoin seed" (secp256k1) / "Nist256p1 seed" (P-256)
bool bip32_master(Curve c, const uint8_t* seed, size_t n, ExtKey& out);
// hardened when index >= 0x80000000. SLIP-10 retry rule for invalid keys on P-256.
bool bip32_ckd_priv(Curve c, const ExtKey& parent, uint32_t index, ExtKey& child);
bool derive_path(Curve c, const uint8_t* seed, size_t n, const uint32_t* path, size_t depth, uint8_t priv[32]);

Addr eth_address(const uint8_t xy64[64]);  // keccak256(X||Y)[12:]

constexpr uint32_t H = 0x80000000u;  // hardened offset
// K1: m/44'/60'/0'/0/0   P1: m/7951'/0'
extern const uint32_t PATH_K1[5];
extern const uint32_t PATH_P1[2];

}  // namespace ripar
