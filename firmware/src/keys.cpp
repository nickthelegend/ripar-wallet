// Device keys: 32-byte seed in NVS (Preferences "ripar" / "seed"), K1 (secp256k1, BIP-32 m/44'/60'/0'/0/0)
// and P1 (P-256, SLIP-10 m/7951'/0') derived with crypto.h.
//
// Only public data is cached in RAM (K1 address, K1/P1 public keys). Each signature re-reads the seed,
// derives the one private key it needs, signs, verifies the result against the cached public key (catches
// arithmetic faults and crypto bugs before anything leaves the device) and zeroizes seed + key.
//
// Entropy: with Wi-Fi/BT never started, esp_fill_random() is only a true RNG while the SAR-ADC entropy source
// is on, so every draw is wrapped in bootloader_random_enable()/disable(). Do not call trng_fill() /
// keys_create() while another task uses the ADC (battery_percent() runs on the app thread, so it's fine).
// RIPAR_BLE / RIPAR_WIFI: while the Bluetooth controller or the Wi-Fi driver runs (the optional BLE link, the Wi-Fi
// test link), the RF subsystem already feeds the RNG and bootloader_random_enable() must not reconfigure the ADC under
// it (ESP-IDF), so trng_fill() then draws directly - no ADC entropy toggling while any radio is up.
// Keys are only ever created at the first boot, before any radio can be on (Wi-Fi's persisted WI-FI ON choice is only
// acted on after the keys exist).
//
// keys_selftest() checks crypto.cpp on the real hardware against published vectors (RFC 6979 A.2.5 P-256,
// the "Satoshi Nakamoto" secp256k1 RFC 6979 vector, BIP-32 TV1, SLIP-10 nist256p1 TV1) and cross-checks it
// with the independent mbedTLS 2.28 implementation that ships with the core (SHA-256/512, HMAC-SHA512,
// public keys, RFC 6979 signatures via mbedtls_ecdsa_sign_det_ext + low-s, verification, DER parsing).
#include <Arduino.h>
#include <Preferences.h>

#include <cstdio>
#include <cstring>

#include "bootloader_random.h"
#include "crypto.h"
#include "device.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "hashes.h"
#if RIPAR_BLE
#include "ble_link.h"
#endif
#if RIPAR_WIFI
#include "wifi_link.h"
#endif
#include "mbedtls/bignum.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

namespace ripar {
namespace {

constexpr const char* kNs = "ripar";
constexpr const char* kSeedKey = "seed";

bool g_have = false;
Addr g_k1addr;
uint8_t g_k1pub[64];
uint8_t g_p1pub[64];

void wipe(void* p, size_t n) {
  volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
  while (n--) *v++ = 0;
}

bool load_seed(uint8_t seed[32]) {
  Preferences prefs;
  if (!prefs.begin(kNs, true)) return false;
  const bool ok = prefs.getBytesLength(kSeedKey) == 32 && prefs.getBytes(kSeedKey, seed, 32) == 32;
  prefs.end();
  if (!ok) wipe(seed, 32);
  return ok;
}

bool derive_one(Curve c, uint8_t priv[32]) {
  uint8_t seed[32];
  if (!load_seed(seed)) return false;
  const bool ok = c == Curve::Secp256k1 ? derive_path(c, seed, 32, PATH_K1, 5, priv)
                                        : derive_path(c, seed, 32, PATH_P1, 2, priv);
  wipe(seed, sizeof seed);
  if (!ok) wipe(priv, 32);
  return ok;
}

// derive both keys from the stored seed and cache the public data
bool load_public() {
  uint8_t seed[32], k1[32], p1[32];
  bool ok = load_seed(seed) && derive_keys_from_seed(seed, k1, p1);
  ok = ok && ec_pubkey(Curve::Secp256k1, k1, g_k1pub) && ec_pubkey(Curve::P256, p1, g_p1pub);
  wipe(seed, sizeof seed);
  wipe(k1, sizeof k1);
  wipe(p1, sizeof p1);
  if (ok) {
    g_k1addr = eth_address(g_k1pub);
  } else {
    g_k1addr = Addr();
    wipe(g_k1pub, 64);
    wipe(g_p1pub, 64);
  }
  g_have = ok;
  return ok;
}

// s <= n/2 (big-endian compare); on-chain verifiers (OZ ECDSA.recover / P256.verify) reject high-s
bool is_low_s(Curve c, const uint8_t rs[64]) {
  static const uint8_t kHalfK1[32] = {0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                      0xff, 0xff, 0xff, 0xff, 0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4,
                                      0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0};
  static const uint8_t kHalfP256[32] = {0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff, 0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b,
                                        0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8};
  return std::memcmp(rs + 32, c == Curve::P256 ? kHalfP256 : kHalfK1, 32) <= 0;
}

// ---------------- mbedTLS cross-check helpers ----------------
int mb_rng(void*, unsigned char* out, size_t n) {
  esp_fill_random(out, n);
  return 0;
}

mbedtls_ecp_group_id grp_id(Curve c) {
  return c == Curve::P256 ? MBEDTLS_ECP_DP_SECP256R1 : MBEDTLS_ECP_DP_SECP256K1;
}

bool mb_pubkey(Curve c, const uint8_t priv[32], uint8_t xy64[64]) {
  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_mpi d;
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi_init(&d);
  uint8_t out[65];
  size_t olen = 0;
  bool ok = mbedtls_ecp_group_load(&grp, grp_id(c)) == 0 && mbedtls_mpi_read_binary(&d, priv, 32) == 0 &&
            mbedtls_ecp_check_privkey(&grp, &d) == 0 && mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, mb_rng, nullptr) == 0 &&
            mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, out, sizeof out) == 0 &&
            olen == 65;
  if (ok) std::memcpy(xy64, out + 1, 64);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_point_free(&Q);
  mbedtls_ecp_group_free(&grp);
  return ok;
}

bool mb_verify(Curve c, const uint8_t xy64[64], const uint8_t digest[32], const uint8_t rs[64]) {
  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_mpi r, s;
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  uint8_t pt[65];
  pt[0] = 0x04;
  std::memcpy(pt + 1, xy64, 64);
  const bool ok = mbedtls_ecp_group_load(&grp, grp_id(c)) == 0 && mbedtls_ecp_point_read_binary(&grp, &Q, pt, 65) == 0 &&
                  mbedtls_ecp_check_pubkey(&grp, &Q) == 0 && mbedtls_mpi_read_binary(&r, rs, 32) == 0 &&
                  mbedtls_mpi_read_binary(&s, rs + 32, 32) == 0 &&
                  mbedtls_ecdsa_verify(&grp, digest, 32, &Q, &r, &s) == 0;
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&r);
  mbedtls_ecp_point_free(&Q);
  mbedtls_ecp_group_free(&grp);
  return ok;
}

// RFC 6979 (HMAC-SHA256) signature from mbedTLS, normalised to low-s
bool mb_sign_det(Curve c, const uint8_t priv[32], const uint8_t digest[32], uint8_t rs[64]) {
  mbedtls_ecp_group grp;
  mbedtls_mpi d, r, s, half;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  mbedtls_mpi_init(&half);
  bool ok = mbedtls_ecp_group_load(&grp, grp_id(c)) == 0 && mbedtls_mpi_read_binary(&d, priv, 32) == 0 &&
            mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &d, digest, 32, MBEDTLS_MD_SHA256, mb_rng, nullptr) == 0 &&
            mbedtls_mpi_copy(&half, &grp.N) == 0 && mbedtls_mpi_shift_r(&half, 1) == 0;
  if (ok && mbedtls_mpi_cmp_mpi(&s, &half) > 0) ok = mbedtls_mpi_sub_mpi(&s, &grp.N, &s) == 0;
  ok = ok && mbedtls_mpi_write_binary(&r, rs, 32) == 0 && mbedtls_mpi_write_binary(&s, rs + 32, 32) == 0;
  mbedtls_mpi_free(&half);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  return ok;
}

bool mb_read_der(Curve c, const uint8_t xy64[64], const uint8_t digest[32], const uint8_t* der, size_t n) {
  mbedtls_ecdsa_context ctx;
  mbedtls_ecdsa_init(&ctx);
  uint8_t pt[65];
  pt[0] = 0x04;
  std::memcpy(pt + 1, xy64, 64);
  const bool ok = mbedtls_ecp_group_load(&ctx.grp, grp_id(c)) == 0 &&
                  mbedtls_ecp_point_read_binary(&ctx.grp, &ctx.Q, pt, 65) == 0 &&
                  mbedtls_ecdsa_read_signature(&ctx, digest, 32, der, n) == 0;
  mbedtls_ecdsa_free(&ctx);
  return ok;
}

// ---------------- self-test ----------------
bool unhex(const char* s, uint8_t* out, size_t n) {
  Bytes b;
  if (!from_hex(s, b) || b.size() != n) return false;
  std::memcpy(out, b.data(), n);
  return true;
}

struct Report {
  std::string& out;
  int fails = 0;
  void check(const char* name, bool ok) {
    out += ok ? "PASS " : "FAIL ";
    out += name;
    out += '\n';
    if (!ok) fails++;
  }
};

void sha256_str(const char* s, uint8_t out[32]) { sha256(reinterpret_cast<const uint8_t*>(s), std::strlen(s), out); }

// One published vector: priv, sha256(msg), expected pubkey (x||y or empty), expected r||s (low-s), recid.
void check_vector(Report& R, const char* tag, Curve c, const char* privHex, const char* msg, const char* pubHex,
                  const char* rsHex, int expRecid) {
  uint8_t d[32], dig[32], pub[64], expPub[64], rs[64], expRs[64], mbRs[64], mbPub[64], der[72], rec[64];
  char name[96];
  const bool vecOk = unhex(privHex, d, 32) && unhex(pubHex, expPub, 64) && unhex(rsHex, expRs, 64);
  sha256_str(msg, dig);
  std::snprintf(name, sizeof name, "%s vector parse", tag);
  R.check(name, vecOk);

  const bool pubOk = ec_pubkey(c, d, pub);
  std::snprintf(name, sizeof name, "%s ec_pubkey == vector", tag);
  R.check(name, pubOk && std::memcmp(pub, expPub, 64) == 0);
  std::snprintf(name, sizeof name, "%s ec_pubkey == mbedTLS", tag);
  R.check(name, pubOk && mb_pubkey(c, d, mbPub) && std::memcmp(pub, mbPub, 64) == 0);

  int recid = -1;
  const bool sigOk = ecdsa_sign(c, d, dig, rs, &recid);
  std::snprintf(name, sizeof name, "%s ecdsa_sign == RFC6979 vector (low-s)", tag);
  R.check(name, sigOk && std::memcmp(rs, expRs, 64) == 0);
  std::snprintf(name, sizeof name, "%s low-s", tag);
  R.check(name, sigOk && is_low_s(c, rs));
  std::snprintf(name, sizeof name, "%s recid == %d", tag, expRecid);
  R.check(name, sigOk && recid == expRecid);
  std::snprintf(name, sizeof name, "%s ecdsa_sign == mbedTLS sign_det + low-s", tag);
  R.check(name, sigOk && mb_sign_det(c, d, dig, mbRs) && std::memcmp(rs, mbRs, 64) == 0);
  std::snprintf(name, sizeof name, "%s ecdsa_verify", tag);
  R.check(name, sigOk && ecdsa_verify(c, pub, dig, rs));
  std::snprintf(name, sizeof name, "%s mbedtls_ecdsa_verify", tag);
  R.check(name, sigOk && mb_verify(c, pub, dig, rs));
  std::snprintf(name, sizeof name, "%s ecdsa_recover", tag);
  R.check(name, sigOk && ecdsa_recover(c, dig, rs, recid, rec) && std::memcmp(rec, pub, 64) == 0);
  const size_t dn = sigOk ? ecdsa_der(rs, der) : 0;
  std::snprintf(name, sizeof name, "%s ecdsa_der parsed by mbedTLS", tag);
  R.check(name, dn >= 8 && dn <= 72 && mb_read_der(c, pub, dig, der, dn));
  uint8_t bad[32];
  std::memcpy(bad, dig, 32);
  bad[31] ^= 1;
  std::snprintf(name, sizeof name, "%s verify rejects a modified digest", tag);
  R.check(name, sigOk && !ecdsa_verify(c, pub, bad, rs) && !mb_verify(c, pub, bad, rs));
  wipe(d, sizeof d);
}

}  // namespace

void trng_fill(uint8_t* p, size_t n) {
  if (!p || !n) return;
  bool radio = false;
#if RIPAR_BLE
  radio = radio || ble_link_radio_alive();
#endif
#if RIPAR_WIFI
  radio = radio || wifi_link_radio_alive();
#endif
  if (radio) {  // RF noise is the entropy source; do not touch the SAR ADC under the radio
    esp_fill_random(p, n);
    return;
  }
  bootloader_random_enable();
  esp_fill_random(p, n);
  bootloader_random_disable();
}

bool derive_keys_from_seed(const uint8_t seed[32], uint8_t k1priv[32], uint8_t p1priv[32]) {
  const bool ok = derive_path(Curve::Secp256k1, seed, 32, PATH_K1, 5, k1priv) &&
                  derive_path(Curve::P256, seed, 32, PATH_P1, 2, p1priv);
  if (!ok) {
    wipe(k1priv, 32);
    wipe(p1priv, 32);
  }
  return ok;
}

bool keys_have_seed() {
  if (g_have) return true;  // loaded by keys_init()/keys_create(); cleared by keys_wipe()
  Preferences prefs;
  if (!prefs.begin(kNs, true)) return false;
  const bool ok = prefs.getBytesLength(kSeedKey) == 32;
  prefs.end();
  return ok;
}

bool keys_init() { return load_public(); }

// Refuses to overwrite an existing seed: call keys_wipe() first for a deliberate reset.
bool keys_create(const uint8_t extra32[32]) {
  if (keys_have_seed()) return false;
  uint8_t pool[64 + 32 + 8];
  trng_fill(pool, 64);
  if (extra32) {
    std::memcpy(pool + 64, extra32, 32);
  } else {
    std::memset(pool + 64, 0, 32);
  }
  const uint64_t t = uint64_t(esp_timer_get_time());  // timing jitter, free extra
  for (int i = 0; i < 8; i++) pool[96 + i] = uint8_t(t >> (8 * i));
  uint8_t seed[32], k1[32], p1[32];
  sha256(pool, sizeof pool, seed);
  wipe(pool, sizeof pool);
  bool ok = derive_keys_from_seed(seed, k1, p1);  // fails with negligible probability (invalid master key)
  wipe(k1, sizeof k1);
  wipe(p1, sizeof p1);
  if (ok) {
    Preferences prefs;
    ok = prefs.begin(kNs, false) && prefs.putBytes(kSeedKey, seed, 32) == 32;
    prefs.end();
  }
  if (ok) {
    uint8_t back[32];
    ok = load_seed(back) && std::memcmp(back, seed, 32) == 0;
    wipe(back, sizeof back);
  }
  wipe(seed, sizeof seed);
  return ok && load_public();
}

// Zeroizes RAM copies and removes the seed from NVS. The seed entry is overwritten with random bytes before it
// is erased, but NVS is log-structured: older copies stay in flash until the page is garbage-collected. A full
// physical erase needs nvs_flash_erase() + reboot (or flash encryption, planned for P1).
void keys_wipe() {
  Preferences prefs;
  if (prefs.begin(kNs, false)) {
    if (prefs.getBytesLength(kSeedKey) > 0) {
      uint8_t junk[32];
      trng_fill(junk, sizeof junk);
      prefs.putBytes(kSeedKey, junk, sizeof junk);
      wipe(junk, sizeof junk);
      prefs.remove(kSeedKey);
    }
    prefs.end();
  }
  g_have = false;
  g_k1addr = Addr();
  wipe(g_k1pub, sizeof g_k1pub);
  wipe(g_p1pub, sizeof g_p1pub);
}

Addr k1_address() { return g_have ? g_k1addr : Addr(); }

void p1_pubkey(uint8_t xy64[64]) {
  if (g_have) {
    std::memcpy(xy64, g_p1pub, 64);
  } else {
    std::memset(xy64, 0, 64);
  }
}

bool k1_sign(const B32& digest, uint8_t rsv65[65]) {
  if (!g_have) return false;
  uint8_t priv[32], rs[64], rec[64];
  int recid = -1;
  bool ok = derive_one(Curve::Secp256k1, priv) && ecdsa_sign(Curve::Secp256k1, priv, digest.v, rs, &recid);
  wipe(priv, sizeof priv);
  ok = ok && (recid == 0 || recid == 1) && is_low_s(Curve::Secp256k1, rs) &&
       ecdsa_verify(Curve::Secp256k1, g_k1pub, digest.v, rs) &&
       ecdsa_recover(Curve::Secp256k1, digest.v, rs, recid, rec) && std::memcmp(rec, g_k1pub, 64) == 0;
  if (ok) {
    std::memcpy(rsv65, rs, 64);
    rsv65[64] = uint8_t(27 + recid);
  }
  return ok;
}

bool p1_sign(const B32& digest, uint8_t rs64[64]) {
  if (!g_have) return false;
  uint8_t priv[32], rs[64];
  int recid = -1;
  bool ok = derive_one(Curve::P256, priv) && ecdsa_sign(Curve::P256, priv, digest.v, rs, &recid);
  wipe(priv, sizeof priv);
  ok = ok && is_low_s(Curve::P256, rs) && ecdsa_verify(Curve::P256, g_p1pub, digest.v, rs);
  if (ok) std::memcpy(rs64, rs, 64);
  return ok;
}

bool p1_sign_der(const B32& digest, Bytes& der) {
  uint8_t rs[64], out[72];
  if (!p1_sign(digest, rs)) return false;
  const size_t n = ecdsa_der(rs, out);
  if (n == 0 || n > sizeof out) return false;
  der.assign(out, out + n);
  return true;
}

bool keys_selftest(std::string& report) {
  report.clear();
  Report R{report};
  uint8_t a[64], b[64];

  // --- hash primitives vs mbedTLS (hardware SHA) ---
  {
    uint8_t msg[300];
    for (size_t i = 0; i < sizeof msg; i++) msg[i] = uint8_t(i * 7 + 3);
    bool ok = true;
    const size_t lens[] = {0, 1, 55, 56, 64, 111, 112, 128, 300};
    for (size_t n : lens) {
      sha256(msg, n, a);
      ok = ok && mbedtls_sha256_ret(msg, n, b, 0) == 0 && std::memcmp(a, b, 32) == 0;
    }
    R.check("sha256 == mbedTLS", ok);
    ok = true;
    for (size_t n : lens) {
      sha512(msg, n, a);
      ok = ok && mbedtls_sha512_ret(msg, n, b, 0) == 0 && std::memcmp(a, b, 64) == 0;
    }
    R.check("sha512 == mbedTLS", ok);
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    hmac_sha512(reinterpret_cast<const uint8_t*>("Bitcoin seed"), 12, msg, 64, a);
    ok = md && mbedtls_md_hmac(md, reinterpret_cast<const uint8_t*>("Bitcoin seed"), 12, msg, 64, b) == 0 &&
         std::memcmp(a, b, 64) == 0;
    hmac_sha512(msg, 200, msg + 5, 150, a);  // key longer than the block
    ok = ok && md && mbedtls_md_hmac(md, msg, 200, msg + 5, 150, b) == 0 && std::memcmp(a, b, 64) == 0;
    R.check("hmac_sha512 == mbedTLS", ok);
  }

  // --- RFC 6979 A.2.5: P-256, SHA-256, message "sample" (s normalised to low-s: n - s) ---
  const uint32_t t0 = millis();
  check_vector(R, "P-256", Curve::P256, "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721", "sample",
               "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
               "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
               "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
               "0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9",
               1);
  // --- secp256k1, priv = 1, message "Satoshi Nakamoto" (RFC 6979 k = 8f8a276c...) ---
  check_vector(R, "secp256k1", Curve::Secp256k1, "0000000000000000000000000000000000000000000000000000000000000001",
               "Satoshi Nakamoto",
               "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
               "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
               "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8"
               "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5",
               1);
  const uint32_t t1 = millis();

  // --- BIP-32 TV1 / SLIP-10 nist256p1 TV1: seed 000102..0f, m/0'/1/2'/2/1000000000 ---
  {
    uint8_t seed16[16], priv[32], exp[32];
    for (int i = 0; i < 16; i++) seed16[i] = uint8_t(i);
    const uint32_t path[5] = {0 + H, 1, 2 + H, 2, 1000000000u};
    bool ok = derive_path(Curve::Secp256k1, seed16, 16, path, 5, priv) &&
              unhex("471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8", exp, 32) &&
              std::memcmp(priv, exp, 32) == 0;
    R.check("BIP-32 TV1 m/0'/1/2'/2/1000000000", ok);
    ok = derive_path(Curve::P256, seed16, 16, path, 5, priv) &&
         unhex("21c4f269ef0a5fd1badf47eeacebeeaa3de22eb8e5b0adcd0f27dd99d34d0119", exp, 32) &&
         std::memcmp(priv, exp, 32) == 0;
    R.check("SLIP-10 P-256 TV1 m/0'/1/2'/2/1000000000", ok);
    wipe(priv, sizeof priv);
  }

  // --- device paths from a fixed seed 00..1f (values from tools/ref_crypto.py + an independent Python ref) ---
  {
    uint8_t seed[32], k1[32], p1[32], exp[32], pub[64], expPub[64];
    for (int i = 0; i < 32; i++) seed[i] = uint8_t(i);
    bool ok = derive_keys_from_seed(seed, k1, p1);
    R.check("derive_keys_from_seed", ok);
    R.check("K1 m/44'/60'/0'/0/0 priv",
            ok && unhex("11407d418c91c6314e009de5a478110ba7e23714289fe8a87941f5773cc38778", exp, 32) &&
                std::memcmp(k1, exp, 32) == 0);
    R.check("P1 m/7951'/0' priv",
            ok && unhex("8c0cf2e758737962f9688403bfc25ef5d52ed648bd34a78e821251080e27edf2", exp, 32) &&
                std::memcmp(p1, exp, 32) == 0);
    Addr want;
    const bool addrOk = ok && ec_pubkey(Curve::Secp256k1, k1, pub) &&
                        unhex("919538116b4f25f1ce01429fd9ed7964556bf565", want.v, 20) && eth_address(pub) == want;
    R.check("K1 address 0x919538116b4F25f1CE01429fd9Ed7964556bf565", addrOk);
    R.check("P1 pubkey",
            ok && ec_pubkey(Curve::P256, p1, pub) &&
                unhex("d9b5652338847e00105256b6f6019a19995559d424e93b1d7dad8f0d26dd8835"
                      "eb352cc0a5b3febc42e2dcf8888c1840aa82c237810c3ee86aa4fbe5f7633f7f",
                      expPub, 64) &&
                std::memcmp(pub, expPub, 64) == 0);
    // signatures with the derived keys vs mbedTLS, over sha256("ripar-selftest")
    uint8_t dig[32], rs[64], mbRs[64];
    sha256_str("ripar-selftest", dig);
    int recid = -1;
    R.check("K1-path sign == mbedTLS", ok && ecdsa_sign(Curve::Secp256k1, k1, dig, rs, &recid) &&
                                           mb_sign_det(Curve::Secp256k1, k1, dig, mbRs) && std::memcmp(rs, mbRs, 64) == 0);
    R.check("P1-path sign == mbedTLS", ok && ecdsa_sign(Curve::P256, p1, dig, rs, &recid) &&
                                           mb_sign_det(Curve::P256, p1, dig, mbRs) && std::memcmp(rs, mbRs, 64) == 0);
    wipe(seed, sizeof seed);
    wipe(k1, sizeof k1);
    wipe(p1, sizeof p1);
  }

  // --- random keys / digests: crypto.h vs mbedTLS both ways ---
  {
    bool ok = true;
    for (int i = 0; i < 4 && ok; i++) {
      const Curve c = (i & 1) ? Curve::P256 : Curve::Secp256k1;
      uint8_t d[32], dig[32], pub[64], mbPub[64], rs[64], mbRs[64];
      int recid = -1;
      esp_fill_random(d, 32);
      esp_fill_random(dig, 32);
      d[0] &= 0x7f;  // < n for both curves
      d[31] |= 1;    // != 0
      ok = ec_pubkey(c, d, pub) && mb_pubkey(c, d, mbPub) && std::memcmp(pub, mbPub, 64) == 0 &&
           ecdsa_sign(c, d, dig, rs, &recid) && mb_sign_det(c, d, dig, mbRs) && std::memcmp(rs, mbRs, 64) == 0 &&
           mb_verify(c, pub, dig, rs);
      wipe(d, sizeof d);
    }
    R.check("random keys: pubkey/sign/verify == mbedTLS (4 rounds)", ok);
  }

  // --- the real device keys, if provisioned ---
  if (g_have) {
    B32 dig;
    sha256_str("ripar-device-selftest", dig.v);
    uint8_t rsv[65], rs[64];
    Bytes der;
    R.check("device K1 sign + mbedTLS verify", k1_sign(dig, rsv) && mb_verify(Curve::Secp256k1, g_k1pub, dig.v, rsv));
    R.check("device P1 sign + mbedTLS verify", p1_sign(dig, rs) && mb_verify(Curve::P256, g_p1pub, dig.v, rs));
    R.check("device P1 DER + mbedTLS parse",
            p1_sign_der(dig, der) && mb_read_der(Curve::P256, g_p1pub, dig.v, der.data(), der.size()));
  } else {
    report += "SKIP device keys (no seed)\n";
  }

  char line[96];
  std::snprintf(line, sizeof line, "time: 2 vectors incl. mbedTLS checks %lu ms\n", static_cast<unsigned long>(t1 - t0));
  report += line;
  std::snprintf(line, sizeof line, "%s (%d failed)\n", R.fails ? "SELFTEST FAIL" : "SELFTEST PASS", R.fails);
  report += line;
  return R.fails == 0;
}

}  // namespace ripar
