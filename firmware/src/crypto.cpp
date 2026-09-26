// Portable crypto for Ripar Wallet (include/crypto.h). Host (g++ -std=c++14) + device (gnu++17, Xtensa).
//
//   SHA-512, HMAC-SHA256/512
//   256-bit Montgomery arithmetic (8 x 32-bit limbs, CIOS) used for both field (mod p) and scalar (mod n) math
//   secp256k1 (a = 0) and P-256 (a = -3) in Jacobian coordinates, 4-bit fixed windows; the i*G table
//   (i = 0..15, affine-normalised) is built once per curve on first use and cached in .bss
//   ECDSA: RFC 6979 nonces (HMAC-SHA256, h1 = the 32-byte digest), low-s, recid, verify, recover, strict DER
//   BIP-32 (secp256k1) and SLIP-10 (nist256p1) private derivation
//
// Conventions / deviations (all mirrored by tools/ref_crypto.py):
//   * If a nonce k gives R.x >= n (prob. ~2^-128 on secp256k1, ~2^-64 on P-256) it is rejected like r == 0 and
//     the RFC 6979 loop continues (K = HMAC_K(V||0x00), V = HMAC_K(V)). So recid is always 0/1, never 2/3.
//   * ecdsa_verify accepts high-s too (plain ECDSA). ecdsa_sign only ever emits low-s.
//   * BIP-32 on secp256k1: an invalid master/child key returns false (no retry). SLIP-10 retry on P-256.
//   * NOT constant-time (branches/table lookups depend on secrets). Accepted for the air-gapped prototype.
//   * Secrets held in this file's own locals are wiped; stack left behind by the inner point arithmetic is not.
//   * The per-curve parameter/table cache is initialised lazily without locking: first use must not race
//     (the device calls crypto from one task only).
#include "crypto.h"

#include <cstring>

#include "hashes.h"

namespace ripar {

namespace {

void wipe(void* p, size_t n) {
  volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
  while (n--) *v++ = 0;
}

// ======================================================================== SHA-512 (FIPS 180-4)
const uint64_t K512[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
    0x3956c25bf348b538ull, 0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
    0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
    0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
    0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
    0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull, 0x06ca6351e003826full, 0x142929670a0e6e70ull,
    0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
    0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
    0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
    0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
    0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
    0xca273eceea26619cull, 0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
    0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
    0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull,
};

inline uint64_t rotr64(uint64_t x, unsigned n) { return (x >> n) | (x << (64 - n)); }

inline uint64_t load_be64(const uint8_t* p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
  return v;
}

inline void store_be64(uint8_t* p, uint64_t v) {
  for (int i = 7; i >= 0; i--) {
    p[i] = uint8_t(v);
    v >>= 8;
  }
}

struct Sha512 {
  uint64_t st[8];
  uint64_t total;  // bytes hashed so far (messages < 2^61 bytes)
  uint8_t buf[128];
  size_t n;

  Sha512() { init(); }
  ~Sha512() { wipe(this, sizeof(*this)); }

  void init() {
    static const uint64_t IV[8] = {0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull,
                                   0xa54ff53a5f1d36f1ull, 0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
                                   0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull};
    std::memcpy(st, IV, sizeof(st));
    total = 0;
    n = 0;
  }

  void block(const uint8_t* p) {
    uint64_t w[16];
    for (int i = 0; i < 16; i++) w[i] = load_be64(p + 8 * i);
    uint64_t a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], hh = st[7];
    for (int i = 0; i < 80; i++) {
      uint64_t wi;
      if (i < 16) {
        wi = w[i];
      } else {
        const uint64_t w15 = w[(i - 15) & 15], w2 = w[(i - 2) & 15];
        const uint64_t s0 = rotr64(w15, 1) ^ rotr64(w15, 8) ^ (w15 >> 7);
        const uint64_t s1 = rotr64(w2, 19) ^ rotr64(w2, 61) ^ (w2 >> 6);
        wi = w[i & 15] = w[i & 15] + s0 + w[(i - 7) & 15] + s1;
      }
      const uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
      const uint64_t ch = (e & f) ^ (~e & g);
      const uint64_t t1 = hh + S1 + ch + K512[i] + wi;
      const uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
      const uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
      const uint64_t t2 = S0 + maj;
      hh = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }
    st[0] += a;
    st[1] += b;
    st[2] += c;
    st[3] += d;
    st[4] += e;
    st[5] += f;
    st[6] += g;
    st[7] += hh;
    wipe(w, sizeof(w));
  }

  void update(const uint8_t* data, size_t len) {
    if (!len) return;
    total += len;
    if (n) {
      size_t take = 128 - n;
      if (take > len) take = len;
      std::memcpy(buf + n, data, take);
      n += take;
      data += take;
      len -= take;
      if (n < 128) return;
      block(buf);
      n = 0;
    }
    while (len >= 128) {
      block(data);
      data += 128;
      len -= 128;
    }
    if (len) {
      std::memcpy(buf, data, len);
      n = len;
    }
  }

  void final(uint8_t out[64]) {
    const uint64_t bits = total << 3;
    uint8_t pad[128 + 16];
    std::memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    // pad to 112 mod 128, then the 128-bit big-endian bit length (high 64 bits are 0)
    size_t padlen = (n < 112) ? (112 - n) : (240 - n);
    store_be64(pad + padlen + 8, bits);
    update(pad, padlen + 16);
    for (int i = 0; i < 8; i++) store_be64(out + 8 * i, st[i]);
    init();
  }
};

// ======================================================================== 256-bit integers
struct Big {
  uint32_t w[8];  // little-endian 32-bit limbs
};

const Big BIG_ONE = {{1, 0, 0, 0, 0, 0, 0, 0}};

inline void big_zero(Big& r) { std::memset(r.w, 0, sizeof(r.w)); }

inline bool big_is_zero(const Big& a) {
  uint32_t x = 0;
  for (int i = 0; i < 8; i++) x |= a.w[i];
  return x == 0;
}

inline bool big_eq(const Big& a, const Big& b) { return std::memcmp(a.w, b.w, sizeof(a.w)) == 0; }

int big_cmp(const Big& a, const Big& b) {
  for (int i = 7; i >= 0; i--) {
    if (a.w[i] != b.w[i]) return a.w[i] < b.w[i] ? -1 : 1;
  }
  return 0;
}

uint32_t big_add(Big& r, const Big& a, const Big& b) {
  uint64_t c = 0;
  for (int i = 0; i < 8; i++) {
    c += uint64_t(a.w[i]) + b.w[i];
    r.w[i] = uint32_t(c);
    c >>= 32;
  }
  return uint32_t(c);
}

uint32_t big_sub(Big& r, const Big& a, const Big& b) {
  uint32_t borrow = 0;
  for (int i = 0; i < 8; i++) {
    const uint64_t d = uint64_t(a.w[i]) - b.w[i] - borrow;
    r.w[i] = uint32_t(d);
    borrow = uint32_t(d >> 63);  // 1 if it wrapped
  }
  return borrow;
}

void big_shr1(Big& r, const Big& a) {
  for (int i = 0; i < 8; i++) r.w[i] = (a.w[i] >> 1) | (i < 7 ? (a.w[i + 1] << 31) : 0u);
}

void big_from_be(Big& r, const uint8_t* b) {
  for (int i = 0; i < 8; i++) {
    const uint8_t* p = b + 28 - 4 * i;
    r.w[i] = (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
  }
}

void big_to_be(uint8_t* b, const Big& a) {
  for (int i = 0; i < 8; i++) {
    uint8_t* p = b + 28 - 4 * i;
    p[0] = uint8_t(a.w[i] >> 24);
    p[1] = uint8_t(a.w[i] >> 16);
    p[2] = uint8_t(a.w[i] >> 8);
    p[3] = uint8_t(a.w[i]);
  }
}

// constants only: exactly 64 hex digits
void big_from_hex(Big& r, const char* s) {
  uint8_t b[32];
  for (int i = 0; i < 32; i++) {
    uint8_t v = 0;
    for (int j = 0; j < 2; j++) {
      const char c = s[2 * i + j];
      const uint8_t d = uint8_t(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
      v = uint8_t((v << 4) | d);
    }
    b[i] = v;
  }
  big_from_be(r, b);
}

inline unsigned big_nibble(const Big& k, int i) { return (k.w[i >> 3] >> ((i & 7) * 4)) & 15u; }

// ======================================================================== Montgomery arithmetic mod an odd m > 2^255
struct Mod {
  Big m;
  Big one;      // R mod m (Montgomery form of 1), R = 2^256
  Big r2;       // R^2 mod m
  Big m_minus2; // inversion exponent (m prime)
  uint32_t minv;  // -m^-1 mod 2^32
};

// r = a + b mod m (a, b < m)
void mod_add(Big& r, const Big& a, const Big& b, const Mod& M) {
  const uint32_t c = big_add(r, a, b);
  if (c || big_cmp(r, M.m) >= 0) big_sub(r, r, M.m);
}

// r = a - b mod m (a, b < m)
void mod_sub(Big& r, const Big& a, const Big& b, const Mod& M) {
  if (big_sub(r, a, b)) big_add(r, r, M.m);
}

// r = a * b * R^-1 mod m (a, b < m). CIOS; r may alias a or b.
void mont_mul(Big& r, const Big& a, const Big& b, const Mod& M) {
  uint32_t t[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 8; i++) {
    const uint32_t bi = b.w[i];
    uint64_t c = 0;
    for (int j = 0; j < 8; j++) {
      const uint64_t s = uint64_t(a.w[j]) * bi + t[j] + c;
      t[j] = uint32_t(s);
      c = s >> 32;
    }
    uint64_t s = uint64_t(t[8]) + c;
    t[8] = uint32_t(s);
    t[9] = uint32_t(s >> 32);
    const uint32_t u = t[0] * M.minv;
    s = uint64_t(u) * M.m.w[0] + t[0];
    c = s >> 32;
    for (int j = 1; j < 8; j++) {
      s = uint64_t(u) * M.m.w[j] + t[j] + c;
      t[j - 1] = uint32_t(s);
      c = s >> 32;
    }
    s = uint64_t(t[8]) + c;
    t[7] = uint32_t(s);
    t[8] = t[9] + uint32_t(s >> 32);
  }
  Big res;
  std::memcpy(res.w, t, sizeof(res.w));
  if (t[8] || big_cmp(res, M.m) >= 0) big_sub(res, res, M.m);
  r = res;
}

inline void to_mont(Big& r, const Big& a, const Mod& M) { mont_mul(r, a, M.r2, M); }  // a < m
inline void from_mont(Big& r, const Big& a, const Mod& M) { mont_mul(r, a, BIG_ONE, M); }

// r = a^e (Montgomery domain in and out)
void mont_pow(Big& r, const Big& a, const Big& e, const Mod& M) {
  Big acc = M.one;
  const Big base = a;
  for (int i = 255; i >= 0; i--) {
    mont_mul(acc, acc, acc, M);
    if ((e.w[i >> 5] >> (i & 31)) & 1u) mont_mul(acc, acc, base, M);
  }
  r = acc;
}

// Montgomery-domain inverse (Fermat, m prime); a != 0
inline void mont_inv(Big& r, const Big& a, const Mod& M) { mont_pow(r, a, M.m_minus2, M); }

void mod_setup(Mod& M, const char* hex) {
  big_from_hex(M.m, hex);
  uint32_t inv = 1;  // Newton iteration for m^-1 mod 2^32 (m odd): correct bits double each step
  for (int i = 0; i < 6; i++) inv *= 2u - M.m.w[0] * inv;
  M.minv = 0u - inv;
  Big z;
  big_zero(z);
  big_sub(M.one, z, M.m);  // 2^256 - m == R mod m, since 2^255 < m < 2^256
  M.r2 = M.one;
  for (int i = 0; i < 256; i++) mod_add(M.r2, M.r2, M.r2, M);  // R * 2^256 mod m
  Big two = BIG_ONE;
  two.w[0] = 2;
  big_sub(M.m_minus2, M.m, two);
}

// ======================================================================== curves
struct Jp {
  Big x, y, z;  // Jacobian, Montgomery form mod p; infinity <=> z == 0
};

struct CurveParams {
  Mod p, n;
  bool a_minus3;  // P-256: a = -3; secp256k1: a = 0
  Big b;          // Montgomery form
  Big sqrt_exp;   // (p + 1) / 4  (p = 3 mod 4 on both curves)
  Big n_half;     // (n - 1) / 2: s is "low" iff s <= n_half
  Jp gtab[16];    // i*G, i = 0..15; entries 1..15 affine-normalised (z = Montgomery 1)
};

inline void jset_inf(Jp& r) {
  big_zero(r.x);
  big_zero(r.y);
  big_zero(r.z);
}
inline bool jis_inf(const Jp& p) { return big_is_zero(p.z); }

// r = 2p; r may alias p
void jdbl(const CurveParams& C, Jp& r, const Jp& p) {
  if (jis_inf(p) || big_is_zero(p.y)) {
    jset_inf(r);
    return;
  }
  const Mod& F = C.p;
  Big yy, s, m, t1, t2, z3;
  mont_mul(yy, p.y, p.y, F);  // Y^2
  mont_mul(s, p.x, yy, F);    // S = 4 X Y^2
  mod_add(s, s, s, F);
  mod_add(s, s, s, F);
  if (C.a_minus3) {  // M = 3 (X - Z^2)(X + Z^2)
    mont_mul(t1, p.z, p.z, F);
    mod_sub(t2, p.x, t1, F);
    mod_add(t1, p.x, t1, F);
    mont_mul(m, t1, t2, F);
  } else {  // M = 3 X^2
    mont_mul(m, p.x, p.x, F);
  }
  mod_add(t1, m, m, F);
  mod_add(m, t1, m, F);
  mont_mul(z3, p.y, p.z, F);  // Z3 = 2 Y Z
  mod_add(z3, z3, z3, F);
  mont_mul(t1, m, m, F);  // X3 = M^2 - 2 S
  mod_sub(t1, t1, s, F);
  mod_sub(t1, t1, s, F);
  mod_sub(t2, s, t1, F);  // Y3 = M (S - X3) - 8 Y^4
  mont_mul(t2, m, t2, F);
  mont_mul(yy, yy, yy, F);
  mod_add(yy, yy, yy, F);
  mod_add(yy, yy, yy, F);
  mod_add(yy, yy, yy, F);
  mod_sub(t2, t2, yy, F);
  r.x = t1;
  r.y = t2;
  r.z = z3;
}

// r = p + q; r may alias p or q. Fast path when q is affine-normalised (q.z == Montgomery 1).
void jadd(const CurveParams& C, Jp& r, const Jp& p, const Jp& q) {
  if (jis_inf(p)) {
    r = q;
    return;
  }
  if (jis_inf(q)) {
    r = p;
    return;
  }
  const Mod& F = C.p;
  const bool q_affine = big_eq(q.z, F.one);
  Big z1z1, u1, u2, s1, s2, t;
  mont_mul(z1z1, p.z, p.z, F);
  if (q_affine) {
    u1 = p.x;
    s1 = p.y;
  } else {
    Big z2z2;
    mont_mul(z2z2, q.z, q.z, F);
    mont_mul(u1, p.x, z2z2, F);
    mont_mul(s1, p.y, q.z, F);
    mont_mul(s1, s1, z2z2, F);
  }
  mont_mul(u2, q.x, z1z1, F);
  mont_mul(s2, q.y, p.z, F);
  mont_mul(s2, s2, z1z1, F);
  if (big_eq(u1, u2)) {
    if (big_eq(s1, s2)) {
      jdbl(C, r, p);
    } else {
      jset_inf(r);
    }
    return;
  }
  Big hh, rr, h2, h3, v, x3, y3, z3;
  mod_sub(hh, u2, u1, F);  // H
  mod_sub(rr, s2, s1, F);  // R
  mont_mul(h2, hh, hh, F);
  mont_mul(h3, h2, hh, F);
  mont_mul(v, u1, h2, F);
  mont_mul(x3, rr, rr, F);  // X3 = R^2 - H^3 - 2 U1 H^2
  mod_sub(x3, x3, h3, F);
  mod_sub(x3, x3, v, F);
  mod_sub(x3, x3, v, F);
  mod_sub(t, v, x3, F);  // Y3 = R (U1 H^2 - X3) - S1 H^3
  mont_mul(y3, rr, t, F);
  mont_mul(t, s1, h3, F);
  mod_sub(y3, y3, t, F);
  if (q_affine) {  // Z3 = H Z1 Z2
    mont_mul(z3, p.z, hh, F);
  } else {
    mont_mul(z3, p.z, q.z, F);
    mont_mul(z3, z3, hh, F);
  }
  r.x = x3;
  r.y = y3;
  r.z = z3;
}

// affine (x, y) in plain (non-Montgomery) form; false for infinity
bool jaffine(const CurveParams& C, const Jp& P, Big& x, Big& y) {
  if (jis_inf(P)) return false;
  const Mod& F = C.p;
  Big zi, zi2, t;
  mont_inv(zi, P.z, F);
  mont_mul(zi2, zi, zi, F);
  mont_mul(t, P.x, zi2, F);
  from_mont(x, t, F);
  mont_mul(zi2, zi2, zi, F);
  mont_mul(t, P.y, zi2, F);
  from_mont(y, t, F);
  return true;
}

// y^2 == x^3 + a x + b for Montgomery-form x, y
bool on_curve_m(const CurveParams& C, const Big& xm, const Big& ym) {
  const Mod& F = C.p;
  Big lhs, rhs, t;
  mont_mul(lhs, ym, ym, F);
  mont_mul(t, xm, xm, F);
  mont_mul(rhs, t, xm, F);
  if (C.a_minus3) {
    mod_sub(rhs, rhs, xm, F);
    mod_sub(rhs, rhs, xm, F);
    mod_sub(rhs, rhs, xm, F);
  }
  mod_add(rhs, rhs, C.b, F);
  return big_eq(lhs, rhs);
}

// tab[i] = i*P, i = 0..15
void build_table(const CurveParams& C, Jp tab[16], const Jp& P) {
  jset_inf(tab[0]);
  tab[1] = P;
  for (int i = 2; i < 16; i++) {
    if (i & 1)
      jadd(C, tab[i], tab[i - 1], P);
    else
      jdbl(C, tab[i], tab[i / 2]);
  }
}

// r = k1*G + k2*P (either scalar may be null). Scalars are plain integers (< 2^256). ptab = build_table(P).
void jmul2(const CurveParams& C, Jp& r, const Big* k1, const Big* k2, const Jp* ptab) {
  Jp acc;
  jset_inf(acc);
  for (int i = 63; i >= 0; i--) {
    if (!jis_inf(acc))
      for (int d = 0; d < 4; d++) jdbl(C, acc, acc);
    if (k1) {
      const unsigned v = big_nibble(*k1, i);
      if (v) jadd(C, acc, acc, C.gtab[v]);
    }
    if (k2) {
      const unsigned v = big_nibble(*k2, i);
      if (v) jadd(C, acc, acc, ptab[v]);
    }
  }
  r = acc;
  wipe(&acc, sizeof(acc));
}

void curve_setup(CurveParams& C, Curve c) {
  const char *p, *n, *b, *gx, *gy;
  if (c == Curve::P256) {  // FIPS 186-4 D.1.2.3
    p = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
    n = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    b = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
    gx = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    gy = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
    C.a_minus3 = true;
  } else {  // SEC 2 2.4.1
    p = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
    n = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
    b = "0000000000000000000000000000000000000000000000000000000000000007";
    gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    C.a_minus3 = false;
  }
  mod_setup(C.p, p);
  mod_setup(C.n, n);
  Big t;
  big_from_hex(t, b);
  to_mont(C.b, t, C.p);
  big_add(t, C.p.m, BIG_ONE);  // p + 1 (no overflow: p < 2^256 - 1)
  big_shr1(t, t);
  big_shr1(C.sqrt_exp, t);
  big_shr1(C.n_half, C.n.m);
  Jp g;
  big_from_hex(t, gx);
  to_mont(g.x, t, C.p);
  big_from_hex(t, gy);
  to_mont(g.y, t, C.p);
  g.z = C.p.one;
  build_table(C, C.gtab, g);
  for (int i = 2; i < 16; i++) {  // normalise to z = 1 so jadd can take the mixed-addition fast path
    Big x, y;
    jaffine(C, C.gtab[i], x, y);
    to_mont(C.gtab[i].x, x, C.p);
    to_mont(C.gtab[i].y, y, C.p);
    C.gtab[i].z = C.p.one;
  }
}

const CurveParams& params(Curve c) {
  static CurveParams cp[2];
  static bool ready[2] = {false, false};
  const int i = (c == Curve::P256) ? 1 : 0;
  if (!ready[i]) {
    curve_setup(cp[i], c);
    ready[i] = true;
  }
  return cp[i];
}

// 1 <= v < n
inline bool scalar_ok(const CurveParams& C, const Big& v) { return !big_is_zero(v) && big_cmp(v, C.n.m) < 0; }

// plain (x, y) -> Montgomery Jacobian point, checking range and curve equation
bool load_point(const CurveParams& C, const uint8_t xy64[64], Jp& P) {
  Big x, y;
  big_from_be(x, xy64);
  big_from_be(y, xy64 + 32);
  if (big_cmp(x, C.p.m) >= 0 || big_cmp(y, C.p.m) >= 0) return false;
  to_mont(P.x, x, C.p);
  to_mont(P.y, y, C.p);
  P.z = C.p.one;
  return on_curve_m(C, P.x, P.y);
}

// public key of a valid scalar d, as plain affine
bool pub_of(const CurveParams& C, const Big& d, Big& x, Big& y) {
  if (!scalar_ok(C, d)) return false;
  Jp P;
  jmul2(C, P, &d, nullptr, nullptr);
  const bool ok = jaffine(C, P, x, y);
  wipe(&P, sizeof(P));
  return ok;
}

// ======================================================================== RFC 6979 HMAC-DRBG (HMAC-SHA256, qlen = 256)
struct Rfc6979 {
  uint8_t K[32];
  uint8_t V[32];

  // x = int2octets(priv), h1 = bits2octets(digest) (digest already reduced mod n)
  Rfc6979(const uint8_t x[32], const uint8_t h1[32]) {
    uint8_t buf[32 + 1 + 32 + 32];
    std::memset(K, 0x00, 32);
    std::memset(V, 0x01, 32);
    for (int round = 0; round < 2; round++) {
      std::memcpy(buf, V, 32);
      buf[32] = uint8_t(round);  // step d: 0x00, step f: 0x01
      std::memcpy(buf + 33, x, 32);
      std::memcpy(buf + 65, h1, 32);
      hmac_sha256(K, 32, buf, sizeof(buf), K);
      hmac_sha256(K, 32, V, 32, V);
    }
    wipe(buf, sizeof(buf));
  }
  ~Rfc6979() {
    wipe(K, sizeof(K));
    wipe(V, sizeof(V));
  }
  // step h: next candidate T (qlen = hlen = 256 -> one HMAC block)
  void generate(uint8_t T[32]) {
    hmac_sha256(K, 32, V, 32, V);
    std::memcpy(T, V, 32);
  }
  // candidate rejected: K = HMAC_K(V || 0x00), V = HMAC_K(V)
  void reject() {
    uint8_t buf[33];
    std::memcpy(buf, V, 32);
    buf[32] = 0x00;
    hmac_sha256(K, 32, buf, sizeof(buf), K);
    hmac_sha256(K, 32, V, 32, V);
    wipe(buf, sizeof(buf));
  }
};

// digest -> z = bits2int(digest) mod n
void digest_to_z(const CurveParams& C, const uint8_t digest[32], Big& z) {
  big_from_be(z, digest);
  if (big_cmp(z, C.n.m) >= 0) big_sub(z, z, C.n.m);  // z < 2^256 < 2n
}

bool sign_impl(Curve c, const uint8_t priv[32], const uint8_t digest[32], bool low_s, uint8_t rs[64], int* recid,
               uint8_t* k_out) {
  if (!priv || !digest || !rs) return false;
  const CurveParams& C = params(c);
  const Mod& N = C.n;
  Big d;
  big_from_be(d, priv);
  if (!scalar_ok(C, d)) {
    wipe(&d, sizeof(d));
    return false;
  }
  Big z;
  digest_to_z(C, digest, z);
  uint8_t h1[32];
  big_to_be(h1, z);
  Rfc6979 drbg(priv, h1);
  Big dm, zm;
  to_mont(dm, d, N);
  to_mont(zm, z, N);
  wipe(&d, sizeof(d));

  bool ok = false;
  uint8_t kb[32];
  Big k, km, kinv, rx, ry, rm, s;
  // Each rejection has probability <= ~2^-64; the bound only makes the loop provably finite.
  for (int attempt = 0; attempt < 64 && !ok; attempt++) {
    drbg.generate(kb);
    big_from_be(k, kb);
    if (scalar_ok(C, k)) {
      Jp R;
      jmul2(C, R, &k, nullptr, nullptr);
      const bool fin = jaffine(C, R, rx, ry);
      wipe(&R, sizeof(R));
      if (fin && !big_is_zero(rx) && big_cmp(rx, N.m) < 0) {  // R.x >= n: rejected (keeps recid in {0,1})
        to_mont(km, k, N);
        mont_inv(kinv, km, N);
        to_mont(rm, rx, N);
        mont_mul(s, rm, dm, N);  // s = k^-1 (z + r d)
        mod_add(s, s, zm, N);
        mont_mul(s, s, kinv, N);
        from_mont(s, s, N);
        if (!big_is_zero(s)) {
          int rid = int(ry.w[0] & 1u);
          if (low_s && big_cmp(s, C.n_half) > 0) {
            big_sub(s, N.m, s);
            rid ^= 1;
          }
          big_to_be(rs, rx);
          big_to_be(rs + 32, s);
          if (recid) *recid = rid;
          if (k_out) big_to_be(k_out, k);
          ok = true;
          break;
        }
      }
    }
    drbg.reject();
  }
  wipe(kb, sizeof(kb));
  wipe(&k, sizeof(k));
  wipe(&km, sizeof(km));
  wipe(&kinv, sizeof(kinv));
  wipe(&dm, sizeof(dm));
  wipe(&ry, sizeof(ry));
  wipe(&s, sizeof(s));
  return ok;
}

void compress_pub(const Big& x, const Big& y, uint8_t out[33]) {
  out[0] = uint8_t(0x02 | (y.w[0] & 1u));
  big_to_be(out + 1, x);
}

inline void ser32(uint8_t* p, uint32_t v) {
  p[0] = uint8_t(v >> 24);
  p[1] = uint8_t(v >> 16);
  p[2] = uint8_t(v >> 8);
  p[3] = uint8_t(v);
}

}  // namespace

// ======================================================================== public API
void sha512(const uint8_t* data, size_t len, uint8_t out[64]) {
  Sha512 h;
  h.update(data, len);
  h.final(out);
}

// out may alias key or msg
void hmac_sha256(const uint8_t* key, size_t klen, const uint8_t* msg, size_t mlen, uint8_t out[32]) {
  uint8_t k0[64], pad[64], inner[32];
  std::memset(k0, 0, sizeof(k0));
  if (klen > 64)
    sha256(key, klen, k0);
  else if (klen)
    std::memcpy(k0, key, klen);
  for (int i = 0; i < 64; i++) pad[i] = uint8_t(k0[i] ^ 0x36);
  Sha256 h;
  h.update(pad, 64);
  h.update(msg, mlen);
  h.final(inner);
  for (int i = 0; i < 64; i++) pad[i] = uint8_t(k0[i] ^ 0x5c);
  h.update(pad, 64);
  h.update(inner, 32);
  h.final(out);
  wipe(k0, sizeof(k0));
  wipe(pad, sizeof(pad));
  wipe(inner, sizeof(inner));
}

// out may alias key or msg
void hmac_sha512(const uint8_t* key, size_t klen, const uint8_t* msg, size_t mlen, uint8_t out[64]) {
  uint8_t k0[128], pad[128], inner[64];
  std::memset(k0, 0, sizeof(k0));
  if (klen > 128)
    sha512(key, klen, k0);
  else if (klen)
    std::memcpy(k0, key, klen);
  for (int i = 0; i < 128; i++) pad[i] = uint8_t(k0[i] ^ 0x36);
  Sha512 h;
  h.update(pad, 128);
  h.update(msg, mlen);
  h.final(inner);
  for (int i = 0; i < 128; i++) pad[i] = uint8_t(k0[i] ^ 0x5c);
  h.update(pad, 128);
  h.update(inner, 64);
  h.final(out);
  wipe(k0, sizeof(k0));
  wipe(pad, sizeof(pad));
  wipe(inner, sizeof(inner));
}

bool ec_pubkey(Curve c, const uint8_t priv[32], uint8_t xy64[64]) {
  if (!priv || !xy64) return false;
  const CurveParams& C = params(c);
  Big d, x, y;
  big_from_be(d, priv);
  const bool ok = pub_of(C, d, x, y);
  wipe(&d, sizeof(d));
  if (!ok) return false;
  big_to_be(xy64, x);
  big_to_be(xy64 + 32, y);
  return true;
}

bool ecdsa_sign(Curve c, const uint8_t priv[32], const uint8_t digest[32], uint8_t rs[64], int* recid) {
  return sign_impl(c, priv, digest, true, rs, recid, nullptr);
}

bool ecdsa_verify(Curve c, const uint8_t xy64[64], const uint8_t digest[32], const uint8_t rs[64]) {
  if (!xy64 || !digest || !rs) return false;
  const CurveParams& C = params(c);
  const Mod& N = C.n;
  Jp Q;
  if (!load_point(C, xy64, Q)) return false;
  Big r, s, z;
  big_from_be(r, rs);
  big_from_be(s, rs + 32);
  if (!scalar_ok(C, r) || !scalar_ok(C, s)) return false;
  digest_to_z(C, digest, z);
  Big w, t, u1, u2;
  to_mont(t, s, N);
  mont_inv(w, t, N);  // s^-1
  to_mont(t, z, N);
  mont_mul(u1, t, w, N);
  from_mont(u1, u1, N);  // z / s
  to_mont(t, r, N);
  mont_mul(u2, t, w, N);
  from_mont(u2, u2, N);  // r / s
  Jp tab[16];
  build_table(C, tab, Q);
  Jp X;
  jmul2(C, X, &u1, &u2, tab);
  Big x, y;
  if (!jaffine(C, X, x, y)) return false;
  if (big_cmp(x, N.m) >= 0) big_sub(x, x, N.m);
  return big_eq(x, r);
}

bool ecdsa_recover(Curve c, const uint8_t digest[32], const uint8_t rs[64], int recid, uint8_t xy64[64]) {
  if (!digest || !rs || !xy64) return false;
  if (recid != 0 && recid != 1) return false;  // 2/3 (R.x >= n) never produced by ecdsa_sign
  const CurveParams& C = params(c);
  const Mod& F = C.p;
  const Mod& N = C.n;
  Big r, s, z;
  big_from_be(r, rs);
  big_from_be(s, rs + 32);
  if (!scalar_ok(C, r) || !scalar_ok(C, s)) return false;
  // R = (r, y) with y parity = recid; r < n < p
  Jp R;
  Big rhs, t, yp;
  to_mont(R.x, r, F);
  mont_mul(t, R.x, R.x, F);
  mont_mul(rhs, t, R.x, F);
  if (C.a_minus3) {
    mod_sub(rhs, rhs, R.x, F);
    mod_sub(rhs, rhs, R.x, F);
    mod_sub(rhs, rhs, R.x, F);
  }
  mod_add(rhs, rhs, C.b, F);
  mont_pow(R.y, rhs, C.sqrt_exp, F);
  mont_mul(t, R.y, R.y, F);
  if (!big_eq(t, rhs)) return false;  // r is not the x of a curve point
  from_mont(yp, R.y, F);
  if (int(yp.w[0] & 1u) != recid) {
    if (big_is_zero(yp)) return false;
    big_sub(yp, F.m, yp);
    to_mont(R.y, yp, F);
  }
  R.z = F.one;
  // Q = r^-1 (s R - z G)
  digest_to_z(C, digest, z);
  Big rinv, u1, u2;
  to_mont(t, r, N);
  mont_inv(rinv, t, N);
  if (!big_is_zero(z)) big_sub(z, N.m, z);  // -z mod n
  to_mont(t, z, N);
  mont_mul(u1, t, rinv, N);
  from_mont(u1, u1, N);
  to_mont(t, s, N);
  mont_mul(u2, t, rinv, N);
  from_mont(u2, u2, N);
  Jp tab[16];
  build_table(C, tab, R);
  Jp Q;
  jmul2(C, Q, &u1, &u2, tab);
  Big x, y;
  if (!jaffine(C, Q, x, y)) return false;
  big_to_be(xy64, x);
  big_to_be(xy64 + 32, y);
  return true;
}

size_t ecdsa_der(const uint8_t rs[64], uint8_t out[72]) {
  uint8_t tmp[72];
  size_t n = 2;
  for (int part = 0; part < 2; part++) {
    const uint8_t* v = rs + 32 * part;
    size_t i = 0;
    while (i < 31 && v[i] == 0) i++;  // minimal: strip leading zeros, keep at least one byte
    const size_t len = 32 - i;
    const bool pad = (v[i] & 0x80) != 0;  // keep INTEGER positive
    tmp[n++] = 0x02;
    tmp[n++] = uint8_t(len + (pad ? 1 : 0));
    if (pad) tmp[n++] = 0x00;
    std::memcpy(tmp + n, v + i, len);
    n += len;
  }
  tmp[0] = 0x30;
  tmp[1] = uint8_t(n - 2);  // <= 70: short-form length
  std::memcpy(out, tmp, n);
  return n;
}

bool bip32_master(Curve c, const uint8_t* seed, size_t n, ExtKey& out) {
  if (!seed && n) return false;
  const CurveParams& C = params(c);
  const char* skey = (c == Curve::P256) ? "Nist256p1 seed" : "Bitcoin seed";
  const size_t sklen = std::strlen(skey);
  const uint8_t* kp = reinterpret_cast<const uint8_t*>(skey);
  uint8_t I[64];
  hmac_sha512(kp, sklen, seed, n, I);
  bool ok = false;
  for (int attempt = 0; attempt < 256; attempt++) {
    Big il;
    big_from_be(il, I);
    const bool valid = scalar_ok(C, il);
    wipe(&il, sizeof(il));
    if (valid) {
      std::memcpy(out.key, I, 32);
      std::memcpy(out.chain, I + 32, 32);
      ok = true;
      break;
    }
    if (c == Curve::Secp256k1) break;   // BIP-32: invalid master key
    hmac_sha512(kp, sklen, I, 64, I);   // SLIP-10: S := I, restart
  }
  wipe(I, sizeof(I));
  return ok;
}

bool bip32_ckd_priv(Curve c, const ExtKey& parent, uint32_t index, ExtKey& child) {
  const CurveParams& C = params(c);
  const Mod& N = C.n;
  Big kpar;
  big_from_be(kpar, parent.key);
  if (!scalar_ok(C, kpar)) {
    wipe(&kpar, sizeof(kpar));
    return false;
  }
  uint8_t cpar[32];
  std::memcpy(cpar, parent.chain, 32);  // child may alias parent
  uint8_t data[37];
  if (index & H) {  // hardened: 0x00 || ser256(kpar) || ser32(i)
    data[0] = 0x00;
    std::memcpy(data + 1, parent.key, 32);
  } else {  // normal: serP(point(kpar)) || ser32(i)
    Big x, y;
    if (!pub_of(C, kpar, x, y)) {
      wipe(&kpar, sizeof(kpar));
      return false;
    }
    compress_pub(x, y, data);
  }
  ser32(data + 33, index);
  uint8_t I[64];
  hmac_sha512(cpar, 32, data, sizeof(data), I);
  bool ok = false;
  for (int attempt = 0; attempt < 256; attempt++) {
    Big il, ki;
    big_from_be(il, I);
    if (big_cmp(il, N.m) < 0) {
      mod_add(ki, il, kpar, N);  // plain addition mod n (both < n)
      if (!big_is_zero(ki)) {
        big_to_be(child.key, ki);
        std::memcpy(child.chain, I + 32, 32);
        ok = true;
      }
      wipe(&ki, sizeof(ki));
    }
    wipe(&il, sizeof(il));
    if (ok || c == Curve::Secp256k1) break;  // BIP-32: invalid child -> caller moves to the next index
    // SLIP-10: I = HMAC-SHA512(cpar, 0x01 || IR || ser32(i))
    data[0] = 0x01;
    std::memcpy(data + 1, I + 32, 32);
    ser32(data + 33, index);
    hmac_sha512(cpar, 32, data, sizeof(data), I);
  }
  wipe(&kpar, sizeof(kpar));
  wipe(data, sizeof(data));
  wipe(I, sizeof(I));
  wipe(cpar, sizeof(cpar));
  return ok;
}

bool derive_path(Curve c, const uint8_t* seed, size_t n, const uint32_t* path, size_t depth, uint8_t priv[32]) {
  if (!priv || (!path && depth)) return false;
  ExtKey k;
  bool ok = bip32_master(c, seed, n, k);
  for (size_t i = 0; ok && i < depth; i++) ok = bip32_ckd_priv(c, k, path[i], k);
  if (ok) std::memcpy(priv, k.key, 32);
  wipe(&k, sizeof(k));
  return ok;
}

Addr eth_address(const uint8_t xy64[64]) {
  uint8_t hsh[32];
  keccak256(xy64, 64, hsh);
  Addr a;
  std::memcpy(a.v, hsh + 12, 20);
  return a;
}

const uint32_t PATH_K1[5] = {44 | H, 60 | H, 0 | H, 0, 0};
const uint32_t PATH_P1[2] = {7951 | H, 0 | H};

#if defined(RIPAR_HOST_TEST)
// Test hooks, host builds only (declared by test/host/test_crypto.cpp, not part of crypto.h): raw RFC 6979 ECDSA
// without low-s normalisation, also returning the nonce k, for checking the RFC 6979 A.2.5 vectors verbatim.
namespace crypto_test {
bool ecdsa_sign_raw(Curve c, const uint8_t priv[32], const uint8_t digest[32], uint8_t rs[64], int* recid,
                    uint8_t k_out[32]) {
  return sign_impl(c, priv, digest, false, rs, recid, k_out);
}
// The index-th raw RFC 6979 candidate T (index rejections applied first). Real rejections are too rare to hit
// with test data (k >= n: ~2^-32 on P-256), so this is how the reject step is tested.
bool rfc6979_candidate(Curve c, const uint8_t priv[32], const uint8_t digest[32], unsigned index, uint8_t k[32]) {
  const CurveParams& C = params(c);
  Big d, z;
  big_from_be(d, priv);
  if (!scalar_ok(C, d)) return false;
  digest_to_z(C, digest, z);
  uint8_t h1[32];
  big_to_be(h1, z);
  Rfc6979 drbg(priv, h1);
  for (unsigned i = 0;; i++) {
    drbg.generate(k);
    if (i == index) return true;
    drbg.reject();
  }
}
}  // namespace crypto_test
#endif

}  // namespace ripar
