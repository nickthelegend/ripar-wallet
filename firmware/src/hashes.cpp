// Portable SHA-256, Keccak-256 (legacy Ethereum padding 0x01) and CRC-32 (IEEE / zlib).
// Host (MinGW g++ -std=c++14) + device (ESP32-S3, gnu++17). No dynamic allocation.
// final() writes the digest, wipes the internal state and re-initialises the object, so an instance can be
// reused for a new message (and does not keep key/seed material around in its buffers).
#include "hashes.h"

#include <cstring>

namespace ripar {

namespace {

// memset that the optimiser may not drop (the object is about to be re-initialised or destroyed).
void wipe(void* p, size_t n) {
  volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
  while (n--) *v++ = 0;
}

inline uint32_t rotr32(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
inline uint64_t rotl64(uint64_t x, unsigned n) { return (x << n) | (x >> (64 - n)); }

inline uint32_t load_be32(const uint8_t* p) {
  return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}
inline void store_be32(uint8_t* p, uint32_t x) {
  p[0] = uint8_t(x >> 24);
  p[1] = uint8_t(x >> 16);
  p[2] = uint8_t(x >> 8);
  p[3] = uint8_t(x);
}
inline uint64_t load_le64(const uint8_t* p) {
  uint64_t x = 0;
  for (int i = 7; i >= 0; i--) x = (x << 8) | p[i];
  return x;
}

// ---------------------------------------------------------------- SHA-256 (FIPS 180-4)
const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

const uint32_t SHA256_IV[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

// ---------------------------------------------------------------- Keccak-f[1600]
const uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
const uint8_t KECCAK_ROTC[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
const uint8_t KECCAK_PILN[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

const size_t KECCAK_RATE = 136;  // (1600 - 2*256) / 8

void keccak_f1600(uint64_t st[25]) {
  uint64_t bc[5];
  for (int round = 0; round < 24; round++) {
    // theta
    for (int i = 0; i < 5; i++) bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
    for (int i = 0; i < 5; i++) {
      uint64_t t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
      for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
    }
    // rho + pi
    uint64_t t = st[1];
    for (int i = 0; i < 24; i++) {
      int j = KECCAK_PILN[i];
      uint64_t tmp = st[j];
      st[j] = rotl64(t, KECCAK_ROTC[i]);
      t = tmp;
    }
    // chi
    for (int j = 0; j < 25; j += 5) {
      for (int i = 0; i < 5; i++) bc[i] = st[j + i];
      for (int i = 0; i < 5; i++) st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
    }
    // iota
    st[0] ^= KECCAK_RC[round];
  }
}

// CRC-32 (reflected poly 0xEDB88320), 4-bit table: small flash footprint, fast enough for UR payloads.
const uint32_t CRC32_NIBBLE[16] = {0x00000000, 0x1DB71064, 0x3B6E20C8, 0x26D930AC, 0x76DC4190, 0x6B6B51F4,
                                   0x4DB26158, 0x5005713C, 0xEDB88320, 0xF00F9344, 0xD6D6A3E8, 0xCB61B38C,
                                   0x9B64C2B0, 0x86D3D2D4, 0xA00AE278, 0xBDBDF21C};

}  // namespace

// ================================================================ Sha256
Sha256::Sha256() : bits_(0), n_(0) {
  std::memcpy(h_, SHA256_IV, sizeof(h_));
  std::memset(buf_, 0, sizeof(buf_));
}

void Sha256::block(const uint8_t* p) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++) w[i] = load_be32(p + 4 * i);
  for (int i = 16; i < 64; i++) {
    uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], h = h_[7];
  for (int i = 0; i < 64; i++) {
    uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t t1 = h + S1 + ch + K256[i] + w[i];
    uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = S0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  h_[0] += a;
  h_[1] += b;
  h_[2] += c;
  h_[3] += d;
  h_[4] += e;
  h_[5] += f;
  h_[6] += g;
  h_[7] += h;
  wipe(w, sizeof(w));
}

void Sha256::update(const uint8_t* data, size_t len) {
  if (len == 0) return;
  bits_ += uint64_t(len) << 3;
  if (n_) {
    size_t take = 64 - n_;
    if (take > len) take = len;
    std::memcpy(buf_ + n_, data, take);
    n_ += take;
    data += take;
    len -= take;
    if (n_ < 64) return;
    block(buf_);
    n_ = 0;
  }
  while (len >= 64) {
    block(data);
    data += 64;
    len -= 64;
  }
  if (len) {
    std::memcpy(buf_, data, len);
    n_ = len;
  }
}

void Sha256::final(uint8_t out[32]) {
  const uint64_t bits = bits_;
  buf_[n_++] = 0x80;
  if (n_ > 56) {
    std::memset(buf_ + n_, 0, 64 - n_);
    block(buf_);
    n_ = 0;
  }
  std::memset(buf_ + n_, 0, 56 - n_);
  for (int i = 0; i < 8; i++) buf_[56 + i] = uint8_t(bits >> (56 - 8 * i));
  block(buf_);
  for (int i = 0; i < 8; i++) store_be32(out + 4 * i, h_[i]);
  // wipe + re-init for reuse
  wipe(buf_, sizeof(buf_));
  wipe(h_, sizeof(h_));
  std::memcpy(h_, SHA256_IV, sizeof(h_));
  bits_ = 0;
  n_ = 0;
}

void sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
  Sha256 h;
  h.update(data, len);
  h.final(out);
}

// ================================================================ Keccak256
Keccak256::Keccak256() : pos_(0) { std::memset(st_, 0, sizeof(st_)); }

void Keccak256::update(const uint8_t* data, size_t len) {
  while (len) {
    if ((pos_ & 7) == 0 && len >= 8) {
      // whole lanes (little-endian)
      while (len >= 8 && pos_ < KECCAK_RATE) {
        st_[pos_ >> 3] ^= load_le64(data);
        pos_ += 8;
        data += 8;
        len -= 8;
      }
    } else {
      st_[pos_ >> 3] ^= uint64_t(*data) << (8 * (pos_ & 7));
      pos_++;
      data++;
      len--;
    }
    if (pos_ == KECCAK_RATE) {
      keccak_f1600(st_);
      pos_ = 0;
    }
  }
}

void Keccak256::final(uint8_t out[32]) {
  // legacy Keccak padding: domain byte 0x01 ... 0x80 (NOT the SHA3-256 0x06)
  st_[pos_ >> 3] ^= uint64_t(0x01) << (8 * (pos_ & 7));
  st_[(KECCAK_RATE - 1) >> 3] ^= uint64_t(0x80) << (8 * ((KECCAK_RATE - 1) & 7));
  keccak_f1600(st_);
  for (int i = 0; i < 32; i++) out[i] = uint8_t(st_[i >> 3] >> (8 * (i & 7)));
  wipe(st_, sizeof(st_));
  pos_ = 0;
}

void keccak256(const uint8_t* data, size_t len, uint8_t out[32]) {
  Keccak256 k;
  k.update(data, len);
  k.final(out);
}

// ================================================================ CRC-32
uint32_t crc32(const uint8_t* data, size_t len) {
  uint32_t c = 0xFFFFFFFFu;
  for (size_t i = 0; i < len; i++) {
    c ^= data[i];
    c = (c >> 4) ^ CRC32_NIBBLE[c & 0x0F];
    c = (c >> 4) ^ CRC32_NIBBLE[c & 0x0F];
  }
  return c ^ 0xFFFFFFFFu;
}

}  // namespace ripar
