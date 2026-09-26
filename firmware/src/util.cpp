// Small portable helpers: U256, hex, short EIP-55 address. Host (g++ -std=c++14) + device.
#include "util.h"

#include "hashes.h"

namespace ripar {

// ================================================================ U256
// Strict: at most 32 bytes (PROTOCOL.md "u256 = big-endian bstr of at most 32 bytes"). Leading zero bytes
// inside those 32 are fine. n > 32 is always rejected, even when the extra leading bytes are zero.
// `out` is only written on success. n == 0 decodes to 0.
bool U256::from_be(const uint8_t* p, size_t n, U256& out) {
  if (n > 32) return false;
  if (n && !p) return false;
  U256 r;
  if (n) std::memcpy(r.v + (32 - n), p, n);
  out = r;
  return true;
}

bool U256::fits_u64() const {
  for (int i = 0; i < 24; i++)
    if (v[i]) return false;
  return true;
}

uint64_t U256::low_u64() const {
  uint64_t x = 0;
  for (int i = 24; i < 32; i++) x = (x << 8) | v[i];
  return x;
}

bool U256::is_zero() const {
  for (int i = 0; i < 32; i++)
    if (v[i]) return false;
  return true;
}

int U256::cmp(const U256& o) const {
  for (int i = 0; i < 32; i++) {
    if (v[i] != o.v[i]) return v[i] < o.v[i] ? -1 : 1;
  }
  return 0;
}

// ================================================================ hex
static const char HEXLC[] = "0123456789abcdef";

std::string to_hex(const uint8_t* p, size_t n, bool prefix0x) {
  std::string s;
  s.reserve(n * 2 + (prefix0x ? 2 : 0));
  if (prefix0x) s += "0x";
  for (size_t i = 0; i < n; i++) {
    s += HEXLC[p[i] >> 4];
    s += HEXLC[p[i] & 0x0F];
  }
  return s;
}

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Accepts an optional "0x"/"0X" prefix, then an even number of hex digits (either case, "" allowed).
// No whitespace. On failure `out` is left unchanged.
bool from_hex(const std::string& s, Bytes& out) {
  size_t i = 0;
  if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) i = 2;
  if ((s.size() - i) & 1) return false;
  Bytes r;
  r.reserve((s.size() - i) / 2);
  for (; i < s.size(); i += 2) {
    int hi = hex_nibble(s[i]), lo = hex_nibble(s[i + 1]);
    if (hi < 0 || lo < 0) return false;
    r.push_back(uint8_t((hi << 4) | lo));
  }
  out.swap(r);
  return true;
}

bool addr_from_hex(const char* s, Addr& out) {
  if (!s || s[0] != '0' || (s[1] != 'x' && s[1] != 'X')) return false;
  Addr a;
  for (int i = 0; i < 20; i++) {
    const char hc = s[2 + 2 * i];
    if (!hc) return false;
    const char lc = s[3 + 2 * i];
    const int hi = hex_nibble(hc), lo = lc ? hex_nibble(lc) : -1;
    if (hi < 0 || lo < 0) return false;
    a.v[i] = uint8_t((hi << 4) | lo);
  }
  if (s[42] != 0) return false;
  out = a;
  return true;
}

// ================================================================ addresses
// EIP-55 mixed-case checksum, 42 chars with "0x". Computed here (keccak of the lower-case hex) so util does not
// depend on abi. abi.cpp's addr_checksum() must give the same string (host tests check both on EIP-55 vectors).
static std::string eip55(const Addr& a) {
  std::string lower = to_hex(a.v, 20, false);
  uint8_t h[32];
  keccak256(reinterpret_cast<const uint8_t*>(lower.data()), lower.size(), h);
  std::string s = "0x";
  s.reserve(42);
  for (size_t i = 0; i < 40; i++) {
    char c = lower[i];
    uint8_t nib = uint8_t((i & 1) ? (h[i / 2] & 0x0F) : (h[i / 2] >> 4));
    if (c >= 'a' && c <= 'f' && nib >= 8) c = char(c - 'a' + 'A');
    s += c;
  }
  return s;
}

// "0x5aAe...eAed": first 4 + last 4 checksummed hex digits, ASCII "..." (the built-in LCD fonts are ASCII-only).
std::string short_addr(const Addr& a) {
  std::string full = eip55(a);
  return full.substr(0, 6) + "..." + full.substr(38, 4);
}

}  // namespace ripar
