// Small portable helpers (compile on host and device).
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace ripar {

using Bytes = std::vector<uint8_t>;

struct Addr {
  uint8_t v[20] = {0};
  bool operator==(const Addr& o) const { return std::memcmp(v, o.v, 20) == 0; }
  bool operator!=(const Addr& o) const { return !(*this == o); }
  bool is_zero() const {
    for (uint8_t b : v)
      if (b) return false;
    return true;
  }
};

struct B32 {
  uint8_t v[32] = {0};
  bool operator==(const B32& o) const { return std::memcmp(v, o.v, 32) == 0; }
};

// 256-bit unsigned integer, big-endian bytes (as in ABI / EIP-712).
struct U256 {
  uint8_t v[32] = {0};
  static U256 from_u64(uint64_t x) {
    U256 r;
    for (int i = 0; i < 8; i++) r.v[31 - i] = uint8_t(x >> (8 * i));
    return r;
  }
  // big-endian byte string of <= 32 bytes (leading zeros optional); false if longer / nonzero overflow
  static bool from_be(const uint8_t* p, size_t n, U256& out);
  bool fits_u64() const;
  uint64_t low_u64() const;
  bool is_zero() const;
  int cmp(const U256& o) const;  // -1 / 0 / 1
};

std::string to_hex(const uint8_t* p, size_t n, bool prefix0x = true);
inline std::string to_hex(const Bytes& b, bool prefix0x = true) { return to_hex(b.data(), b.size(), prefix0x); }
bool from_hex(const std::string& s, Bytes& out);  // accepts optional 0x, even length

// short display form: 0x1234…abcd (EIP-55 checksummed)
std::string short_addr(const Addr& a);

// Strict table address: "0x"/"0X" + exactly 40 hex digits (either case, checksum NOT verified here).
// "" / nullptr / malformed -> false and `out` unchanged (used for the "" placeholders of undeployed contracts).
bool addr_from_hex(const char* s, Addr& out);

}  // namespace ripar
