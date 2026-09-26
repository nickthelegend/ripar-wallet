// ERC-20 calldata decoding + human formatting (amounts, EIP-55, address fingerprint). Host (g++ -std=c++14) + device.
#include "abi.h"

#include <cstring>

#include "hashes.h"

namespace ripar {

namespace {

const uint32_t SEL_TRANSFER = 0xa9059cbbu;       // transfer(address,uint256)
const uint32_t SEL_APPROVE = 0x095ea7b3u;        // approve(address,uint256)
const uint32_t SEL_TRANSFER_FROM = 0x23b872ddu;  // transferFrom(address,address,uint256)

// ABI address word: 12 zero bytes then the 20-byte address. Dirty high bytes -> reject (strict).
bool read_addr_word(const uint8_t* w, Addr& out) {
  for (int i = 0; i < 12; i++)
    if (w[i]) return false;
  std::memcpy(out.v, w + 12, 20);
  return true;
}

// Decimal digits of v, most significant first, no leading zeros ("0" for zero). At most 78 digits.
std::string u256_decimal(const U256& v) {
  uint8_t n[32];
  std::memcpy(n, v.v, 32);
  char rev[80];
  size_t len = 0;
  size_t first = 0;  // index of the first non-zero byte of n (the quotient shrinks as we divide)
  for (;;) {
    while (first < 32 && n[first] == 0) first++;
    uint32_t rem = 0;
    for (size_t i = first; i < 32; i++) {
      uint32_t cur = (rem << 8) | n[i];
      n[i] = uint8_t(cur / 10u);
      rem = cur % 10u;
    }
    rev[len++] = char('0' + rem);
    bool more = false;
    for (size_t i = first; i < 32; i++)
      if (n[i]) {
        more = true;
        break;
      }
    if (!more || len >= sizeof(rev)) break;
  }
  std::string s;
  s.reserve(len);
  while (len) s += rev[--len];
  return s;
}

// "1234567" -> "1,234,567"
std::string group_thousands(const std::string& digits) {
  std::string s;
  size_t n = digits.size();
  s.reserve(n + n / 3);
  for (size_t i = 0; i < n; i++) {
    if (i && (n - i) % 3 == 0) s += ',';
    s += digits[i];
  }
  return s;
}

}  // namespace

// Strict ERC-20 decoding. Empty calldata -> None (plain native transfer). Anything that is not exactly one of
// the three known calls with the exact length and clean address words -> Unknown (from/to/amount left zero;
// selector filled in when there are at least 4 bytes). The caller must refuse to meter an Unknown call.
Erc20Call abi_decode_erc20(const Bytes& calldata) {
  Erc20Call r;
  if (calldata.empty()) return r;  // None
  r.kind = Erc20Call::Unknown;
  if (calldata.size() < 4) return r;
  const uint8_t* p = calldata.data();
  r.selector = (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);

  Erc20Call::Kind kind;
  size_t words;
  switch (r.selector) {
    case SEL_TRANSFER:
      kind = Erc20Call::Transfer;
      words = 2;
      break;
    case SEL_APPROVE:
      kind = Erc20Call::Approve;
      words = 2;
      break;
    case SEL_TRANSFER_FROM:
      kind = Erc20Call::TransferFrom;
      words = 3;
      break;
    default:
      return r;
  }
  if (calldata.size() != 4 + 32 * words) return r;

  const uint8_t* w = p + 4;
  Addr from, to;
  if (kind == Erc20Call::TransferFrom) {
    if (!read_addr_word(w, from)) return r;
    w += 32;
  }
  if (!read_addr_word(w, to)) return r;
  w += 32;
  U256 amount;
  std::memcpy(amount.v, w, 32);

  r.kind = kind;
  r.from = from;
  r.to = to;
  r.amount = amount;
  return r;
}

// EIP-55: hex digit i is upper-cased when nibble i of keccak256(lower-case hex, 40 ASCII chars) is >= 8.
std::string addr_checksum(const Addr& a) {
  static const char HEXLC[] = "0123456789abcdef";
  char lower[40];
  for (int i = 0; i < 20; i++) {
    lower[2 * i] = HEXLC[a.v[i] >> 4];
    lower[2 * i + 1] = HEXLC[a.v[i] & 0x0F];
  }
  uint8_t h[32];
  keccak256(reinterpret_cast<const uint8_t*>(lower), 40, h);
  std::string s = "0x";
  s.reserve(42);
  for (int i = 0; i < 40; i++) {
    char c = lower[i];
    uint8_t nib = uint8_t((i & 1) ? (h[i / 2] & 0x0F) : (h[i / 2] >> 4));
    if (c >= 'a' && nib >= 8) c = char(c - 'a' + 'A');
    s += c;
  }
  return s;
}

// value / 10^decimals in decimal, integer part with ',' every 3 digits, at most maxFrac fraction digits.
//   - exact values: trailing fraction zeros are trimmed ("12.5", "1,234", "0.000001").
//   - if non-zero digits beyond maxFrac are cut off, the result is truncated toward zero, keeps all maxFrac
//     digits and ends with "..." ("0.000000..." for 1e-7, "1.234567..." for 1.2345678) - never rounded up and
//     never silently shown as an exact smaller number. ASCII "..." because the LCD fonts are ASCII-only.
// decimals < 0 is treated as 0, maxFrac < 0 as 0. Any decimals value works without large allocations.
std::string format_units(const U256& v, int decimals, int maxFrac) {
  if (decimals < 0) decimals = 0;
  if (maxFrac < 0) maxFrac = 0;
  const std::string D = u256_decimal(v);
  const size_t L = D.size();
  const size_t dec = size_t(decimals);

  // integer part = D[0 .. L-dec), fraction = (dec-L) zeros then D[fstart .. L)
  const size_t fstart = L > dec ? L - dec : 0;
  const size_t lead = dec > L ? dec - L : 0;
  std::string out = group_thousands(fstart ? D.substr(0, fstart) : std::string("0"));

  const size_t keep = size_t(maxFrac) < dec ? size_t(maxFrac) : dec;
  std::string frac;
  frac.reserve(keep);
  for (size_t i = 0; i < keep; i++) frac += i < lead ? '0' : D[fstart + (i - lead)];

  // first digit of D that is not shown
  const size_t firstDropped = fstart + (keep > lead ? keep - lead : 0);
  bool truncated = false;
  for (size_t j = firstDropped; j < L; j++)
    if (D[j] != '0') {
      truncated = true;
      break;
    }

  if (truncated) {
    if (keep) out += "." + frac;
    out += "...";
    return out;
  }
  size_t end = frac.size();
  while (end && frac[end - 1] == '0') end--;
  if (end) out += "." + frac.substr(0, end);
  return out;
}

// 4 icon indexes = the first 4 bytes of keccak256(20 raw address bytes) (32 bits; security review MINOR 3: the
// old 4 nibbles gave only 16 bits). Companion apps can reproduce it: keccak256(addressBytes)[0..3].
void addr_fingerprint(const Addr& a, uint8_t idx[4]) {
  uint8_t h[32];
  keccak256(a.v, 20, h);
  for (int i = 0; i < 4; i++) idx[i] = h[i];
}

std::string u256_dec(const U256& v) { return u256_decimal(v); }

// 16 short, visually distinct, easily drawn nouns with distinct first letters (text fallback / icon names).
const char* const FINGERPRINT_NAMES[16] = {
    "sun", "moon", "key",    "tree", "fish", "bird", "heart", "cup",  //
    "eye", "leaf", "anchor", "drop", "gem",  "ring", "owl",   "wave",
};

}  // namespace ripar
