// Calldata decoding + human formatting. Host + device.
#pragma once
#include <string>

#include "util.h"

namespace ripar {

struct Erc20Call {
  enum Kind { None, Transfer, Approve, TransferFrom, Unknown } kind = None;  // None = empty calldata
  Addr from, to;  // Transfer: to. Approve: to = spender. TransferFrom: from -> to
  U256 amount;
  uint32_t selector = 0;
};
// Strict: exact length (4 + 32*n), address words must have 12 zero bytes. Unknown selector -> Unknown.
Erc20Call abi_decode_erc20(const Bytes& calldata);

std::string addr_checksum(const Addr& a);                         // EIP-55, with 0x
std::string format_units(const U256& v, int decimals, int maxFrac = 6);  // "12.5", "0.000001", "1,234.5"
std::string u256_dec(const U256& v);                               // plain decimal, no grouping ("0", "25000000")
// 4 icon indexes (0..255 each) = the first 4 bytes of keccak256(20 address bytes): 32 fingerprint bits. The
// same address always shows the same icons. ui_fingerprint() uses every bit (shape, colour, dot, tile).
// The icons are a quick visual aid only; review screens always show the full 42-character EIP-55 address.
void addr_fingerprint(const Addr& a, uint8_t idx[4]);
extern const char* const FINGERPRINT_NAMES[16];  // "sun","moon","key",... (text fallback: FINGERPRINT_NAMES[idx & 15])

}  // namespace ripar
