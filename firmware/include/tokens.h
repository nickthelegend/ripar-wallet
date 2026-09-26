// Firmware token + chain table (security review B3). Portable C++14 (host + device).
//
// The device never takes decimals or a symbol from the companion for a token it knows: amounts of listed assets
// are formatted with the table's decimals, and a request whose optional keys 15 (decimals) / 16 (symbol)
// disagree with the table is refused. Unlisted tokens are shown as the raw base-unit integer, the full token
// address and "UNKNOWN TOKEN - decimals unverified"; a companion symbol is only ever shown marked "(companion)".
#pragma once
#include <cstdint>
#include <string>

#include "util.h"

namespace ripar {

struct TokenInfo {
  const char* addr;   // "0x" + 40 hex (EIP-55) for an ERC-20; "" = placeholder, not deployed yet (never matches)
  uint8_t decimals;   // exactly what decimals() returns on chain
  const char* symbol;  // exactly what symbol() returns on chain (printable ASCII, <= 16 bytes)
  const char* name;    // plain-language name for the review screen
};

struct ChainInfo {
  uint64_t chainId;
  const char* name;           // "Monad testnet"
  const char* nativeSymbol;   // "MON"
  uint8_t nativeDecimals;     // 18
};

const ChainInfo* chain_find(uint64_t chainId);                     // nullptr = chain not supported by the firmware
const TokenInfo* token_find(uint64_t chainId, const Addr& token);   // listed ERC-20 on that chain, or nullptr
// "Monad testnet (10143)" / "UNKNOWN CHAIN 1"
std::string chain_text(uint64_t chainId);

// What the review shows for one asset.
struct TokenView {
  bool native = false;  // the chain's native coin (a call's value), not an ERC-20
  bool listed = false;  // decimals + symbol come from the firmware table (verified)
  Addr token;           // ERC-20 contract (zero for native)
  int decimals = -1;    // table decimals when listed, else -1 (unverified: amounts are shown in base units)
  std::string symbol;   // table symbol when listed; otherwise the companion's key-16 symbol ("" if none)
  std::string name;     // table name when listed, else ""
};

// Resolves the asset of an amount. For a listed asset (a table token, or the native coin of a supported chain) the
// companion's claims - request keys 15 / 16, pass nullptr when absent - must equal the table, else false + err
// (a lying companion is refused, not corrected). An unlisted asset always resolves (listed = false).
bool token_resolve(uint64_t chainId, bool native, const Addr& token, const int* claimedDecimals,
                   const std::string* claimedSymbol, TokenView& out, std::string& err);

// Amount text: "25 AUSD" / "0.5 MON" for a listed asset (every fraction digit, never rounded);
// "25000000 base units" for an unlisted one (the raw integer, no decimals applied).
std::string token_amount(const TokenView& t, const U256& amount);

}  // namespace ripar
