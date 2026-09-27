// Firmware token + chain table (docs/PROTOCOL.md §4 ripar-cosign-req keys 15/16; security review B3).
// Portable C++14 (host + device).
//
// ADDING A TOKEN: append a row to the chain's table with the EIP-55 address and exactly the decimals() / symbol()
// the contract returns. test/host/test_policy.cpp checks every address is a valid EIP-55 checksum.
#include "tokens.h"

#include "abi.h"

namespace ripar {

namespace {

const ChainInfo CHAINS[] = {
    {10143, "Monad testnet", "MON", 18},
    {143, "Monad", "MON", 18},
};

// ---- Monad testnet (10143)
const TokenInfo TOKENS_10143[] = {
    // Agora AUSD on Monad testnet (research/judge_merge.md §6, verify_tech.md #17: 6 decimals).
    {"0xa9012a055bd4e0eDfF8Ce09f960291C09D5322dC", 6, "AUSD", "Agora USD"},
    // MockUSD - Ripar's 6-decimal demo token (contracts/src/MockUSD.sol: ERC20("MockUSD (Ripar demo)", "mUSD"),
    // decimals() = 6). CREATE2 address from the bytecode frozen at main 5cea7cf (contracts/SPEC.md v1.2).
    {"0xB5b7eaffbF9bf68cbcC1Ce8B5850b2ea9d6f9a2a", 6, "mUSD", "MockUSD (Ripar demo)"},
};

// ---- Monad mainnet (143): no token verified yet (AUSD's mainnet address has not been checked on 143).
const TokenInfo TOKENS_143[] = {
    {"", 6, "AUSD", "Agora USD"},  // PLACEHOLDER: TODO(team) verify the AUSD address on chain 143 before filling in
};

template <size_t N>
const TokenInfo* find_in(const TokenInfo (&t)[N], const Addr& a) {
  for (size_t i = 0; i < N; i++) {
    Addr x;
    if (addr_from_hex(t[i].addr, x) && x == a) return &t[i];
  }
  return nullptr;
}

std::string u64_text(uint64_t v) {
  char buf[24];
  size_t k = 0;
  do {
    buf[k++] = char('0' + v % 10);
    v /= 10;
  } while (v);
  std::string s;
  while (k) s += buf[--k];
  return s;
}

}  // namespace

const ChainInfo* chain_find(uint64_t chainId) {
  for (const ChainInfo& c : CHAINS)
    if (c.chainId == chainId) return &c;
  return nullptr;
}

const TokenInfo* token_find(uint64_t chainId, const Addr& token) {
  if (token.is_zero()) return nullptr;
  if (chainId == 10143) return find_in(TOKENS_10143, token);
  if (chainId == 143) return find_in(TOKENS_143, token);
  return nullptr;
}

std::string chain_text(uint64_t chainId) {
  const ChainInfo* c = chain_find(chainId);
  if (!c) return "UNKNOWN CHAIN " + u64_text(chainId);
  return std::string(c->name) + " (" + u64_text(chainId) + ")";
}

bool token_resolve(uint64_t chainId, bool native, const Addr& token, const int* claimedDecimals,
                   const std::string* claimedSymbol, TokenView& out, std::string& err) {
  TokenView v;
  v.native = native;
  if (!native) v.token = token;
  int dec = -1;
  const char* sym = nullptr;
  const char* name = nullptr;
  if (native) {
    if (const ChainInfo* c = chain_find(chainId)) {
      dec = c->nativeDecimals;
      sym = c->nativeSymbol;
      name = c->nativeSymbol;
    }
  } else if (const TokenInfo* t = token_find(chainId, token)) {
    dec = t->decimals;
    sym = t->symbol;
    name = t->name;
  }
  if (sym) {  // listed: the companion's claims must agree
    if (claimedDecimals && *claimedDecimals != dec) {
      err = "key 15 (decimals) = " + u64_text(uint64_t(*claimedDecimals)) + " disagrees with the firmware token table (" +
            sym + " has " + u64_text(uint64_t(dec)) + ")";
      return false;
    }
    if (claimedSymbol && *claimedSymbol != sym) {
      err = "key 16 (symbol) \"" + *claimedSymbol + "\" disagrees with the firmware token table (" + sym + ")";
      return false;
    }
    v.listed = true;
    v.decimals = dec;
    v.symbol = sym;
    v.name = name;
  } else {
    v.listed = false;
    v.decimals = -1;
    v.symbol = claimedSymbol ? *claimedSymbol : std::string();
  }
  out = v;
  err.clear();
  return true;
}

std::string token_amount(const TokenView& t, const U256& amount) {
  if (t.listed && t.decimals >= 0) return format_units(amount, t.decimals, t.decimals) + " " + t.symbol;
  return u256_dec(amount) + " base units";
}

#ifdef RIPAR_HOST_TEST
// Host-only hook for test/host/test_policy.cpp (not declared in any header): walks every table row.
namespace tokens_test {
size_t count() { return sizeof(TOKENS_10143) / sizeof(TokenInfo) + sizeof(TOKENS_143) / sizeof(TokenInfo); }
bool row(size_t i, uint64_t* chainId, const TokenInfo** t) {
  const size_t a = sizeof(TOKENS_10143) / sizeof(TokenInfo), b = sizeof(TOKENS_143) / sizeof(TokenInfo);
  if (i < a) {
    *chainId = 10143;
    *t = &TOKENS_10143[i];
  } else if (i < a + b) {
    *chainId = 143;
    *t = &TOKENS_143[i - a];
  } else {
    return false;
  }
  return true;
}
}  // namespace tokens_test
#endif

}  // namespace ripar
