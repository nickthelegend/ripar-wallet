// Review screens: the exact ordered (label, value) lines the device shows for a parsed request, and the strict
// caveat-terms decoders (security review M4). Portable C++14 (host + device), host-tested in test/host/test_policy.cpp.
//
// flows.cpp builds the screen ONLY from these lines and signs the digest rebuilt from the SAME parsed struct
// (protocol.h cosign_digest(r) etc.), so what is displayed and what is signed come from one place. Rules:
//   - every address (payee, spender, token, target, delegate, vault, contract) is the full 42-character EIP-55 form;
//     hashes are full 0x + 64 hex; amounts never rounded (tokens.h token_amount); times as UTC
//   - companion-provided text is marked "(companion)"; values are printable ASCII (UTF-8 shown as '?')
//   - Review::ok == false -> the first line is REFUSED + the reason, and SIGN must not be armed
//   - firmware v1.2: the vault is shown as "<address> (derived from this device)" (vault.h); a co-sign for the
//     remembered mandate shows "<payee> becomes an AUTO payee of this mandate: ..." with the mandate's caps exactly
//     when policy.h cosign_whitelists_payee() holds; the mandate's AUTO period reads "never resets (lifetime cap)" for
//     0, else the duration + "(fixed windows from the first AUTO spend)"; the agent id is marked "(companion)"
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "context.h"
#include "policy.h"
#include "protocol.h"

namespace ripar {

enum class Tone : uint8_t { Normal, Good, Warn, Bad, Dim };  // UI colours: text / green / amber / red / grey

struct RLine {
  std::string label;  // "" = the value uses the full width
  std::string value;
  Tone tone;
};

struct Review {
  std::string title;         // "CO-SIGN PAYMENT", ...
  std::vector<RLine> lines;  // in display order
  bool ok = false;           // the policy allows signing this request
  std::string refusal;       // why not ("" when ok)
};

// ---------------------------------------------------------------- caveat enforcers + strict terms decoders (M4)
enum class EnfKind : uint8_t {
  Unknown,                    // not decodable -> refused
  PulseCosign,                // Ripar PulseCosignEnforcer: abi.encode(Terms), 288 bytes
  ERC20TransferAmount,        // token (20) || maxAmount uint256 (32)                       = 52 bytes
  NativeTokenTransferAmount,  // allowance uint256                                          = 32 bytes
  ValueLte,                   // max value uint256                                          = 32 bytes
  LimitedCalls,               // max calls uint256                                          = 32 bytes
  ERC20PeriodTransfer,        // token (20) || periodAmount || periodDuration || startDate  = 116 bytes
  Timestamp,                  // afterThreshold uint128 || beforeThreshold uint128          = 32 bytes
  AllowedTargets,             // n x 20-byte address, n >= 1                               = 20n bytes
  Redeemer,                   // n x 20-byte address, n >= 1                               = 20n bytes
};
const size_t CAVEAT_MAX_ADDRS = 16;  // AllowedTargets / Redeemer lists longer than this are refused

// What an enforcer address is on `chainId`: the MetaMask v1.3.0 enforcers that have a decoder, or the Ripar
// PulseCosignEnforcer (compiled-in address, or the one pinned at pairing when ctx is paired to chainId). (enforcers.cpp)
EnfKind enforcer_kind(uint64_t chainId, const Addr& enforcer, const Context& ctx);
// Contract name of a known MetaMask enforcer the device deliberately does NOT decode ("NonceEnforcer",
// "AllowedCalldataEnforcer", ...) for the refusal text; nullptr otherwise. (enforcers.cpp)
const char* enforcer_refused_name(uint64_t chainId, const Addr& enforcer);
const char* enforcer_kind_text(EnfKind k);  // "ERC-20 total spend cap", ... ("UNKNOWN ENFORCER" for Unknown)

// PulseCosignEnforcer Terms (research/judge_merge.md §6), abi.encode of 9 static words:
//   bytes32 px, bytes32 py, address token, uint128 perTxAutoCap, uint128 periodAutoCap, uint32 period,
//   uint64 epoch, bool newPayeeNeedsHuman, address sentinel
struct PulseTerms {
  B32 px, py;               // device P-256 key (keyId = keccak256(abi.encode(px, py)))
  Addr token;               // metered ERC-20; zero = native only
  U256 perTxAutoCap, periodAutoCap;  // uint128
  uint32_t period = 0;      // seconds
  uint64_t epoch = 0;
  bool newPayeeNeedsHuman = false;
  Addr sentinel;            // zero = no sentinel lane
};
// Exactly 288 bytes, every word canonical (address: 12 zero bytes, uint128: 16, uint32: 28, uint64: 24,
// bool: 0 or 1). false + err otherwise.
bool decode_pulse_terms(const Bytes& terms, PulseTerms& out, std::string& err);

struct CaveatView {
  EnfKind kind = EnfKind::Unknown;
  PulseTerms pulse;          // PulseCosign
  Addr token;                // ERC20TransferAmount, ERC20PeriodTransfer
  U256 amount;               // cap / allowance / max value / max calls / period amount
  U256 duration, start;      // ERC20PeriodTransfer: periodDuration, startDate
  U256 after, before;        // Timestamp (uint128; 0 = no bound)
  std::vector<Addr> addrs;   // AllowedTargets, Redeemer
};
// Strict decode of one caveat (exact length, canonical words). Unknown / undecodable enforcers -> false + err
// ("UNKNOWN ENFORCER 0x...", "NonceEnforcer is not supported (no terms decoder)", "... terms must be 52 bytes").
bool decode_caveat(uint64_t chainId, const Caveat& c, const Context& ctx, CaveatView& out, std::string& err);

// ---------------------------------------------------------------- formatting
std::string utc_text(uint64_t unixSeconds);   // "2026-09-21 14:13:20 UTC" (proleptic Gregorian, any u64)
std::string duration_text(const U256& seconds);  // "86400 s = 1 d", "90061 s = 1 d 1 h 1 min 1 s", "45 s"
std::string ascii_text(const std::string& s);     // printable ASCII; each other UTF-8 sequence -> '?'

// ---------------------------------------------------------------- review screens
// k1 = this device's K1 address (the vault owner being bound)
Review review_pair(const PairReq& r, const Context& current, const Addr& k1);
Review review_cosign(const CosignReq& r, const Context& ctx);
Review review_mandate(const MandateReq& r, const Context& ctx, const uint8_t p1xy[64]);
// fromCosign = the device built r itself with deny_from_cosign() (requestHash computed on the device)
Review review_deny(const DenyReq& r, const Context& ctx, bool fromCosign);
Review review_privy(const PrivyReq& r, const uint8_t p1xy[64]);
Review review_revoke(const Context& ctx);
Review review_panic(const Context& ctx);   // shows panic_next_epoch(ctx)
Review review_reopen(const Context& ctx);  // shows reopen_next_nonce(ctx)

}  // namespace ripar
