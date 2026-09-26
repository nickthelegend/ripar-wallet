// Caveat enforcers + pinned contract addresses compiled into the firmware (docs/PROTOCOL.md §4 ripar-mandate-req,
// security review B2 / M3 / M4). Portable C++14 (host + device).
//
// A mandate is only signed when EVERY caveat enforcer has a strict terms decoder (review.h decode_caveat) and
// exactly one caveat is the pinned Ripar PulseCosignEnforcer (policy.h check_mandate). Tables are per chain: an
// address only means something on the chain it was deployed on.
//
// MetaMask delegation-framework v1.3.0 (documents/Deployments.md, fetched 2026-09-26 from
// github.com/MetaMask/delegation-framework; deterministic CREATE2 deployment with salt "GATOR", the document lists
// "Monad" and "Monad testnet" among the deployment chains, same address on both). Every address below is the EIP-55
// checksummed form from that document; the host tests check each checksum.
//
// DECODED (enforcer_kind != Unknown): the 8 MetaMask enforcers whose getTermsInfo() layout the device decodes and
// shows field by field, plus the Ripar PulseCosignEnforcer.
// KNOWN BUT REFUSED (enforcer_refused_name): every other v1.3.0 enforcer - no terms decoder, so the user could not
// see what it allows (AllowedCalldata, AllowedMethods, ArgsEqualityCheck, ExactCalldata/Execution, streaming,
// multi-token, balance-change, Nonce, Id, BlockNumber, ...) and the ones that change the semantics of the other
// caveats (LogicalOrWrapper), deploy contracts, pay via a second delegation or work in batch mode.
//
// TODO(team, after deployment): paste the deployed Ripar PulseCosignEnforcer address of each chain into
// RIPAR_COSIGN below. While a placeholder is "" the device uses the address pinned at pairing (ripar-pair-req key 5,
// shown in full and confirmed with pulse + SIGN); once filled in, pairing with any other address is refused.
#include <cstring>

#include "policy.h"
#include "protocol.h"
#include "review.h"

namespace ripar {

namespace {

const uint64_t CHAIN_MONAD_TESTNET = 10143;
const uint64_t CHAIN_MONAD_MAINNET = 143;

struct Pinned {
  uint64_t chainId;
  const char* addr;  // "0x" + 40 hex digits, or "" (placeholder: not deployed yet, never matches)
};

// ---- Ripar PulseCosignEnforcer. TODO(team): paste the deployed addresses (EIP-55).
const Pinned RIPAR_COSIGN[] = {
    {CHAIN_MONAD_TESTNET, ""},  // PLACEHOLDER - TODO after deployment on 10143
    {CHAIN_MONAD_MAINNET, ""},  // PLACEHOLDER - TODO after deployment on 143
};

// ---- MetaMask DelegationManager v1.3.0 (research/judge_merge.md §6: live on 143 and 10143)
const Pinned DELEGATION_MANAGER[] = {
    {CHAIN_MONAD_TESTNET, "0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3"},
    {CHAIN_MONAD_MAINNET, "0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3"},
};

struct Enf {
  const char* addr;  // EIP-55
  EnfKind kind;
};

// ---- MetaMask v1.3.0 enforcers with a terms decoder (same address on every listed chain)
const Enf METAMASK_DECODED[] = {
    {"0x7F20f61b1f09b08D970938F6fa563634d65c4EeB", EnfKind::AllowedTargets},             // AllowedTargetsEnforcer
    {"0x474e3Ae7E169e940607cC624Da8A15Eb120139aB", EnfKind::ERC20PeriodTransfer},        // ERC20PeriodTransferEnforcer
    {"0xf100b0819427117EcF76Ed94B358B1A5b5C6D2Fc", EnfKind::ERC20TransferAmount},        // ERC20TransferAmountEnforcer
    {"0x04658B29F6b82ed55274221a06Fc97D318E25416", EnfKind::LimitedCalls},               // LimitedCallsEnforcer
    {"0xF71af580b9c3078fbc2BBF16FbB8EEd82b330320", EnfKind::NativeTokenTransferAmount},  // NativeTokenTransferAmountEnf.
    {"0xE144b0b2618071B4E56f746313528a669c7E65c5", EnfKind::Redeemer},                   // RedeemerEnforcer
    {"0x1046bb45C8d673d4ea75321280DB34899413c069", EnfKind::Timestamp},                  // TimestampEnforcer
    {"0x92Bf12322527cAA612fd31a0e810472BBB106A8F", EnfKind::ValueLte},                   // ValueLteEnforcer
};

struct Refused {
  const char* addr;  // EIP-55
  const char* name;  // contract name (refusal text)
};

// ---- MetaMask v1.3.0 enforcers the device recognises but refuses (no decoder / unsafe semantics)
const Refused METAMASK_REFUSED[] = {
    {"0xc2b0d624c1c4319760C96503BA27C347F3260f55", "AllowedCalldataEnforcer"},
    {"0x2c21fD0Cb9DC8445CB3fb0DC5E7Bb0Aca01842B5", "AllowedMethodsEnforcer"},
    {"0xe264F1f09A19505a1ca1a86D5b01E8bFdb64324A", "ApprovalRevocationEnforcer"},
    {"0x44B8C6ae3C304213c3e298495e12497Ed3E56E41", "ArgsEqualityCheckEnforcer"},
    {"0x5d9818dF0AE3f66e9c3D0c5029DAF99d1823ca6c", "BlockNumberEnforcer"},
    {"0xcdF6aB796408598Cea671d79506d7D48E97a5437", "ERC20BalanceChangeEnforcer"},
    {"0x56c97aE02f233B29fa03502Ecc0457266d9be00e", "ERC20StreamingEnforcer"},
    {"0x8aFdf96eDBbe7e1eD3f5Cd89C7E084841e12A09e", "ERC721BalanceChangeEnforcer"},
    {"0x3790e6B7233f779b09DA74C72b6e94813925b9aF", "ERC721TransferEnforcer"},
    {"0x63c322732695cAFbbD488Fc6937A0A7B66fC001A", "ERC1155BalanceChangeEnforcer"},
    {"0x99F2e9bF15ce5eC84685604836F71aB835DBBdED", "ExactCalldataEnforcer"},
    {"0x146713078D39eCC1F5338309c28405ccf85Abfbb", "ExactExecutionEnforcer"},
    {"0xC8B5D93463c893401094cc70e66A206fb5987997", "IdEnforcer"},
    {"0xFB2f1a9BD76d3701B730E5d69C3219D42D80eBb7", "MultiTokenPeriodEnforcer"},
    {"0xbD7B277507723490Cd50b12EaaFe87C616be6880", "NativeBalanceChangeEnforcer"},
    {"0x9BC0FAf4Aca5AE429F4c06aEEaC517520CB16BD9", "NativeTokenPeriodTransferEnforcer"},
    {"0xD10b97905a320b13a0608f7E9cC506b56747df19", "NativeTokenStreamingEnforcer"},
    {"0xDE4f2FAC4B3D87A1d9953Ca5FC09FCa7F366254f", "NonceEnforcer"},
    {"0xE1302607a3251AF54c3a6e69318d6aa07F5eB46c", "LogicalOrWrapperEnforcer"},
    {"0x24ff2AA430D53a8CD6788018E902E098083dcCd2", "DeployedEnforcer"},
    {"0x4803a326ddED6dDBc60e659e5ed12d85c7582811", "NativeTokenPaymentEnforcer"},
    {"0x1e141e455d08721Dd5BCDA1BaA6Ea5633Afd5017", "ExactExecutionBatchEnforcer"},
    {"0x982FD5C86BBF425d7d1451f974192d4525113DfD", "ExactCalldataBatchEnforcer"},
    {"0x6649b61c873F6F9686A1E1ae9ee98aC380c7bA13", "SpecificActionERC20TransferBatchEnforcer"},
    {"0x7EEf9734E7092032B5C56310Eb9BbD1f4A524681", "OwnershipTransferEnforcer"},
};

bool metamask_chain(uint64_t chainId) { return chainId == CHAIN_MONAD_TESTNET || chainId == CHAIN_MONAD_MAINNET; }

bool addr_is(const char* hex, const Addr& a) {
  Addr x;
  return addr_from_hex(hex, x) && x == a;  // "" never matches
}

template <size_t N>
bool pinned_lookup(const Pinned (&t)[N], uint64_t chainId, Addr& out) {
  for (size_t i = 0; i < N; i++) {
    Addr x;
    if (t[i].chainId == chainId && addr_from_hex(t[i].addr, x)) {
      out = x;
      return true;
    }
  }
  return false;
}

}  // namespace

bool compiled_cosign_enforcer(uint64_t chainId, Addr& out) { return pinned_lookup(RIPAR_COSIGN, chainId, out); }

bool compiled_delegation_manager(uint64_t chainId, Addr& out) {
  return pinned_lookup(DELEGATION_MANAGER, chainId, out);
}

EnfKind enforcer_kind(uint64_t chainId, const Addr& enforcer, const Context& ctx) {
  if (enforcer.is_zero()) return EnfKind::Unknown;
  Addr pulse;
  if (compiled_cosign_enforcer(chainId, pulse)) {
    if (pulse == enforcer) return EnfKind::PulseCosign;
  } else if (ctx.paired() && ctx.chainId == chainId && !ctx.pulseCosignEnforcer.is_zero() &&
             ctx.pulseCosignEnforcer == enforcer) {
    return EnfKind::PulseCosign;
  }
  if (metamask_chain(chainId))
    for (const Enf& e : METAMASK_DECODED)
      if (addr_is(e.addr, enforcer)) return e.kind;
  return EnfKind::Unknown;
}

const char* enforcer_refused_name(uint64_t chainId, const Addr& enforcer) {
  if (!metamask_chain(chainId)) return nullptr;
  for (const Refused& e : METAMASK_REFUSED)
    if (addr_is(e.addr, enforcer)) return e.name;
  return nullptr;
}

const char* enforcer_kind_text(EnfKind k) {
  switch (k) {
    case EnfKind::PulseCosign:
      return "Pulse co-sign + spend caps";
    case EnfKind::ERC20TransferAmount:
      return "ERC-20 total spend cap";
    case EnfKind::NativeTokenTransferAmount:
      return "MON total spend cap";
    case EnfKind::ValueLte:
      return "Max MON value per call";
    case EnfKind::LimitedCalls:
      return "Limited number of calls";
    case EnfKind::ERC20PeriodTransfer:
      return "ERC-20 cap per period";
    case EnfKind::Timestamp:
      return "Valid time window";
    case EnfKind::AllowedTargets:
      return "Only listed contracts";
    case EnfKind::Redeemer:
      return "Only listed redeemers";
    default:
      return "UNKNOWN ENFORCER";
  }
}

// Plain-language name of an enforcer the device can DECODE without a pairing context (compiled-in addresses only).
const char* enforcer_name(uint64_t chainId, const Addr& enforcer) {
  const EnfKind k = enforcer_kind(chainId, enforcer, Context());
  return k == EnfKind::Unknown ? nullptr : enforcer_kind_text(k);
}

#ifdef RIPAR_HOST_TEST
// Host-only hook for test/host/test_protocol.cpp + test_policy.cpp (not declared in any header): walks every row.
namespace enforcers_test {
// table: 0 = Ripar PulseCosignEnforcer, 1 = DelegationManager, 2 = MetaMask decoded, 3 = MetaMask refused
size_t count() {
  return sizeof(RIPAR_COSIGN) / sizeof(Pinned) + sizeof(DELEGATION_MANAGER) / sizeof(Pinned) +
         sizeof(METAMASK_DECODED) / sizeof(Enf) + sizeof(METAMASK_REFUSED) / sizeof(Refused);
}
bool row(size_t i, int* table, uint64_t* chainId, const char** addr, const char** name) {
  const size_t a = sizeof(RIPAR_COSIGN) / sizeof(Pinned), b = sizeof(DELEGATION_MANAGER) / sizeof(Pinned),
               c = sizeof(METAMASK_DECODED) / sizeof(Enf), d = sizeof(METAMASK_REFUSED) / sizeof(Refused);
  if (i < a) {
    *table = 0;
    *chainId = RIPAR_COSIGN[i].chainId;
    *addr = RIPAR_COSIGN[i].addr;
    *name = "PulseCosignEnforcer";
  } else if (i < a + b) {
    *table = 1;
    *chainId = DELEGATION_MANAGER[i - a].chainId;
    *addr = DELEGATION_MANAGER[i - a].addr;
    *name = "DelegationManager";
  } else if (i < a + b + c) {
    *table = 2;
    *chainId = 0;
    *addr = METAMASK_DECODED[i - a - b].addr;
    *name = enforcer_kind_text(METAMASK_DECODED[i - a - b].kind);
  } else if (i < a + b + c + d) {
    *table = 3;
    *chainId = 0;
    *addr = METAMASK_REFUSED[i - a - b - c].addr;
    *name = METAMASK_REFUSED[i - a - b - c].name;
  } else {
    return false;
  }
  return true;
}
}  // namespace enforcers_test
#endif

}  // namespace ripar
