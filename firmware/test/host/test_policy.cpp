// DEPS: hashes util cbor eip712 abi protocol enforcers json_strict tokens policy review context vault
// Host tests for the pinned-context policy (src/policy.cpp), the review screens + strict caveat decoders
// (src/review.cpp), the Context NVS blob (src/context.cpp) and the firmware token table (src/tokens.cpp).
//   - Context: exact byte layout v3, CRC, refusal of v1 / v2 / wrong sizes / bad flags / any flipped byte
//   - token table (B3): EIP-55 of every row, AUSD 6 decimals, placeholders never match, keys 15/16 must agree
//   - expiry (MINOR 2): UTC text, 2^40 bound, 7-day window after the monotonic "not before" time
//   - co-sign / mandate / deny / pair / revoke / panic / reopen checks against a pinned Context (M3, B2, M7)
//   - caveat decoders (M4): exact lengths, canonical ABI words, every decoded field compared with the independent
//     Python decoder (make_request.py caveat_dump via vectors_protocol.h POLICY_MANDATE)
//   - review lines: golden screens built from EIP-55 test-vector addresses, full addresses everywhere, never "..."
//   - the security review probes as regression tests (B2 nonce-only mandate, B3 1e12 AUSD, M3 chain 143,
//     MINOR 1 approve / transferFrom claims, MINOR 2 expiry 2^64-1, MINOR 3 fingerprint bits, MINOR 7 deny agent)
//   - fork review 2: N1 mandate epoch == panic floor (epochs above it survived every panic) + pair-req counter
//     floors; N2 re-pairing shows every changed pinned value and cannot abandon a live mandate ("REVOKE FIRST");
//     m2 device-time ratchet (1 day per co-sign, 30-day pairing jump in red); m3 unpinned sentinel; m5 revoke / panic
//     reviews show the enforcer that is actually signed for
//   - firmware v1.2: compiled-in PulseCosignEnforcer / registry / relay (pair keys 3 / 5 / 7 must equal them), the vault
//     derived from K1 (pair key 8 must equal it, absent = pinned; every mandate / co-sign delegator must equal it),
//     context v3 (last mandate's pulse terms, unpanickedMandates), PANIC FIRST (replaces REVOKE FIRST), review lines
//     (period text, agent id "(companion)", "<payee> becomes an AUTO payee of this mandate" exactly when the enforcer
//     v1.2 known-payee predicate holds), MockUSD in the token table
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "abi.h"
#include "cbor.h"
#include "check.h"
#include "context.h"
#include "eip712.h"
#include "hashes.h"
#include "policy.h"
#include "protocol.h"
#include "review.h"
#include "tokens.h"
#include "util.h"
#include "vault.h"
#include "vectors_protocol.h"

using namespace ripar;

namespace ripar {
namespace tokens_test {  // host-only hook in src/tokens.cpp
size_t count();
bool row(size_t i, uint64_t* chainId, const TokenInfo** t);
}  // namespace tokens_test
}  // namespace ripar

// ------------------------------------------------------------------ fixtures (EIP-55 spec test vectors + AUSD)
static int g_bad = 0;
static Bytes HX(const char* s) {
  Bytes b;
  if (!from_hex(s ? s : "", b)) g_bad++;
  return b;
}
static Addr A(const char* s) {
  Bytes b = HX(s);
  Addr a;
  if (b.size() == 20)
    std::memcpy(a.v, b.data(), 20);
  else
    g_bad++;
  return a;
}
static B32 fill32(uint8_t x) {
  B32 b;
  std::memset(b.v, x, 32);
  return b;
}

static const char* const S_PAYEE = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
// firmware v1.2: the demo device (seed sha256("ripar demo seed")) and the vault it derives from its K1
static const char* const S_K1 = "0x753454832754c071704be47915d4DeC6339624Eb";
static const char* const S_VAULT = "0xc36F625D426eBa8f1e0129276B284a939CD3A57D";
static const char* const S_OTHER_VAULT = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359";
static const char* const S_REDEEMER = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB";
// firmware v1.2: the compiled-in Ripar contracts (CREATE2, contracts/SPEC.md v1.2)
static const char* const S_PULSE = "0x64d61fe5438981DC803ED61250FEf024617ae7eE";
static const char* const S_SENTINEL = "0x6666666666666666666666666666666666666666";
static const char* const S_RELAY = "0xE433dCA75CA6cd730b1006F51A26208B000eA9E2";
// RiparReputationRelay on Monad (143), pinned since the firmware v1.2 review (contracts/test/FirmwarePins.t.sol)
static const char* const S_RELAY_143 = "0x108BA102F7D0915f51c93F128b96Bd24F647f06d";
static const char* const S_REGISTRY = "0xA08a47c9d645926615CF04D69b7a048133F68c9f";
static const char* const S_MUSD = "0xB5b7eaffbF9bf68cbcC1Ce8B5850b2ea9d6f9a2a";
static const char* const S_OTHER_PULSE = "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb";
static const char* const S_DELEGATE = "0xABaBaBaBABabABabAbAbABAbABabababaBaBABaB";
static const char* const S_AUSD = "0xa9012a055bd4e0eDfF8Ce09f960291C09D5322dC";
static const char* const S_DM = "0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3";
static const char* const S_ERC20_AMOUNT = "0xf100b0819427117EcF76Ed94B358B1A5b5C6D2Fc";
static const char* const S_TIMESTAMP = "0x1046bb45C8d673d4ea75321280DB34899413c069";
static const char* const S_REDEEMER_ENF = "0xE144b0b2618071B4E56f746313528a669c7E65c5";
static const char* const S_LIMITED = "0x04658B29F6b82ed55274221a06Fc97D318E25416";
static const char* const S_VALUE_LTE = "0x92Bf12322527cAA612fd31a0e810472BBB106A8F";
static const char* const S_NATIVE_AMOUNT = "0xF71af580b9c3078fbc2BBF16FbB8EEd82b330320";
static const char* const S_PERIOD = "0x474e3Ae7E169e940607cC624Da8A15Eb120139aB";
static const char* const S_TARGETS = "0x7F20f61b1f09b08D970938F6fa563634d65c4EeB";
static const char* const S_NONCE_ENF = "0xDE4f2FAC4B3D87A1d9953Ca5FC09FCa7F366254f";
static const char* const S_METHODS_ENF = "0x2c21fD0Cb9DC8445CB3fb0DC5E7Bb0Aca01842B5";
static const char* const S_NATIVE_PERIOD = "0x9BC0FAf4Aca5AE429F4c06aEEaC517520CB16BD9";
static const char* const MANDATE_HASH_HEX = "0x2222222222222222222222222222222222222222222222222222222222222222";

static Context pinned() {
  Context c;
  c.chainId = 10143;
  c.delegationManager = A(S_DM);
  c.pulseCosignEnforcer = A(S_PULSE);
  c.sentinel = A(S_SENTINEL);
  c.relay = A(S_RELAY);
  c.registry = A(S_REGISTRY);
  c.vault = A(S_VAULT);
  c.lastDelegationHash = fill32(0x22);
  c.hasAgentId = true;
  c.agentId = 7;
  c.minEpoch = 3;
  c.reopenNonce = 4;
  c.notBefore = 0;
  // v3: the pulse terms of mandate 0x22..22 (golden_caveats rule 1) and "signed since the last panic"
  c.pulseToken = A(S_AUSD);
  c.perTxAutoCap = U256::from_u64(25000000);
  c.periodAutoCap = U256::from_u64(50000000);
  c.period = 86400;
  c.newPayeeNeedsHuman = true;
  c.unpanickedMandates = true;
  return c;
}

// ------------------------------------------------------------------ CBOR request builder (untrusted-input shape)
static CborVal cu(uint64_t x) {
  CborVal v;
  v.type = CborVal::UInt;
  v.u = x;
  return v;
}
static CborVal cb(const Bytes& b) {
  CborVal v;
  v.type = CborVal::Bytes_;
  v.b = b;
  return v;
}
static CborVal cb(const Addr& a) { return cb(Bytes(a.v, a.v + 20)); }
static CborVal ct(const std::string& s) {
  CborVal v;
  v.type = CborVal::Text;
  v.b.assign(s.begin(), s.end());
  return v;
}
struct M {
  CborVal v;
  M() { v.type = CborVal::Map; }
  M& set(uint64_t k, const CborVal& x) {
    for (size_t i = 0; i + 1 < v.items.size(); i += 2)
      if (v.items[i].u == k) {
        v.items[i + 1] = x;
        return *this;
      }
    v.items.push_back(cu(k));
    v.items.push_back(x);
    return *this;
  }
  M& del(uint64_t k) {
    for (size_t i = 0; i + 1 < v.items.size(); i += 2)
      if (v.items[i].u == k) {
        v.items.erase(v.items.begin() + long(i), v.items.begin() + long(i) + 2);
        break;
      }
    return *this;
  }
};
static Bytes word(const U256& u) { return Bytes(u.v, u.v + 32); }
static Bytes word64(uint64_t x) { return word(U256::from_u64(x)); }
static Bytes ab(const Addr& a) { return Bytes(a.v, a.v + 20); }
static Bytes addr_word(const Addr& a) {
  Bytes w(12, 0);
  w.insert(w.end(), a.v, a.v + 20);
  return w;
}
static Bytes cat(std::initializer_list<Bytes> parts) {
  Bytes o;
  for (const Bytes& p : parts) o.insert(o.end(), p.begin(), p.end());
  return o;
}
static Bytes transfer_calldata(const Addr& to, uint64_t amount) {
  return cat({HX("a9059cbb"), addr_word(to), word64(amount)});
}

static M cosign_golden() {
  M risk, ai, claims;
  risk.set(1, ct("Nansen")).set(2, ct("Exchange")).set(3, ct("Binance 14")).set(4, cu(1234));
  claims.set(1, cb(A(S_PAYEE))).set(2, cb(A(S_AUSD))).set(3, cb(HX("01851960")));  // 25,500,000
  ai.set(1, ct("rent")).set(2, claims.v);
  M m;
  m.set(1, cb(Bytes(16, 0x11)))
      .set(2, cu(10143))
      .set(3, cb(A(S_PULSE)))
      .set(4, cb(Bytes(32, 0x22)))
      .set(5, cb(A(S_VAULT)))
      .set(6, cb(A(S_REDEEMER)))
      .set(7, cb(A(S_AUSD)))
      .set(8, cb(Bytes(1, 0)))
      .set(9, cb(transfer_calldata(A(S_PAYEE), 25500000)))
      .set(10, cb(Bytes(1, 7)))
      .set(11, cu(1790400000))
      .set(12, risk.v)
      .set(13, ai.v)
      .set(14, cb(HX("02faf080")))  // 50,000,000
      .set(15, cu(6))
      .set(16, ct("AUSD"));
  return m;
}

// PulseCosignEnforcer Terms, encoded here independently of the decoder
static Bytes pulse_terms(const Bytes& xy, const Addr& token, uint64_t perTx, uint64_t periodCap, uint32_t period,
                         uint64_t epoch, bool human, const Addr& sentinel) {
  return cat({Bytes(xy.begin(), xy.begin() + 32), Bytes(xy.begin() + 32, xy.end()), addr_word(token), word64(perTx),
              word64(periodCap), word64(period), word64(epoch), word64(human ? 1 : 0), addr_word(sentinel)});
}
static Bytes u128pair(uint64_t a, uint64_t b) {
  Bytes w1 = word64(a), w2 = word64(b);
  return cat({Bytes(w1.begin() + 16, w1.end()), Bytes(w2.begin() + 16, w2.end())});
}
static CborVal caveat(const Addr& enf, const Bytes& terms) {
  CborVal c;
  c.type = CborVal::Array;
  c.items.push_back(cb(enf));
  c.items.push_back(cb(terms));
  return c;
}
static std::vector<CborVal> golden_caveats(const Bytes& xy) {
  const Addr ausd = A(S_AUSD);
  return {
      caveat(A(S_PULSE), pulse_terms(xy, ausd, 25000000, 50000000, 86400, 3, true, A(S_SENTINEL))),
      caveat(A(S_ERC20_AMOUNT), cat({ab(ausd), word64(500000000)})),
      caveat(A(S_TIMESTAMP), u128pair(1790380800, 1790985600)),
      caveat(A(S_REDEEMER_ENF), ab(A(S_REDEEMER))),
      caveat(A(S_LIMITED), word64(100)),
      caveat(A(S_VALUE_LTE), word64(0)),
      caveat(A(S_NATIVE_AMOUNT), word64(1000000000000000000ull)),
      caveat(A(S_PERIOD), cat({ab(ausd), word64(50000000), word64(86400), word64(1790380800)})),
      caveat(A(S_TARGETS), cat({ab(ausd), ab(A(S_PAYEE))})),
  };
}
static M mandate_with(const std::vector<CborVal>& cavs) {
  CborVal arr;
  arr.type = CborVal::Array;
  arr.items = cavs;
  M m;
  m.set(1, cb(Bytes(16, 0x33)))
      .set(2, cu(10143))
      .set(3, cb(A(S_DM)))
      .set(4, cb(A(S_DELEGATE)))
      .set(5, cb(A(S_VAULT)))
      .set(6, cb(Bytes(32, 0xFF)))
      .set(7, arr)
      .set(8, cb(Bytes(1, 42)))
      .set(9, ct("Rent agent"))
      .set(10, cu(7));
  return m;
}

static bool parse_cosign(const M& m, CosignReq& r) {
  std::string err;
  const bool ok = parse_cosign_req(m.v, r, err);
  if (!ok) std::printf("     parse_cosign_req: %s\n", err.c_str());
  return ok;
}
static bool parse_mandate(const M& m, MandateReq& r) {
  std::string err;
  const bool ok = parse_mandate_req(m.v, r, err);
  if (!ok) std::printf("     parse_mandate_req: %s\n", err.c_str());
  return ok;
}

// ------------------------------------------------------------------ review comparison helpers
struct L {
  const char* label;
  std::string value;
  Tone tone;
};
static const char* tone_name(Tone t) {
  switch (t) {
    case Tone::Good:
      return "good";
    case Tone::Warn:
      return "warn";
    case Tone::Bad:
      return "bad";
    case Tone::Dim:
      return "dim";
    default:
      return "normal";
  }
}
static void print_review(const Review& r) {
  std::printf("     [%s] ok=%d refusal=%s\n", r.title.c_str(), r.ok ? 1 : 0, r.refusal.c_str());
  for (const RLine& l : r.lines)
    std::printf("       %-16s | %s (%s)\n", l.label.c_str(), l.value.c_str(), tone_name(l.tone));
}
static bool same_lines(const Review& r, const std::vector<L>& want) {
  bool ok = r.lines.size() == want.size();
  for (size_t i = 0; ok && i < want.size(); i++)
    ok = r.lines[i].label == want[i].label && r.lines[i].value == want[i].value && r.lines[i].tone == want[i].tone;
  if (!ok) {
    print_review(r);
    std::printf("     expected:\n");
    for (const L& l : want) std::printf("       %-16s | %s (%s)\n", l.label, l.value.c_str(), tone_name(l.tone));
  }
  return ok;
}
static const RLine* find_line(const Review& r, const std::string& label) {
  for (const RLine& l : r.lines)
    if (l.label == label) return &l;
  return nullptr;
}
static bool any_value_contains(const Review& r, const std::string& s) {
  for (const RLine& l : r.lines)
    if (l.value.find(s) != std::string::npos) return true;
  return false;
}
// Structural rules every review screen must satisfy (M2 / MINOR 3): printable ASCII, nothing cut ("..."), every
// address-valued line carries a full 42-character EIP-55 address, REFUSED first exactly when !ok.
static void check_review_rules(const Review& r, const char* what) {
  bool ok = true;
  for (const RLine& l : r.lines) {
    for (char ch : l.label + l.value) ok = ok && uint8_t(ch) >= 0x20 && uint8_t(ch) < 0x7F;
    ok = ok && l.value.find("...") == std::string::npos && !l.value.empty();
    static const char* const ADDR_LABELS[] = {"To",       "From",     "Spender",  "Vault",     "Redeemer",
                                              "Token addr", "Enforcer", "Contract", "Delegate",  "Manager",
                                              "Owner (K1)", "Registry", "Relay"};
    for (const char* al : ADDR_LABELS)
      if (l.label == al && l.value.compare(0, 2, "0x") == 0) {
        Bytes b;
        const bool hex = l.value.size() >= 42 && from_hex(l.value.substr(0, 42), b) && b.size() == 20;
        Addr a;
        if (hex) std::memcpy(a.v, b.data(), 20);
        ok = ok && hex && addr_checksum(a) == l.value.substr(0, 42);
      }
  }
  ok = ok && (r.ok == r.refusal.empty());
  ok = ok && (r.ok ? (r.lines.empty() || r.lines[0].label != "REFUSED")
                   : (!r.lines.empty() && r.lines[0].label == "REFUSED" && r.lines[0].value == r.refusal));
  if (!CHECK(ok)) {
    std::printf("     review rules violated: %s\n", what);
    print_review(r);
  }
}

// Canonical text of a decoded caveat (same format as make_request.py caveat_dump()).
static std::string hexa(const Addr& a) { return to_hex(a.v, 20, false); }
static std::string dump(const CaveatView& v) {
  switch (v.kind) {
    case EnfKind::PulseCosign:
      return "pulse px=" + to_hex(v.pulse.px.v, 32, false) + " py=" + to_hex(v.pulse.py.v, 32, false) +
             " token=" + hexa(v.pulse.token) + " perTx=" + u256_dec(v.pulse.perTxAutoCap) +
             " periodCap=" + u256_dec(v.pulse.periodAutoCap) + " period=" + u256_dec(U256::from_u64(v.pulse.period)) +
             " epoch=" + u256_dec(U256::from_u64(v.pulse.epoch)) + " human=" + (v.pulse.newPayeeNeedsHuman ? "1" : "0") +
             " sentinel=" + hexa(v.pulse.sentinel);
    case EnfKind::ERC20TransferAmount:
      return "erc20TransferAmount token=" + hexa(v.token) + " amount=" + u256_dec(v.amount);
    case EnfKind::NativeTokenTransferAmount:
      return "nativeTokenTransferAmount amount=" + u256_dec(v.amount);
    case EnfKind::ValueLte:
      return "valueLte amount=" + u256_dec(v.amount);
    case EnfKind::LimitedCalls:
      return "limitedCalls amount=" + u256_dec(v.amount);
    case EnfKind::ERC20PeriodTransfer:
      return "erc20PeriodTransfer token=" + hexa(v.token) + " amount=" + u256_dec(v.amount) +
             " duration=" + u256_dec(v.duration) + " start=" + u256_dec(v.start);
    case EnfKind::Timestamp:
      return "timestamp after=" + u256_dec(v.after) + " before=" + u256_dec(v.before);
    case EnfKind::AllowedTargets:
    case EnfKind::Redeemer: {
      std::string o = v.kind == EnfKind::AllowedTargets ? "allowedTargets " : "redeemer ";
      for (size_t i = 0; i < v.addrs.size(); i++) o += (i ? "," : "") + hexa(v.addrs[i]);
      return o;
    }
    default:
      return "unknown";
  }
}

// ================================================================== sections
static void test_context_blob() {
  CHECK_SECTION("Context NVS blob v3: layout, CRC, refusals");
  CHECK_EQ(CONTEXT_BODY_SIZE, size_t(252));
  CHECK_EQ(CONTEXT_BLOB_SIZE, size_t(256));
  Context c = pinned();
  c.chainId = 0x0102030405060708ull;
  c.agentId = 0x1112131415161718ull;
  c.minEpoch = 0x2122232425262728ull;
  c.reopenNonce = 0x3132333435363738ull;
  c.notBefore = 0x4142434445464748ull;
  c.lastDelegationHash = fill32(0x5A);
  c.perTxAutoCap = U256();
  c.periodAutoCap = U256();
  for (int i = 0; i < 16; i++) {
    c.perTxAutoCap.v[16 + i] = uint8_t(0x60 + i);   // uint128: the low 16 bytes
    c.periodAutoCap.v[16 + i] = uint8_t(0x70 + i);
  }
  c.period = 0x51525354u;
  uint8_t b[CONTEXT_BLOB_SIZE];
  context_serialize(c, b);
  CHECK_EQ(int(b[0]), 3);
  CHECK_EQ_HEX(b + 1, 8, "0102030405060708");
  CHECK_EQ_HEX(b + 9, 20, "db9b1e94b5b69df7e401ddbede43491141047db3");
  CHECK_EQ_HEX(b + 29, 20, "64d61fe5438981dc803ed61250fef024617ae7ee");
  CHECK_EQ_HEX(b + 49, 20, "6666666666666666666666666666666666666666");
  CHECK_EQ_HEX(b + 69, 20, "e433dca75ca6cd730b1006f51a26208b000ea9e2");
  CHECK_EQ_HEX(b + 89, 20, "a08a47c9d645926615cf04d69b7a048133f68c9f");
  CHECK_EQ_HEX(b + 109, 20, "c36f625d426eba8f1e0129276b284a939cd3a57d");
  CHECK_EQ_HEX(b + 129, 32, "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");
  CHECK_EQ(int(b[161]), 1);
  CHECK_EQ_HEX(b + 162, 8, "1112131415161718");
  CHECK_EQ_HEX(b + 170, 8, "2122232425262728");
  CHECK_EQ_HEX(b + 178, 8, "3132333435363738");
  CHECK_EQ_HEX(b + 186, 8, "4142434445464748");
  CHECK_EQ_HEX(b + 194, 20, "a9012a055bd4e0edff8ce09f960291c09d5322dc");  // v3: pulse token
  CHECK_EQ_HEX(b + 214, 16, "606162636465666768696a6b6c6d6e6f");          // perTxAutoCap (uint128)
  CHECK_EQ_HEX(b + 230, 16, "707172737475767778797a7b7c7d7e7f");          // periodAutoCap (uint128)
  CHECK_EQ_HEX(b + 246, 4, "51525354");                                  // period
  CHECK_EQ(int(b[250]), 1);                                              // newPayeeNeedsHuman
  CHECK_EQ(int(b[251]), 1);                                              // unpanickedMandates
  const uint32_t crc = crc32(b, 252);
  const uint8_t crcBE[4] = {uint8_t(crc >> 24), uint8_t(crc >> 16), uint8_t(crc >> 8), uint8_t(crc)};
  CHECK_EQ_BYTES(b + 252, crcBE, 4);

  Context back;
  CHECK(context_deserialize(b, sizeof b, back));
  uint8_t again[CONTEXT_BLOB_SIZE];
  context_serialize(back, again);
  CHECK_EQ_BYTES(again, b, sizeof b);
  CHECK(back.vault == c.vault && back.agentId == c.agentId && back.hasAgentId && back.notBefore == c.notBefore);
  CHECK(back.pulseToken == c.pulseToken && back.period == c.period && back.newPayeeNeedsHuman &&
        back.unpanickedMandates && back.perTxAutoCap.cmp(c.perTxAutoCap) == 0 &&
        back.periodAutoCap.cmp(c.periodAutoCap) == 0);
  {  // the flags round-trip as false too
    Context f = c;
    f.newPayeeNeedsHuman = false;
    f.unpanickedMandates = false;
    uint8_t fb[CONTEXT_BLOB_SIZE];
    context_serialize(f, fb);
    CHECK(fb[250] == 0 && fb[251] == 0);
    Context fback;
    CHECK(context_deserialize(fb, sizeof fb, fback) && !fback.newPayeeNeedsHuman && !fback.unpanickedMandates);
  }

  // any single flipped bit is refused and leaves the output untouched
  size_t refused = 0;
  for (size_t i = 0; i < sizeof b; i++) {
    uint8_t t[CONTEXT_BLOB_SIZE];
    std::memcpy(t, b, sizeof t);
    t[i] ^= uint8_t(1u << (i % 8));
    Context o;
    o.chainId = 99;
    if (!context_deserialize(t, sizeof t, o) && o.chainId == 99) refused++;
  }
  CHECK_EQ(refused, sizeof b);
  Context o;
  CHECK(!context_deserialize(b, sizeof b - 1, o));
  CHECK(!context_deserialize(nullptr, sizeof b, o));
  uint8_t big[CONTEXT_BLOB_SIZE + 1];
  std::memcpy(big, b, sizeof b);
  big[sizeof b] = 0;
  CHECK(!context_deserialize(big, sizeof big, o));
  // versions 1 / 2 (older firmware) and a bad flag byte are refused even with a valid CRC
  uint8_t t[CONTEXT_BLOB_SIZE];
  const auto recrc = [](uint8_t* x) {
    const uint32_t k = crc32(x, CONTEXT_BODY_SIZE);
    x[252] = uint8_t(k >> 24), x[253] = uint8_t(k >> 16), x[254] = uint8_t(k >> 8), x[255] = uint8_t(k);
  };
  for (uint8_t ver : {uint8_t(1), uint8_t(2), uint8_t(4)}) {
    std::memcpy(t, b, sizeof t);
    t[0] = ver;
    recrc(t);
    CHECK(!context_deserialize(t, sizeof t, o));
  }
  for (size_t flag : {size_t(161), size_t(250), size_t(251)}) {
    std::memcpy(t, b, sizeof t);
    t[flag] = 2;
    recrc(t);
    CHECK(!context_deserialize(t, sizeof t, o));
  }
  {  // a genuine v2 blob of firmware v1.1 (198 bytes, its own CRC): not loaded -> the device counts as unpaired
    uint8_t v2[198];
    std::memcpy(v2, b, 194);
    v2[0] = 2;
    const uint32_t k = crc32(v2, 194);
    v2[194] = uint8_t(k >> 24), v2[195] = uint8_t(k >> 16), v2[196] = uint8_t(k >> 8), v2[197] = uint8_t(k);
    Context u;
    CHECK(!context_deserialize(v2, sizeof v2, u) && !u.paired());
  }
  // a default Context is "not paired"
  CHECK(!Context().paired());
  Context z;
  context_serialize(Context(), t);
  CHECK(context_deserialize(t, sizeof t, z) && !z.paired());
}

static void test_tokens() {
  CHECK_SECTION("token table (B3)");
  size_t n = 0, placeholders = 0;
  for (size_t i = 0; i < tokens_test::count(); i++) {
    uint64_t chain = 0;
    const TokenInfo* t = nullptr;
    if (!CHECK(tokens_test::row(i, &chain, &t))) break;
    CHECK(chain_find(chain) != nullptr);
    CHECK(t->decimals <= 36);
    CHECK(t->symbol && std::strlen(t->symbol) >= 1 && std::strlen(t->symbol) <= 16);
    for (const char* p = t->symbol; *p; p++) CHECK(*p > 0x20 && *p < 0x7F);
    if (!t->addr || !*t->addr) {
      placeholders++;
      continue;
    }
    n++;
    Addr a;
    CHECK(addr_from_hex(t->addr, a));
    CHECK_EQ(addr_checksum(a), std::string(t->addr));
    CHECK(token_find(chain, a) == t);
  }
  CHECK(n >= 1);
  CHECK(!tokens_test::row(tokens_test::count(), nullptr, nullptr));
  std::printf("   %u verified token(s), %u placeholder(s) (TODO after deployment)\n", unsigned(n), unsigned(placeholders));

  const Addr ausd = A(S_AUSD);
  const TokenInfo* t = token_find(10143, ausd);
  CHECK(t && t->decimals == 6 && std::string(t->symbol) == "AUSD");
  // firmware v1.2: MockUSD (contracts/src/MockUSD.sol, CREATE2) on 10143 only, 6 decimals, symbol "mUSD"
  t = token_find(10143, A(S_MUSD));
  CHECK(t && t->decimals == 6 && std::string(t->symbol) == "mUSD" && std::string(t->name) == "MockUSD (Ripar demo)");
  CHECK(token_find(143, A(S_MUSD)) == nullptr);
  CHECK(token_find(143, ausd) == nullptr);  // mainnet address not verified: not listed
  CHECK(token_find(1, ausd) == nullptr);
  CHECK(token_find(10143, Addr()) == nullptr);  // "" placeholders never match the zero address
  CHECK_EQ(chain_text(10143), std::string("Monad testnet (10143)"));
  CHECK_EQ(chain_text(143), std::string("Monad (143)"));
  CHECK_EQ(chain_text(1), std::string("UNKNOWN CHAIN 1"));

  TokenView v;
  std::string err;
  const int d6 = 6, d18 = 18;
  const std::string sA = "AUSD", sU = "USDC", sM = "MON";
  CHECK(token_resolve(10143, false, ausd, nullptr, nullptr, v, err) && v.listed && v.decimals == 6 && v.symbol == "AUSD");
  CHECK(token_resolve(10143, false, ausd, &d6, &sA, v, err));
  CHECK(!token_resolve(10143, false, ausd, &d18, nullptr, v, err));
  CHECK(err.find("key 15") != std::string::npos);
  CHECK(!token_resolve(10143, false, ausd, nullptr, &sU, v, err));
  CHECK(err.find("key 16") != std::string::npos);
  CHECK(token_resolve(10143, true, Addr(), &d18, &sM, v, err) && v.native && v.listed && v.symbol == "MON");
  CHECK(!token_resolve(10143, true, Addr(), &d6, nullptr, v, err));
  // unlisted: always resolves, base units, companion symbol kept for display only
  CHECK(token_resolve(10143, false, A(S_PAYEE), &d6, &sU, v, err) && !v.listed && v.decimals == -1 && v.symbol == "USDC");
  CHECK_EQ(token_amount(v, U256::from_u64(25000000)), std::string("25000000 base units"));
  CHECK(token_resolve(1, true, Addr(), nullptr, nullptr, v, err) && !v.listed);
  // amounts of listed tokens: every fraction digit, never rounded, never "..."
  CHECK(token_resolve(10143, false, ausd, nullptr, nullptr, v, err));
  CHECK_EQ(token_amount(v, U256::from_u64(1000000000000ull)), std::string("1,000,000 AUSD"));  // review probe B3
  CHECK_EQ(token_amount(v, U256::from_u64(1)), std::string("0.000001 AUSD"));
  CHECK_EQ(token_amount(v, U256::from_u64(25500000)), std::string("25.5 AUSD"));
  CHECK(token_resolve(10143, true, Addr(), nullptr, nullptr, v, err));
  CHECK_EQ(token_amount(v, U256::from_u64(1)), std::string("0.000000000000000001 MON"));
  const std::string sMusd = "mUSD", sMUSD = "MUSD";
  CHECK(token_resolve(10143, false, A(S_MUSD), &d6, &sMusd, v, err) && v.listed && v.symbol == "mUSD");
  CHECK_EQ(token_amount(v, U256::from_u64(1234567)), std::string("1.234567 mUSD"));
  CHECK(!token_resolve(10143, false, A(S_MUSD), &d18, nullptr, v, err));  // a lying companion is refused
  CHECK(!token_resolve(10143, false, A(S_MUSD), nullptr, &sMUSD, v, err));
}

static void test_time() {
  CHECK_SECTION("UTC text + expiry bounds (MINOR 2)");
  CHECK_EQ(utc_text(0), std::string("1970-01-01 00:00:00 UTC"));
  CHECK_EQ(utc_text(1790400000), std::string("2026-09-26 05:20:00 UTC"));
  CHECK_EQ(utc_text(951782400), std::string("2000-02-29 00:00:00 UTC"));
  CHECK_EQ(utc_text(4107542400ull), std::string("2100-03-01 00:00:00 UTC"));
  CHECK_EQ(utc_text(253402300799ull), std::string("9999-12-31 23:59:59 UTC"));
  CHECK_EQ(utc_text((1ull << 40) - 1), std::string("36812-02-20 00:36:15 UTC"));
  CHECK_EQ(utc_text(~0ull), std::string("584554051223-11-09 07:00:15 UTC"));
  CHECK_EQ(duration_text(U256::from_u64(45)), std::string("45 s"));
  CHECK_EQ(duration_text(U256::from_u64(86400)), std::string("86400 s = 1 d"));
  CHECK_EQ(duration_text(U256::from_u64(90061)), std::string("90061 s = 1 d 1 h 1 min 1 s"));

  const uint64_t floor = RIPAR_TIME_FLOOR;
  CHECK_EQ(floor, 1790380800ull);
  CHECK_EQ(effective_not_before(0), floor);
  CHECK_EQ(effective_not_before(floor + 5), floor + 5);
  std::string err;
  CHECK(expiry_check(floor + 7 * 86400, 0, err) && err.empty());
  CHECK(!expiry_check(floor + 7 * 86400 + 1, 0, err));
  CHECK(err.find("EXPIRY TOO FAR") != std::string::npos && err.find("2026-10-03 00:00:01 UTC") != std::string::npos);
  CHECK(expiry_check(0, 0, err));  // already expired: the enforcer rejects it on chain; showing it is harmless
  CHECK(!expiry_check(1ull << 40, ~0ull, err));
  CHECK(err.find("2^40") != std::string::npos);
  CHECK(!expiry_check(~0ull, 0, err));  // review probe: expiry 2^64-1 parsed fine before the fix
  CHECK(expiry_check(2000000000ull + 7 * 86400, 2000000000ull, err));
  CHECK(!expiry_check(2000000000ull + 7 * 86400 + 1, 2000000000ull, err));
  CHECK(expiry_check((1ull << 40) - 1, (1ull << 40) - 1, err));
}

static void test_pair_policy() {
  CHECK_SECTION("pairing: check_pair + context_after_pair (M3; firmware v1.2 pinned contracts + derived vault)");
  std::string err;
  const Addr k1 = A(S_K1);
  CHECK(vault_address(k1) == A(S_VAULT));
  for (size_t i = 0; i < sizeof(pv::PAIR) / sizeof(pv::PAIR[0]); i++) {
    CborVal m;
    CHECK(cbor_decode(HX(pv::PAIR[i].cbor), m));
    PairReq r;
    CHECK(parse_pair_req(m, r, err));
    const bool ok = check_pair(r, Context(), k1, err);
    CHECK_EQ(ok, pv::PAIR[i].chainId != 1);  // chain 1 is not supported by the firmware
    if (!ok) CHECK(err.find("UNSUPPORTED CHAIN 1") != std::string::npos);
    if (ok) {  // whatever the request left out, the device pins its compiled-in contracts and its own vault
      const Context c = context_after_pair(Context(), r, k1);
      CHECK(c.vault == A(S_VAULT) && c.pulseCosignEnforcer == A(S_PULSE) && c.registry == A(S_REGISTRY));
      CHECK(c.delegationManager == A(S_DM));
      CHECK(c.relay == A(r.chainId == 10143 ? S_RELAY : S_RELAY_143));  // both relays are compiled in
    }
  }
  PairReq r;
  r.reqId = Bytes(16, 1);
  r.chainId = 10143;
  r.registry = A(S_REGISTRY);
  CHECK(check_pair(r, Context(), k1, err));
  r.manager = A(S_PAYEE);  // not the MetaMask DelegationManager compiled into the firmware
  CHECK(!check_pair(r, Context(), k1, err));
  CHECK(err.find("WRONG DELEGATION MANAGER: key 4 = ") == 0);
  r.manager = A(S_DM);
  r.enforcer = A(S_PULSE);
  r.sentinel = A(S_SENTINEL);
  r.relay = A(S_RELAY);
  r.vault = A(S_VAULT);
  r.hasNow = true;
  r.now = 1790500000;
  CHECK(check_pair(r, Context(), k1, err));

  CHECK_SECTION("pairing: keys 3 / 5 / 7 must equal the compiled-in contracts (firmware v1.2)");
  {
    struct Bad {
      const char* name;
      int key;
      const char* want;
    } bad[] = {
        {"registry", 3,
         "WRONG REGISTRY: key 3 = 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed is not the RiparDeviceRegistry this "
         "firmware pins on Monad testnet (10143): 0xA08a47c9d645926615CF04D69b7a048133F68c9f"},
        {"enforcer", 5,
         "WRONG PULSE CO-SIGN ENFORCER: key 5 = 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed is not the "
         "PulseCosignEnforcer this firmware pins on Monad testnet (10143): 0x64d61fe5438981DC803ED61250FEf024617ae7eE"},
        {"relay", 7,
         "WRONG REPUTATION RELAY: key 7 = 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed is not the RiparReputationRelay "
         "this firmware pins on Monad testnet (10143): 0xE433dCA75CA6cd730b1006F51A26208B000eA9E2"},
    };
    for (const Bad& b : bad) {
      PairReq x = r;
      if (b.key == 3) x.registry = A(S_PAYEE);
      if (b.key == 5) x.enforcer = A(S_PAYEE);
      if (b.key == 7) x.relay = A(S_PAYEE);
      std::string e;
      if (!CHECK(!check_pair(x, Context(), k1, e) && e == b.want)) std::printf("     %s: %s\n", b.name, e.c_str());
      const Review rx = review_pair(x, Context(), k1);
      CHECK(!rx.ok && rx.refusal == e);
      check_review_rules(rx, b.name);
    }
    // chain 143 (firmware v1.2 review, medium): registry, enforcer AND relay are compiled in. Before the fix any
    // non-zero key 7 was accepted and pinned on 143, so a companion could route every deny to a contract it controls.
    PairReq m = r;
    m.chainId = 143;
    m.relay = A(S_PAYEE);
    {
      std::string e;
      CHECK(!check_pair(m, Context(), k1, e));
      CHECK_EQ(e, std::string("WRONG REPUTATION RELAY: key 7 = ") + S_PAYEE +
                      " is not the RiparReputationRelay this firmware pins on Monad (143): " + S_RELAY_143);
      CHECK(!review_pair(m, Context(), k1).ok);
    }
    m.relay = A(S_RELAY_143);
    CHECK(check_pair(m, Context(), k1, err));
    Context c143 = context_after_pair(Context(), m, k1);
    CHECK(c143.relay == A(S_RELAY_143) && c143.pulseCosignEnforcer == A(S_PULSE) && c143.registry == A(S_REGISTRY));
    const Review r143 = review_pair(m, Context(), k1);
    const RLine* l = find_line(r143, "Relay");
    CHECK(l && l->value == std::string(S_RELAY_143) + " (firmware table)" && l->tone == Tone::Good);
    m.relay = Addr();  // absent key 7: the compiled-in relay is pinned
    CHECK(context_after_pair(Context(), m, k1).relay == A(S_RELAY_143));
    const Review r143none = review_pair(m, Context(), k1);
    l = find_line(r143none, "Relay");
    CHECK(l && l->value == std::string(S_RELAY_143) + " (firmware table)" && l->tone == Tone::Good);
    m.enforcer = A(S_OTHER_PULSE);
    CHECK(!check_pair(m, Context(), k1, err) && err.find("WRONG PULSE CO-SIGN ENFORCER: key 5") == 0);
    m.enforcer = A(S_PULSE);
    m.registry = A(S_OTHER_PULSE);
    CHECK(!check_pair(m, Context(), k1, err) && err.find("WRONG REGISTRY: key 3") == 0);
    // absent keys 4 / 5 / 7 pin the compiled-in contracts (10143)
    PairReq minimal;
    minimal.reqId = Bytes(16, 2);
    minimal.chainId = 10143;
    minimal.registry = A(S_REGISTRY);
    CHECK(check_pair(minimal, Context(), k1, err));
    const Context cm = context_after_pair(Context(), minimal, k1);
    CHECK(cm.delegationManager == A(S_DM) && cm.pulseCosignEnforcer == A(S_PULSE) && cm.relay == A(S_RELAY));
    CHECK(cm.vault == A(S_VAULT) && cm.sentinel.is_zero());
    const Review rm = review_pair(minimal, Context(), k1);
    check_review_rules(rm, "minimal pairing");
    l = find_line(rm, "Registry");
    CHECK(l && l->value == std::string(S_REGISTRY) + " (firmware table)" && l->tone == Tone::Good);
    l = find_line(rm, "Co-sign");
    CHECK(l && l->value == std::string(S_PULSE) + " (firmware table)" && l->tone == Tone::Good);
    l = find_line(rm, "Relay");
    CHECK(l && l->value == std::string(S_RELAY) + " (firmware table)" && l->tone == Tone::Good);
  }

  CHECK_SECTION("pairing: the vault is derived from K1 - key 8 can only confirm it (firmware v1.2)");
  {
    PairReq x = r;
    x.vault = A(S_OTHER_VAULT);  // review probe (SPEC v1.2 "Vault choice"): a companion-chosen vault
    std::string e;
    CHECK(!check_pair(x, Context(), k1, e));
    CHECK_EQ(e, std::string("VAULT IS NOT THIS DEVICE'S VAULT: key 8 = ") + S_OTHER_VAULT + ", but this device's K1 " +
                    S_K1 + " owns the vault " + S_VAULT +
                    " (MetaMask SimpleFactory CREATE2, salt 0; leave key 8 out to pin it)");
    const Review rx = review_pair(x, Context(), k1);
    check_review_rules(rx, "pair with another vault");
    CHECK(!rx.ok);
    const RLine* l = find_line(rx, "Vault");
    CHECK(l && l->value == std::string(S_VAULT) + " (derived from this device)");
    l = find_line(rx, "Key 8 vault");
    CHECK(l && l->value == std::string(S_OTHER_VAULT) + " (NOT THIS DEVICE'S VAULT)" && l->tone == Tone::Bad);
    CHECK(context_after_pair(Context(), x, k1).vault == A(S_VAULT));  // never the companion's key 8
    // the same request from another device (another K1): its own vault, so key 8 = S_VAULT is refused there
    const Addr otherK1 = A(S_PAYEE);
    CHECK(!check_pair(r, Context(), otherK1, e) && e.find("VAULT IS NOT THIS DEVICE'S VAULT") == 0);
    x.vault = Addr();  // absent: the derived vault is pinned
    CHECK(check_pair(x, Context(), k1, e));
    CHECK(context_after_pair(Context(), x, k1).vault == A(S_VAULT));
    CHECK(context_after_pair(Context(), x, otherK1).vault == vault_address(otherK1));
    const Review rv = review_pair(x, Context(), k1);
    CHECK(rv.ok && !find_line(rv, "Key 8 vault"));
    l = find_line(rv, "Vault");
    CHECK(l && l->value == std::string(S_VAULT) + " (derived from this device)" && l->tone == Tone::Good);
  }

  // first pairing: everything pinned, counters start at 0
  Context c = context_after_pair(Context(), r, k1);
  CHECK(c.paired() && c.chainId == 10143);
  CHECK(c.delegationManager == A(S_DM) && c.pulseCosignEnforcer == A(S_PULSE) && c.sentinel == A(S_SENTINEL));
  CHECK(c.relay == A(S_RELAY) && c.registry == A(S_REGISTRY) && c.vault == A(S_VAULT));
  CHECK(c.notBefore == 1790500000 && c.minEpoch == 0 && c.reopenNonce == 0 && !c.hasAgentId);
  CHECK(!c.unpanickedMandates && c.lastDelegationHash == B32() && !c.newPayeeNeedsHuman);
  // manager omitted -> the compiled-in DelegationManager is pinned
  PairReq r2 = r;
  r2.manager = Addr();
  CHECK(context_after_pair(Context(), r2, k1).delegationManager == A(S_DM));
  // re-pairing: monotonic counters survive, time never goes back, the mandate (and its terms and the PANIC FIRST
  // flag) survive in the same scope
  Context cur = pinned();
  cur.minEpoch = 9;
  cur.reopenNonce = 11;
  cur.notBefore = 1790600000;
  Context same = context_after_pair(cur, r, k1);
  CHECK(same.minEpoch == 9 && same.reopenNonce == 11 && same.notBefore == 1790600000);
  CHECK(same.lastDelegationHash == cur.lastDelegationHash && same.hasAgentId && same.agentId == 7);
  CHECK(same.unpanickedMandates && same.pulseToken == A(S_AUSD) && same.period == 86400 && same.newPayeeNeedsHuman);
  CHECK(same.perTxAutoCap.low_u64() == 25000000 && same.periodAutoCap.low_u64() == 50000000);
  PairReq r3 = r;
  r3.chainId = 143;
  Context moved = context_after_pair(cur, r3, k1);  // (check_pair refuses this: PANIC FIRST, below)
  CHECK(moved.chainId == 143 && moved.lastDelegationHash == B32() && moved.minEpoch == 9 && moved.pulseToken.is_zero());
  CHECK(moved.unpanickedMandates);  // the flag follows the device
  r3 = r;
  r3.now = 1790700000;
  CHECK_EQ(context_after_pair(cur, r3, k1).notBefore, 1790700000ull);

  // the pairing review shows every pinned contract in full
  const Review rv = review_pair(r, Context(), k1);
  check_review_rules(rv, "review_pair");
  CHECK(rv.ok);
  const RLine* v = find_line(rv, "Vault");
  CHECK(v && v->value == std::string(S_VAULT) + " (derived from this device)" && v->tone == Tone::Good);
  v = find_line(rv, "Co-sign");
  CHECK(v && v->value == std::string(S_PULSE) + " (firmware table)");
  v = find_line(rv, "Owner (K1)");
  CHECK(v && v->value == S_K1);
  v = find_line(rv, "Time");
  CHECK(v && v->value == "2026-09-27 09:06:40 UTC (companion clock - check it)");
  const Review rv2 = review_pair(r, pinned(), k1);
  CHECK(!rv2.lines.empty() && rv2.lines[0].value.find("REPLACES the current pairing") == 0);
  CHECK(rv2.ok && rv2.lines.size() > 1 && rv2.lines[1].value == "no pinned contract changes");
  check_review_rules(rv2, "re-pair, same contracts");

  CHECK_SECTION("re-pairing: changed pinned values shown; PANIC FIRST (v1.2, replaces REVOKE FIRST)");
  {
    const Context cur = pinned();  // holds the mandate 0x22..22 this device signed, no panic since
    PairReq same = r;
    CHECK(check_pair(same, cur, k1, err));  // same scope: allowed
    same.sentinel = A(S_PAYEE);             // the sentinel may change (the mandate stays tracked) ...
    CHECK(check_pair(same, cur, k1, err));
    const Review rs = review_pair(same, cur, k1);
    check_review_rules(rs, "re-pair, sentinel change");
    CHECK(rs.ok);
    // ... but every changed value is shown old -> new, in red
    size_t changes = 0;
    for (const RLine& l : rs.lines)
      if (l.label == "CHANGES") {
        changes++;
        CHECK(l.tone == Tone::Bad);
      }
    CHECK_EQ(changes, size_t(1));
    CHECK(any_value_contains(rs, std::string("Sentinel: ") + S_SENTINEL + " -> " + S_PAYEE));
    CHECK(context_after_pair(cur, same, k1).lastDelegationHash == cur.lastDelegationHash);
    // a 143 context that still holds a companion-chosen relay (pinned before the 143 relay was compiled in): no deny
    // is signed for it, and re-pairing (key 7 absent) moves it to the compiled-in relay, shown old -> new; the relay
    // is not part of the mandate scope, so PANIC FIRST does not block it
    {
      PairReq p143 = r;
      p143.chainId = 143;
      p143.relay = Addr();
      Context c143 = context_after_pair(Context(), p143, k1);
      c143.relay = A(S_REDEEMER);
      c143.lastDelegationHash = fill32(0x22);
      c143.unpanickedMandates = true;
      Addr pr;
      std::string e;
      CHECK(!pinned_relay(c143, 143, pr, e) && e.find("PINNED RELAY DIFFERS FROM FIRMWARE TABLE") == 0);
      CHECK(check_pair(p143, c143, k1, err));
      CHECK(context_after_pair(c143, p143, k1).relay == A(S_RELAY_143));
      const Review rr = review_pair(p143, c143, k1);
      CHECK(rr.ok && any_value_contains(rr, std::string("Relay: ") + S_REDEEMER + " -> " + S_RELAY_143));
      check_review_rules(rr, "re-pair 143, relay moved to the compiled-in one");
    }
    // review probe: a re-pairing moves the chain (or, with an older context, the enforcer / vault) away from live
    // mandates: after it the device's PANIC would be signed for the new chain / enforcer and no longer cover them
    struct Scope {
      const char* name;
      int which;
    } scopes[] = {{"chain", 0}, {"enforcer (stored one differs)", 1}, {"vault (stored one differs)", 2},
                  {"manager (stored one differs)", 3}};
    for (const Scope& sc : scopes) {
      PairReq x = r;
      Context from = cur;
      if (sc.which == 0) {
        x.chainId = 143;
        x.relay = Addr();  // key 7 left out: the relay compiled in for 143
      }
      if (sc.which == 1) from.pulseCosignEnforcer = A(S_OTHER_PULSE);
      if (sc.which == 2) from.vault = A(S_OTHER_VAULT);
      if (sc.which == 3) from.delegationManager = A(S_PAYEE);
      std::string e;
      const bool ok = check_pair(x, from, k1, e);
      if (!CHECK(!ok && e.find("PANIC FIRST: mandates signed on Monad testnet (10143) (PulseCosignEnforcer ") == 0))
        std::printf("     scope %s: ok=%d err=%s\n", sc.name, ok, e.c_str());
      CHECK(e.find(") would not be covered by PANIC after re-pairing. Sign a PANIC (home: hold 5 s) and relay it, "
                   "then pair again") != std::string::npos);
      CHECK(e.find("REVOKE FIRST") == std::string::npos);
      const Review rx = review_pair(x, from, k1);
      check_review_rules(rx, sc.name);
      CHECK(!rx.ok);
      CHECK(any_value_contains(rx, std::string("FORGETS mandate ") + MANDATE_HASH_HEX + " (still live: PANIC first)"));
      // a revoke alone is not enough: earlier mandates signed since the last panic may still be live
      Context revoked = from;
      context_after_revoke(revoked);
      CHECK(revoked.lastDelegationHash == B32() && revoked.hasAgentId && revoked.agentId == 7);
      CHECK(revoked.unpanickedMandates);
      CHECK(!check_pair(x, revoked, k1, e) && e.find("PANIC FIRST") == 0);
      // after a PANIC signed by the device (it kills every mandate it signed) the same pairing is allowed and shows
      // the change, including the forgotten (dead) mandate
      Context panicked = from;
      context_after_panic(panicked, panic_next_epoch(panicked));
      CHECK(!panicked.unpanickedMandates && panicked.minEpoch == 4);
      CHECK(check_pair(x, panicked, k1, e));
      const Review ry = review_pair(x, panicked, k1);
      check_review_rules(ry, sc.name);
      CHECK(ry.ok);
      bool shown = false;
      for (const RLine& l : ry.lines) shown = shown || (l.label == "CHANGES" && l.tone == Tone::Bad);
      CHECK(shown);
      // v1.2 review (low): the panic is only SIGNED, the chain kills the mandate once it is RELAYED - the device
      // cannot see that, so the text says "once relayed" and a red PANIC line asks the user to check it on chain
      CHECK(any_value_contains(ry, std::string("FORGETS mandate ") + MANDATE_HASH_HEX +
                                       " (killed once this device's last PANIC is relayed)"));
      CHECK(!any_value_contains(ry, "killed by this device's last PANIC"));
      {
        const RLine* pl = find_line(ry, "PANIC");
        CHECK(pl && pl->tone == Tone::Bad &&
              pl->value == "mandates signed on Monad testnet (10143) die only once this device's PANIC (min epoch 4) "
                           "is relayed there - this device cannot check that. Confirm only if the on-chain min epoch "
                           "of this device key is >= 4");
        // no such line when the scope stays (nothing is moved away from the old mandates)
        PairReq same = r;
        same.now = r.now;
        if (sc.which == 0) CHECK(!find_line(review_pair(same, panicked, k1), "PANIC"));
      }
      const Context after = context_after_pair(panicked, x, k1);
      CHECK(after.lastDelegationHash == B32() && !after.unpanickedMandates && after.minEpoch == 4);
    }
    PairReq x = r;
    x.chainId = 143;
    x.relay = Addr();
    const Review rx = review_pair(x, pinned(), k1);
    CHECK(any_value_contains(rx, "Chain: Monad testnet (10143) -> Monad (143)"));
    // an unpaired device has nothing to abandon; a paired one without mandates since its last panic neither
    CHECK(check_pair(x, Context(), k1, err));
    Context quiet = pinned();
    quiet.unpanickedMandates = false;
    CHECK(check_pair(x, quiet, k1, err));
    // a panic epoch that does not exceed the device's floor kills nothing: the flag stays
    Context noKill = pinned();
    context_after_panic(noKill, noKill.minEpoch);
    CHECK(noKill.unpanickedMandates);
  }

  CHECK_SECTION("pair-req counter floors (keys 10 / 11) only raise the counters (fork review N1)");
  {
    Context cur = pinned();  // minEpoch 3, reopenNonce 4
    PairReq f = r;
    f.hasMinEpoch = true;
    f.minEpoch = 12;
    f.hasReopenNonce = true;
    f.reopenNonce = 2;  // lower than the device's: ignored
    CHECK(check_pair(f, cur, k1, err));
    Context n = context_after_pair(cur, f, k1);
    CHECK_EQ(n.minEpoch, uint64_t(12));
    CHECK_EQ(n.reopenNonce, uint64_t(4));
    CHECK(n.unpanickedMandates);  // a floor kills nothing on chain
    const Review rv3 = review_pair(f, cur, k1);
    check_review_rules(rv3, "pair floors");
    const RLine* me = find_line(rv3, "Min epoch");
    CHECK(me && me->value == "12 RAISED from 3 (companion floor) - mandates must use it, next PANIC signs 13" &&
          me->tone == Tone::Warn);
    const RLine* rn = find_line(rv3, "Reopen nonce");
    CHECK(rn && rn->value == "4 - next REOPEN signs 5" && rn->tone == Tone::Dim);
    f.minEpoch = 1;  // a lower floor never lowers the counter
    f.reopenNonce = 40;
    n = context_after_pair(cur, f, k1);
    CHECK_EQ(n.minEpoch, uint64_t(3));
    CHECK_EQ(n.reopenNonce, uint64_t(40));
    // floors must leave headroom (the parser refuses >= 2^63 too)
    f.minEpoch = uint64_t(1) << 63;
    CHECK(!check_pair(f, cur, k1, err) && err == "BAD COUNTER FLOOR");
    CHECK_EQ(context_after_pair(cur, f, k1).minEpoch, uint64_t(3));
    f.minEpoch = (uint64_t(1) << 63) - 1;
    CHECK(check_pair(f, cur, k1, err));
    n = context_after_pair(cur, f, k1);
    CHECK_EQ(n.minEpoch, (uint64_t(1) << 63) - 1);
    CHECK(check_panic(n, err) && panic_next_epoch(n) == uint64_t(1) << 63);  // panic still possible
    // the Python pair vectors carry floors too (make_request.py minEpoch / reopenNonce)
    for (const pv::Pair& v : pv::PAIR) {
      CborVal m;
      CHECK(cbor_decode(HX(v.cbor), m));
      PairReq q;
      if (!CHECK(parse_pair_req(m, q, err))) continue;
      Context c;
      c.minEpoch = 5;
      c.reopenNonce = 9;
      const Context after = context_after_pair(c, q, k1);
      CHECK_EQ(after.minEpoch, v.hasMinEpoch && v.minEpoch > 5 ? v.minEpoch : 5u);
      CHECK_EQ(after.reopenNonce, v.hasReopenNonce && v.reopenNonce > 9 ? v.reopenNonce : 9u);
    }
    // review probe (fork review N1 / conformance MINOR 4): after a lost context the device restarts its counters at
    // 0; pairing with the on-chain floors makes its next PANIC / REOPEN count again
    Context lost;
    PairReq back = r;
    back.hasMinEpoch = true;
    back.minEpoch = 7;  // on chain: minEpoch[keyId] = 7
    back.hasReopenNonce = true;
    back.reopenNonce = 3;  // the sentinel saw nonce 3
    const Context rec = context_after_pair(lost, back, k1);
    CHECK(panic_next_epoch(rec) == 8 && reopen_next_nonce(rec) == 4);
  }

  CHECK_SECTION("pairing clock: a jump of more than 30 days is shown in red (fork review m2)");
  {
    PairReq t = r;
    t.now = RIPAR_TIME_FLOOR + 30ull * 86400;  // exactly 30 days after an unset device time: amber
    const Review r30 = review_pair(t, Context(), k1);
    const RLine* l = find_line(r30, "Time");
    CHECK(l && l->tone == Tone::Warn);
    t.now += 1;
    const Review rj = review_pair(t, Context(), k1);
    check_review_rules(rj, "pair time jump");
    l = find_line(rj, "Time");
    CHECK(l && l->tone == Tone::Bad && l->value.find("MORE THAN 30 DAYS AFTER the device time") != std::string::npos);
    Context later;
    later.notBefore = t.now - 86400;  // a device time close to it: amber again
    const Review rl = review_pair(t, later, k1);
    l = find_line(rl, "Time");
    CHECK(l && l->tone == Tone::Warn);
  }
}

static void test_cosign_policy() {
  CHECK_SECTION("co-sign: golden review screen");
  const Context ctx = pinned();
  CosignReq r;
  if (!CHECK(parse_cosign(cosign_golden(), r))) return;
  std::string err;
  CHECK(check_cosign(r, ctx, err));
  CHECK(r.aiMatches);
  const Review rv = review_cosign(r, ctx);
  CHECK_EQ(rv.title, std::string("CO-SIGN PAYMENT"));
  CHECK(rv.ok);
  check_review_rules(rv, "golden cosign");
  CHECK(same_lines(rv, {
                           {"Action", "Send AUSD (ERC-20 transfer)", Tone::Normal},
                           {"Amount", "25.5 AUSD", Tone::Normal},
                           {"To", S_PAYEE, Tone::Normal},
                           {"Token", "AUSD - Agora USD", Tone::Good},
                           {"Token addr", S_AUSD, Tone::Normal},
                           {"Chain", "Monad testnet (10143)", Tone::Normal},
                           {"Vault", std::string(S_VAULT) + " (derived from this device)", Tone::Good},
                           {"Redeemer", S_REDEEMER, Tone::Normal},
                           {"Mandate", MANDATE_HASH_HEX, Tone::Good},
                           {"", std::string(S_PAYEE) +
                                    " becomes an AUTO payee of this mandate: the agent can then pay it without a pulse, "
                                    "up to 25 AUSD per payment and 50 AUSD per 86400 s = 1 d window (fixed windows from "
                                    "the first AUTO spend)",
                            Tone::Warn},
                           {"Expires", "2026-09-26 05:20:00 UTC", Tone::Normal},
                           {"Nonce", "7", Tone::Normal},
                           {"Budget left", "50 AUSD (companion)", Tone::Dim},
                           {"AI says", "rent (companion)", Tone::Dim},
                           {"AI claims", "MATCH - recipient, token and amount (ERC-20 transfer)", Tone::Good},
                           {"Risk", "Nansen: Exchange / Binance 14, 1234 days old (companion)", Tone::Warn},
                           {"Enforcer", S_PULSE, Tone::Dim},
                       }));
  // the signed digest comes from the same struct as the lines: changing a displayed field changes the digest
  CosignReq r2 = r;
  r2.h.target.v[0] ^= 1;
  CHECK(!(cosign_digest(r2) == cosign_digest(r)));

  CHECK_SECTION("co-sign: pinned-context refusals (M3) + probes");
  struct Case {
    const char* name;
    M m;
    Context ctx;
    const char* want;
  };
  std::vector<Case> cases;
  {
    M m = cosign_golden();
    m.set(2, cu(143));  // review probe M3: a co-sign request on chain 143 parsed and was signable
    cases.push_back({"chain 143 while paired to 10143", m, ctx, "WRONG CHAIN: request is for Monad (143)"});
  }
  {
    M m = cosign_golden();
    m.set(3, cb(A(S_PAYEE)));
    cases.push_back({"companion-chosen enforcer", m, ctx, "ENFORCER NOT PINNED"});
  }
  {
    M m = cosign_golden();
    m.set(5, cb(A(S_OTHER_VAULT)));
    cases.push_back({"delegator is not the vault", m, ctx,
                     "NOT THIS DEVICE'S VAULT: delegator 0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359 is not the vault "
                     "0xc36F625D426eBa8f1e0129276B284a939CD3A57D derived from this device's K1"});
  }
  {
    Context c = ctx;
    c.vault = Addr();  // cannot happen after a v1.2 pairing: fail closed
    cases.push_back({"no vault pinned", cosign_golden(), c, "NO VAULT PINNED - pair again"});
  }
  cases.push_back({"not paired", cosign_golden(), Context(), "NOT PAIRED"});
  {
    Context c = ctx;
    c.pulseCosignEnforcer = A(S_OTHER_PULSE);  // a stored enforcer that is not the compiled-in one
    cases.push_back({"stored enforcer differs from the firmware table", cosign_golden(), c,
                     "PINNED ENFORCER DIFFERS FROM FIRMWARE TABLE"});
  }
  {
    Context c = ctx;  // a chain without a compiled-in enforcer and none pinned
    c.chainId = 777;
    c.pulseCosignEnforcer = Addr();
    M m = cosign_golden();
    m.set(2, cu(777));
    cases.push_back({"no enforcer pinned", m, c, "NO PULSE CO-SIGN ENFORCER PINNED"});
  }
  {
    M m = cosign_golden();
    m.set(11, cu(~0ull));  // review probe MINOR 2
    cases.push_back({"expiry 2^64-1", m, ctx, "EXPIRY TOO FAR"});
  }
  {
    M m = cosign_golden();
    m.set(11, cu(1790380800ull + 7 * 86400 + 1));
    cases.push_back({"expiry 7 days + 1 s", m, ctx, "EXPIRY TOO FAR"});
  }
  {
    M m = cosign_golden();
    m.set(9, cb(cat({HX("12345678"), word64(1)})));
    m.del(13);
    cases.push_back({"unknown calldata", m, ctx, "UNKNOWN CALLDATA (selector 0x12345678, 36 bytes)"});
  }
  {
    M m = cosign_golden();
    m.set(8, cb(Bytes(1, 1)));
    cases.push_back({"ERC-20 transfer with native value", m, ctx, "ERC-20 CALL WITH NATIVE VALUE"});
  }
  for (const Case& c : cases) {
    CosignReq q;
    if (!CHECK(parse_cosign(c.m, q))) continue;
    std::string e;
    const bool ok = check_cosign(q, c.ctx, e);
    if (!CHECK(!ok && e.find(c.want) != std::string::npos))
      std::printf("     case %s: ok=%d err=%s\n", c.name, ok ? 1 : 0, e.c_str());
    const Review rv2 = review_cosign(q, c.ctx);
    CHECK(!rv2.ok && rv2.refusal == e);
    check_review_rules(rv2, c.name);
  }
  // a later device time (notBefore) moves the window
  {
    M m = cosign_golden();
    m.set(11, cu(1791000000));
    CosignReq q;
    CHECK(parse_cosign(m, q));
    std::string e;
    CHECK(!check_cosign(q, ctx, e));
    Context later = ctx;
    later.notBefore = 1790500000;
    CHECK(check_cosign(q, later, e));
  }
  // firmware v1.2: the compiled-in enforcer is the one used (an empty stored one too); only a chain without one uses
  // the address pinned at pairing
  {
    Addr compiled;
    CHECK(compiled_cosign_enforcer(10143, compiled) && compiled == A(S_PULSE));
    CHECK(compiled_cosign_enforcer(143, compiled) && compiled == A(S_PULSE));
    CHECK(!compiled_cosign_enforcer(1, compiled));
    Addr out;
    std::string e;
    CHECK(pinned_cosign_enforcer(ctx, 10143, out, e) && out == A(S_PULSE));
    Context empty = ctx;
    empty.pulseCosignEnforcer = Addr();
    CHECK(pinned_cosign_enforcer(empty, 10143, out, e) && out == A(S_PULSE));
    Context other = ctx;
    other.chainId = 777;
    other.pulseCosignEnforcer = A(S_OTHER_PULSE);
    CHECK(pinned_cosign_enforcer(other, 777, out, e) && out == A(S_OTHER_PULSE));
  }

  CHECK_SECTION("co-sign: review probes MINOR 1 (AI claims) + B3 (token table)");
  {  // approve with claims equal to the decode: never a match, and the screen says so
    M m = cosign_golden();
    m.set(9, cb(cat({HX("095ea7b3"), addr_word(A(S_PAYEE)), word64(25500000)})));
    CosignReq q;
    CHECK(parse_cosign(m, q));
    CHECK(!q.aiMatches);
    const Review rv2 = review_cosign(q, ctx);
    const RLine* l = find_line(rv2, "AI claims");
    CHECK(l && l->value == "NOT CHECKED - only a transfer can match" && l->tone == Tone::Warn);
    l = find_line(rv2, "Action");
    CHECK(l && l->value == "APPROVE AUSD spending (ERC-20 approve)");
    l = find_line(rv2, "Spender");
    CHECK(l && l->value == S_PAYEE);
  }
  {  // transferFrom from the vault with matching claims: still no match (moves an allowance)
    M m = cosign_golden();
    m.set(9, cb(cat({HX("23b872dd"), addr_word(A(S_VAULT)), addr_word(A(S_PAYEE)), word64(25500000)})));
    CosignReq q;
    CHECK(parse_cosign(m, q));
    CHECK(!q.aiMatches);
    const Review rv2 = review_cosign(q, ctx);
    const RLine* l = find_line(rv2, "From");
    CHECK(l && l->value == std::string(S_VAULT) + " (vault)");
    check_review_rules(rv2, "transferFrom");
  }
  {  // transfer with a claim for another amount: MISMATCH in red
    M m = cosign_golden();
    M claims;
    claims.set(1, cb(A(S_PAYEE))).set(2, cb(A(S_AUSD))).set(3, cb(HX("01851961")));
    M ai;
    ai.set(1, ct("rent")).set(2, claims.v);
    m.set(13, ai.v);
    CosignReq q;
    CHECK(parse_cosign(m, q));
    CHECK(!q.aiMatches);
    const Review rc = review_cosign(q, ctx);
    const RLine* l = find_line(rc, "AI claims");
    CHECK(l && l->tone == Tone::Bad && l->value.find("MISMATCH") == 0);
  }
  for (size_t i = 0; i < sizeof(pv::COSIGN) / sizeof(pv::COSIGN[0]); i++) {  // Python vectors agree
    CborVal m;
    CHECK(cbor_decode(HX(pv::COSIGN[i].cbor), m));
    CosignReq q;
    std::string e;
    CHECK(parse_cosign_req(m, q, e));
    if (q.call.kind == Erc20Call::TransferFrom || q.call.kind == Erc20Call::Approve) CHECK(!q.aiMatches);
  }
  {  // review probe B3: 1e12 AUSD base units without key 15 -> "1,000,000 AUSD", never "0.000001"
    CborVal m;
    CHECK(cbor_decode(HX(pv::COSIGN[15].cbor), m));
    CosignReq q;
    std::string e;
    CHECK(parse_cosign_req(m, q, e));
    CHECK(q.enforcer == A(S_PULSE) && q.h.delegator == A(S_VAULT));  // v1.2 vectors: compiled enforcer, derived vault
    Context c = ctx;
    c.pulseCosignEnforcer = q.enforcer;
    c.vault = q.h.delegator;
    const Review rv2 = review_cosign(q, c);
    const RLine* l = find_line(rv2, "Amount");
    CHECK(l && l->value == "1,000,000 AUSD");
    CHECK(!any_value_contains(rv2, "0.000001"));
  }
  {  // unlisted token: base units + full address + UNKNOWN TOKEN; companion symbol / decimals marked
    CborVal m;
    CHECK(cbor_decode(HX(pv::COSIGN[1].cbor), m));
    CosignReq q;
    std::string e;
    CHECK(parse_cosign_req(m, q, e));
    const Review rv2 = review_cosign(q, ctx);
    const RLine* l = find_line(rv2, "Token");
    CHECK(l && l->value == "UNKNOWN TOKEN - decimals unverified" && l->tone == Tone::Bad);
    l = find_line(rv2, "Amount");
    CHECK(l && l->value == u256_dec(q.call.amount) + " base units");
    l = find_line(rv2, "Token addr");
    CHECK(l && l->value == addr_checksum(q.h.target));
    l = find_line(rv2, "Symbol");
    CHECK(l && l->value == "AUSD (companion)" && l->tone == Tone::Warn);
    l = find_line(rv2, "Decimals");
    CHECK(l && l->value == "6 (companion, unverified)");
  }

  CHECK_SECTION("co-sign: every Python vector, context pinned to it");
  size_t okCount = 0;
  for (size_t i = 0; i < sizeof(pv::COSIGN) / sizeof(pv::COSIGN[0]); i++) {
    const pv::Cosign& v = pv::COSIGN[i];
    CborVal m;
    CHECK(cbor_decode(HX(v.cbor), m));
    CosignReq q;
    std::string e;
    if (!CHECK(parse_cosign_req(m, q, e))) continue;
    Context c;
    c.chainId = q.chainId;
    c.pulseCosignEnforcer = q.enforcer;
    c.vault = q.h.delegator;
    const bool ok = check_cosign(q, c, e);
    const bool want = v.callKind != 4 /*Unknown*/ && !(v.callKind != 0 && !q.h.value.is_zero()) &&
                      v.expiry <= 1790380800ull + 7 * 86400;
    if (!CHECK_EQ(ok, want)) std::printf("     %s: %s\n", v.name, e.c_str());
    okCount += ok ? 1 : 0;
    const Review rv2 = review_cosign(q, c);
    CHECK_EQ(rv2.ok, ok);
    check_review_rules(rv2, v.name);
    // the amount line always names the asset: listed symbol or base units
    const RLine* amt = find_line(rv2, q.call.kind == Erc20Call::Approve ? "Allowance" : "Amount");
    if (q.call.kind != Erc20Call::Unknown)
      CHECK(amt && (amt->value.find(" base units") != std::string::npos ||
                    (q.token.listed && amt->value.find(" " + q.token.symbol) != std::string::npos)));
  }
  CHECK(okCount >= 10);

  CHECK_SECTION("co-sign: '<payee> becomes an AUTO payee' exactly when the enforcer v1.2 predicate holds");
  {
    const auto wl_line = [](const Review& rv) -> const RLine* {
      for (const RLine& l : rv.lines)
        if (l.label.empty() && l.value.find(" becomes an AUTO payee of this mandate") != std::string::npos) return &l;
      return nullptr;
    };
    const Addr payee = A(S_PAYEE);
    struct Case {
      const char* name;
      Bytes calldata;
      Addr target;
      uint64_t value;
      int ctxKind;  // 0 pinned() (AUSD terms), 1 native terms, 2 newPayeeNeedsHuman false, 3 other mandate hash,
                    // 4 period 0, 5 no remembered mandate
      bool want;
      const char* payee;  // expected payee in the line
    };
    const Bytes xfer = transfer_calldata(payee, 25500000);
    std::vector<Case> cs = {
        {"AUSD transfer to a new payee", xfer, A(S_AUSD), 0, 0, true, S_PAYEE},
        {"AUSD transfer of 0", transfer_calldata(payee, 0), A(S_AUSD), 0, 0, false, nullptr},
        {"transfer on another token", xfer, A(S_MUSD), 0, 0, false, nullptr},
        {"AUSD approve", cat({HX("095ea7b3"), addr_word(payee), word64(5)}), A(S_AUSD), 0, 0, false, nullptr},
        {"AUSD transferFrom", cat({HX("23b872dd"), addr_word(A(S_VAULT)), addr_word(payee), word64(5)}), A(S_AUSD), 0,
         0, false, nullptr},
        {"AUSD transfer to the zero address", transfer_calldata(Addr(), 5), A(S_AUSD), 0, 0, false, nullptr},
        {"AUSD transfer with native value", xfer, A(S_AUSD), 1, 0, false, nullptr},
        {"native send under AUSD terms", Bytes(), payee, 1000, 0, false, nullptr},
        {"native send under native terms", Bytes(), payee, 1000000000000000000ull, 1, true, S_PAYEE},
        {"native send of 0 under native terms", Bytes(), payee, 0, 1, false, nullptr},
        {"AUSD transfer under native terms", xfer, A(S_AUSD), 0, 1, false, nullptr},
        {"newPayeeNeedsHuman false", xfer, A(S_AUSD), 0, 2, false, nullptr},
        {"another mandate", xfer, A(S_AUSD), 0, 3, false, nullptr},
        {"lifetime cap (period 0)", xfer, A(S_AUSD), 0, 4, true, S_PAYEE},
        {"no mandate remembered (revoked)", xfer, A(S_AUSD), 0, 5, false, nullptr},
    };
    for (const Case& c : cs) {
      Context x = pinned();
      if (c.ctxKind == 1) {
        x.pulseToken = Addr();
        x.perTxAutoCap = U256::from_u64(500000000000000000ull);
        x.periodAutoCap = U256::from_u64(2000000000000000000ull);
        x.period = 3600;
      }
      if (c.ctxKind == 2) x.newPayeeNeedsHuman = false;
      if (c.ctxKind == 3) x.lastDelegationHash = fill32(0x23);
      if (c.ctxKind == 4) x.period = 0;
      if (c.ctxKind == 5) context_after_revoke(x);
      M m = cosign_golden();
      m.set(9, cb(c.calldata)).set(7, cb(c.target)).set(8, cb(word64(c.value))).del(13).del(15).del(16).del(14);
      CosignReq q;
      if (!CHECK(parse_cosign(m, q))) continue;
      Addr got;
      const bool wl = cosign_whitelists_payee(q, x, got);
      const Review rv2 = review_cosign(q, x);
      const RLine* l = wl_line(rv2);
      if (!CHECK(wl == c.want && (l != nullptr) == c.want)) {
        std::printf("     case %s: predicate=%d line=%d\n", c.name, wl ? 1 : 0, l ? 1 : 0);
        print_review(rv2);
      }
      check_review_rules(rv2, c.name);
      if (c.want && l) {
        CHECK(got == A(c.payee) && l->tone == Tone::Warn && l->value.find(c.payee) == 0);
        if (c.ctxKind == 1)
          CHECK_EQ(l->value, std::string(S_PAYEE) +
                                 " becomes an AUTO payee of this mandate: the agent can then pay it without a pulse, up "
                                 "to 0.5 MON per payment and 2 MON per 3600 s = 1 h window (fixed windows from the "
                                 "first AUTO spend)");
        if (c.ctxKind == 4)
          CHECK_EQ(l->value, std::string(S_PAYEE) +
                                 " becomes an AUTO payee of this mandate: the agent can then pay it without a pulse, up "
                                 "to 25 AUSD per payment and 50 AUSD in total (lifetime cap)");
      }
    }
    // firmware v1.2 review (low): a REFUSED co-sign never shows the AUTO payee line (nothing is signed, nothing is
    // whitelisted) - before the fix the golden co-sign with another vault as delegator showed it under REFUSED
    {
      M m = cosign_golden();
      m.set(5, cb(A(S_OTHER_VAULT)));
      CosignReq q;
      CHECK(parse_cosign(m, q));
      std::string e;
      CHECK(!check_cosign(q, pinned(), e) && e.find("NOT THIS DEVICE'S VAULT") == 0);
      Addr got;
      CHECK(!cosign_whitelists_payee(q, pinned(), got));
      CHECK(!cosign_may_whitelist_payee(q, pinned(), got));
      const Review rv2 = review_cosign(q, pinned());
      CHECK(!rv2.ok);
      CHECK(!any_value_contains(rv2, "becomes an AUTO payee"));
      CHECK(!any_value_contains(rv2, "AUTO payee"));
      check_review_rules(rv2, "refused co-sign: no AUTO payee line");
      // the same with a wrong chain / enforcer / an expiry too far: refused, no AUTO line either
      Context wrongChain = pinned();
      wrongChain.chainId = 143;
      CHECK(!cosign_whitelists_payee(q, wrongChain, got));
      CosignReq far;
      CHECK(parse_cosign(cosign_golden(), far));
      far.h.expiry = uint64_t(1) << 41;
      CHECK(!check_cosign(far, pinned(), e) && !cosign_whitelists_payee(far, pinned(), got));
      CHECK(!any_value_contains(review_cosign(far, pinned()), "AUTO payee"));
    }
    // firmware v1.2 review (low): a co-sign under a mandate the device does not remember (an older one, one revoked
    // since) can whitelist its payee on chain for that mandate's caps, which the device does not know: the review says
    // so ("may become an AUTO payee"); before the fix it showed only UNKNOWN MANDATE
    {
      const auto may_line = [](const Review& rv) -> const RLine* {
        for (const RLine& l : rv.lines)
          if (l.label.empty() && l.value.find(" may become an AUTO payee of mandate ") != std::string::npos) return &l;
        return nullptr;
      };
      struct May {
        const char* name;
        Bytes calldata;
        Addr target;
        uint64_t value;
        int ctxKind;  // 0 pinned() (the golden co-sign's mandate), 1 another remembered mandate, 2 revoked, 3 refused
        const char* payee;  // the payee of the line, nullptr = no line
      };
      const std::vector<May> ms = {
          {"remembered mandate", xfer, A(S_AUSD), 0, 0, nullptr},
          {"older mandate: AUSD transfer", xfer, A(S_AUSD), 0, 1, S_PAYEE},
          {"older mandate: transfer on another token", xfer, A(S_MUSD), 0, 1, S_PAYEE},
          {"older mandate: native send", Bytes(), payee, 1000, 1, S_PAYEE},
          {"older mandate: native send of 0", Bytes(), payee, 0, 1, nullptr},
          {"older mandate: transfer of 0", transfer_calldata(payee, 0), A(S_AUSD), 0, 1, nullptr},
          {"older mandate: transfer to 0", transfer_calldata(Addr(), 5), A(S_AUSD), 0, 1, nullptr},
          {"older mandate: approve", cat({HX("095ea7b3"), addr_word(payee), word64(5)}), A(S_AUSD), 0, 1, nullptr},
          {"revoked (unrelayed) mandate: AUSD transfer", xfer, A(S_AUSD), 0, 2, S_PAYEE},
          {"older mandate, refused (other vault)", xfer, A(S_AUSD), 0, 3, nullptr},
      };
      for (const May& c : ms) {
        Context x = pinned();
        if (c.ctxKind == 1 || c.ctxKind == 3) x.lastDelegationHash = fill32(0x23);
        if (c.ctxKind == 2) context_after_revoke(x);
        M m = cosign_golden();
        m.set(9, cb(c.calldata)).set(7, cb(c.target)).set(8, cb(word64(c.value))).del(13).del(15).del(16).del(14);
        if (c.ctxKind == 3) m.set(5, cb(A(S_OTHER_VAULT)));
        CosignReq q;
        if (!CHECK(parse_cosign(m, q))) continue;
        Addr got;
        const bool may = cosign_may_whitelist_payee(q, x, got);
        const Review rv2 = review_cosign(q, x);
        const RLine* l = may_line(rv2);
        if (!CHECK(may == (c.payee != nullptr) && (l != nullptr) == (c.payee != nullptr))) {
          std::printf("     case %s: predicate=%d line=%d\n", c.name, may ? 1 : 0, l ? 1 : 0);
          print_review(rv2);
        }
        if (c.ctxKind != 0) CHECK(!wl_line(rv2));  // never "becomes": the device does not know those terms
        check_review_rules(rv2, c.name);
        if (c.payee && l) {
          CHECK(got == A(c.payee) && l->tone == Tone::Warn);
          CHECK_EQ(l->value, std::string(c.payee) + " may become an AUTO payee of mandate " +
                                 to_hex(q.h.delegationHash.v, 32) +
                                 ": the agent could then pay it without a pulse, up to caps this device does not know");
          CHECK(any_value_contains(rv2, "UNKNOWN MANDATE - not the last mandate this device signed"));
        }
      }
    }
    // after a PANIC the remembered mandate is marked as killed (once relayed)
    Context p = pinned();
    context_after_panic(p, panic_next_epoch(p));
    CosignReq q;
    CHECK(parse_cosign(cosign_golden(), q));
    const Review rp = review_cosign(q, p);
    CHECK(any_value_contains(rp, "this device signed a PANIC after this mandate: once that PANIC is relayed, the chain "
                                 "refuses it"));
    CHECK(!any_value_contains(review_cosign(q, pinned()), "signed a PANIC after this mandate"));
  }
}

static void test_mandate_policy() {
  CHECK_SECTION("mandate: golden review screen (B2 + M4)");
  const Bytes xy = HX(pv::DEMO_P1_XY);
  const Context ctx = pinned();
  MandateReq r;
  if (!CHECK(parse_mandate(mandate_with(golden_caveats(xy)), r))) return;
  std::string err;
  if (!CHECK(check_mandate(r, ctx, xy.data(), err))) std::printf("     %s\n", err.c_str());
  const Review rv = review_mandate(r, ctx, xy.data());
  CHECK(rv.ok);
  check_review_rules(rv, "golden mandate");
  CHECK(same_lines(rv, {
                           {"Label", "Rent agent (companion)", Tone::Dim},
                           {"Agent id", "7 (companion)", Tone::Normal},
                           {"Delegate", S_DELEGATE, Tone::Normal},
                           {"Vault", std::string(S_VAULT) + " (derived from this device)", Tone::Good},
                           {"Chain", "Monad testnet (10143)", Tone::Normal},
                           {"Manager", S_DM, Tone::Normal},
                           {"Rule 1/9", "Pulse co-sign + spend caps", Tone::Normal},
                           {"Device key", "THIS DEVICE", Tone::Good},
                           {"Token", "AUSD - Agora USD", Tone::Good},
                           {"Token addr", S_AUSD, Tone::Normal},
                           {"Auto per tx", "25 AUSD", Tone::Normal},
                           {"Auto per period", "50 AUSD", Tone::Normal},
                           {"Period", "86400 s = 1 d (fixed windows from the first AUTO spend)", Tone::Normal},
                           {"Epoch", "3 (= panic floor)", Tone::Normal},
                           {"New payees", "need a pulse co-sign", Tone::Good},
                           {"Sentinel", S_SENTINEL, Tone::Good},
                           {"Enforcer", S_PULSE, Tone::Dim},
                           {"Rule 2/9", "ERC-20 total spend cap", Tone::Normal},
                           {"Token", "AUSD - Agora USD", Tone::Good},
                           {"Token addr", S_AUSD, Tone::Normal},
                           {"Total cap", "500 AUSD", Tone::Normal},
                           {"Enforcer", S_ERC20_AMOUNT, Tone::Dim},
                           {"Rule 3/9", "Valid time window", Tone::Normal},
                           {"Valid after", "2026-09-26 00:00:00 UTC", Tone::Normal},
                           {"Valid before", "2026-10-03 00:00:00 UTC", Tone::Normal},
                           {"Enforcer", S_TIMESTAMP, Tone::Dim},
                           {"Rule 4/9", "Only listed redeemers", Tone::Normal},
                           {"Redeemer 1/1", S_REDEEMER, Tone::Normal},
                           {"Enforcer", S_REDEEMER_ENF, Tone::Dim},
                           {"Rule 5/9", "Limited number of calls", Tone::Normal},
                           {"Max calls", "100", Tone::Normal},
                           {"Enforcer", S_LIMITED, Tone::Dim},
                           {"Rule 6/9", "Max MON value per call", Tone::Normal},
                           {"Max per call", "0 MON", Tone::Normal},
                           {"Enforcer", S_VALUE_LTE, Tone::Dim},
                           {"Rule 7/9", "MON total spend cap", Tone::Normal},
                           {"Total cap", "1 MON", Tone::Normal},
                           {"Enforcer", S_NATIVE_AMOUNT, Tone::Dim},
                           {"Rule 8/9", "ERC-20 cap per period", Tone::Normal},
                           {"Token", "AUSD - Agora USD", Tone::Good},
                           {"Token addr", S_AUSD, Tone::Normal},
                           {"Per period", "50 AUSD", Tone::Normal},
                           {"Period", "86400 s = 1 d", Tone::Normal},
                           {"Starts", "2026-09-26 00:00:00 UTC", Tone::Normal},
                           {"Enforcer", S_PERIOD, Tone::Dim},
                           {"Rule 9/9", "Only listed contracts", Tone::Normal},
                           {"Contract 1/2", S_AUSD, Tone::Normal},
                           {"Contract 2/2", S_PAYEE, Tone::Normal},
                           {"Enforcer", S_TARGETS, Tone::Dim},
                           {"Salt", "42", Tone::Dim},
                           {"Authority", "ROOT (new mandate, not a re-delegation)", Tone::Dim},
                       }));

  // the device records exactly the mandate it signed (M3: Context written only by the device's own mandates), its
  // pulse terms (v3, for the co-sign review) and that no panic covers it yet (PANIC FIRST)
  Context after = ctx;
  after.unpanickedMandates = false;
  after.pulseToken = Addr();
  after.period = 7;
  context_after_mandate(after, r);
  CHECK(after.lastDelegationHash == hash_delegation(r.d));
  CHECK(after.hasAgentId && after.agentId == 7);
  CHECK(after.unpanickedMandates);
  CHECK(after.pulseToken == A(S_AUSD) && after.period == 86400 && after.newPayeeNeedsHuman);
  CHECK(after.perTxAutoCap.low_u64() == 25000000 && after.periodAutoCap.low_u64() == 50000000);
  MandateReq noAgent = r;
  noAgent.hasAgentId = false;
  context_after_mandate(after, noAgent);
  CHECK(!after.hasAgentId && after.agentId == 0);
  {  // native terms, period 0, newPayeeNeedsHuman false: stored as signed; the review says "lifetime cap"
    std::vector<CborVal> v = golden_caveats(xy);
    v[0] = caveat(A(S_PULSE), pulse_terms(xy, Addr(), 7, 9, 0, 3, false, A(S_SENTINEL)));
    MandateReq q;
    CHECK(parse_mandate(mandate_with(v), q));
    std::string e;
    CHECK(check_mandate(q, ctx, xy.data(), e));
    Context n = ctx;
    context_after_mandate(n, q);
    CHECK(n.pulseToken.is_zero() && n.period == 0 && !n.newPayeeNeedsHuman && n.perTxAutoCap.low_u64() == 7 &&
          n.periodAutoCap.low_u64() == 9);
    const Review rq = review_mandate(q, ctx, xy.data());
    const RLine* l = find_line(rq, "Period");
    CHECK(l && l->value == "never resets (lifetime cap)");
    l = find_line(rq, "Metered");
    CHECK(l && l->value == "MON only (native)");
    // the stored context round-trips through the NVS blob with the terms
    uint8_t blob[CONTEXT_BLOB_SIZE];
    context_serialize(n, blob);
    Context back;
    CHECK(context_deserialize(blob, sizeof blob, back) && back.unpanickedMandates && back.periodAutoCap.low_u64() == 9);
  }
  {  // a mandate without an agent id: "none"
    MandateReq q = r;
    q.hasAgentId = false;
    const Review rn = review_mandate(q, ctx, xy.data());
    const RLine* l = find_line(rn, "Agent id");
    CHECK(l && l->value == "none");
  }

  CHECK_SECTION("mandate: refusals (B2 probes, pinned manager / vault, stale epoch, undecodable caveats)");
  struct Case {
    const char* name;
    std::vector<CborVal> cavs;
    int field;  // 0 = none, 2 chain, 3 manager, 4 delegate, 5 delegator
    Addr value;
    Context ctx;
    const char* want;
  };
  const std::vector<CborVal> g = golden_caveats(xy);
  const Bytes otherKey(64, 0x5C);
  std::vector<Case> cases;
  // review probe B2: a mandate whose only caveat is NonceEnforcer was signable (unlimited agent authority)
  cases.push_back({"NonceEnforcer only", {caveat(A(S_NONCE_ENF), word64(0))}, 0, Addr(), ctx,
                   "MANDATE WITHOUT PULSE CO-SIGN (no caveat uses the pinned PulseCosignEnforcer"});
  cases.push_back({"decodable caps, no pulse caveat", {g[1], g[2], g[4]}, 0, Addr(), ctx, "MANDATE WITHOUT PULSE CO-SIGN"});
  cases.push_back({"two pulse caveats", {g[0], g[1], g[0]}, 0, Addr(), ctx,
                   "MANDATE WITHOUT PULSE CO-SIGN (2 pulse co-sign caveats; exactly one is allowed)"});
  {
    Context c = ctx;
    c.pulseCosignEnforcer = A(S_OTHER_PULSE);
    cases.push_back({"stored enforcer differs from the firmware table", g, 0, Addr(), c,
                     "MANDATE WITHOUT PULSE CO-SIGN: PINNED ENFORCER DIFFERS FROM FIRMWARE TABLE"});
  }
  {
    Context c = ctx;
    c.vault = Addr();
    cases.push_back({"no vault pinned", g, 0, Addr(), c, "NO VAULT PINNED - pair again"});
  }
  {
    std::vector<CborVal> v = g;
    v[0] = caveat(A(S_PULSE), pulse_terms(otherKey, A(S_AUSD), 1, 1, 1, 3, true, A(S_SENTINEL)));
    cases.push_back({"pulse terms name another device key", v, 0, Addr(), ctx, "RULE 1: PULSE CO-SIGN KEY IS NOT THIS DEVICE"});
  }
  {
    std::vector<CborVal> v = g;
    v[0] = caveat(A(S_PULSE), pulse_terms(xy, A(S_AUSD), 1, 1, 1, 2, true, A(S_SENTINEL)));
    cases.push_back({"epoch below minEpoch", v, 0, Addr(), ctx, "RULE 1: STALE EPOCH 2"});
  }
  {
    std::vector<CborVal> v = g;
    v[0] = caveat(A(S_PULSE), pulse_terms(xy, A(S_AUSD), 1, 1, 1, 3, true, A(S_PAYEE)));
    cases.push_back({"sentinel not pinned", v, 0, Addr(), ctx, "RULE 1: SENTINEL IS NOT THE PINNED"});
  }
  {
    // fork review N1 probe: ctx.minEpoch = 3, the device's next panic is 4 -> epochs 4, 1000, 2^64-1 were accepted and
    // could never be killed by a panic from this device
    const uint64_t above[] = {4, 1000, ~0ull};
    for (uint64_t ep : above) {
      std::vector<CborVal> v = g;
      v[0] = caveat(A(S_PULSE), pulse_terms(xy, A(S_AUSD), 1, 1, 1, ep, true, A(S_SENTINEL)));
      cases.push_back({"epoch above the panic floor", v, 0, Addr(), ctx, "RULE 1: EPOCH "});
    }
    std::vector<CborVal> v = g;
    v[0] = caveat(A(S_PULSE), pulse_terms(xy, A(S_AUSD), 1, 1, 1, 3, true, A(S_SENTINEL)));
    v.insert(v.begin(), g[1]);
    Context c = ctx;
    c.minEpoch = 2;
    cases.push_back({"epoch above the floor (rule 2)", v, 0, Addr(), c, "RULE 2: EPOCH 3 IS ABOVE THE PANIC FLOOR 2"});
  }
  {
    // fork review m3: no sentinel pinned -> the terms may not name one (it could be an always-open contract)
    Context c = ctx;
    c.sentinel = Addr();
    cases.push_back({"sentinel named, none pinned", g, 0, Addr(), c, "RULE 1: SENTINEL NOT PINNED: "});
    std::vector<CborVal> v = g;
    v[0] = caveat(A(S_PULSE), pulse_terms(xy, A(S_AUSD), 1, 1, 1, 3, true, Addr()));
    cases.push_back({"no sentinel in the terms, one pinned", v, 0, Addr(), ctx, "RULE 1: SENTINEL IS NOT THE PINNED"});
  }
  {
    std::vector<CborVal> v = g;
    v.push_back(caveat(A(S_METHODS_ENF), HX("a9059cbb")));
    cases.push_back({"AllowedMethods (no decoder)", v, 0, Addr(), ctx,
                     "RULE 10: AllowedMethodsEnforcer 0x2c21fD0Cb9DC8445CB3fb0DC5E7Bb0Aca01842B5 is not supported"});
  }
  {
    std::vector<CborVal> v = g;
    v.push_back(caveat(A(S_NATIVE_PERIOD), Bytes(96, 1)));
    cases.push_back({"NativeTokenPeriodTransfer (no decoder)", v, 0, Addr(), ctx, "RULE 10: NativeTokenPeriodTransferEnforcer"});
  }
  {
    std::vector<CborVal> v = g;
    v.insert(v.begin(), caveat(A(S_PAYEE), Bytes()));
    cases.push_back({"unknown enforcer", v, 0, Addr(), ctx, "(computed below)"});
  }
  cases.push_back({"chain 143", g, 2, Addr(), ctx, "WRONG CHAIN"});
  cases.push_back({"companion-chosen manager", g, 3, A(S_PAYEE), ctx, "WRONG DELEGATION MANAGER"});
  {
    // v1.2 review (info): a stored manager other than the compiled-in one is refused like a stored enforcer / relay,
    // even when the request names that stored manager
    Context c = ctx;
    c.delegationManager = A(S_PAYEE);
    cases.push_back({"stored manager differs from the firmware table", g, 3, A(S_PAYEE), c,
                     "PINNED DELEGATION MANAGER DIFFERS FROM FIRMWARE TABLE - pair again"});
  }
  cases.push_back({"delegator is not the vault", g, 5, A(S_OTHER_VAULT), ctx, "NOT THIS DEVICE'S VAULT: delegator "});
  {
    Addr any;
    any.v[18] = 0x0a;
    any.v[19] = 0x11;
    cases.push_back({"ANY_DELEGATE", g, 4, any, ctx, "OPEN DELEGATION"});
  }
  cases.push_back({"not paired", g, 0, Addr(), Context(), "NOT PAIRED"});
  {
    Context c = ctx;
    c.chainId = 143;
    cases.push_back({"paired to another chain", g, 0, Addr(), c, "WRONG CHAIN"});
  }
  for (Case& c : cases) {
    M m = mandate_with(c.cavs);
    if (c.field == 2) m.set(2, cu(143));
    if (c.field >= 3) m.set(uint64_t(c.field), cb(c.value));
    MandateReq q;
    if (!CHECK(parse_mandate(m, q))) continue;
    std::string e;
    const bool ok = check_mandate(q, c.ctx, xy.data(), e);
    const std::string want = c.name == std::string("unknown enforcer")
                                 ? std::string("RULE 1: UNKNOWN ENFORCER ") + S_PAYEE
                                 : std::string(c.want);
    if (!CHECK(!ok && e.find(want) == 0)) std::printf("     case %s: ok=%d err=%s\n", c.name, ok ? 1 : 0, e.c_str());
    if (c.name == std::string("epoch above the panic floor"))
      CHECK(e.find("IS ABOVE THE PANIC FLOOR 3 (a panic from this device could not kill it; it must be exactly 3)") !=
            std::string::npos);
    const Review rv2 = review_mandate(q, c.ctx, xy.data());
    CHECK(!rv2.ok && rv2.refusal == e);
    check_review_rules(rv2, c.name);
  }
  // epoch == panic floor is the only accepted epoch (fork review N1); the review line says so
  {
    const uint64_t floors[] = {0, 3, 1ull << 62};
    for (uint64_t fl : floors) {
      std::vector<CborVal> v = g;
      v[0] = caveat(A(S_PULSE), pulse_terms(xy, A(S_AUSD), 1, 1, 1, fl, true, A(S_SENTINEL)));
      Context c = ctx;
      c.minEpoch = fl;
      MandateReq q;
      if (!CHECK(parse_mandate(mandate_with(v), q))) continue;
      std::string e;
      CHECK(check_mandate(q, c, xy.data(), e));
      const Review rv3 = review_mandate(q, c, xy.data());
      const RLine* l = find_line(rv3, "Epoch");
      CHECK(rv3.ok && l && l->tone == Tone::Normal && l->value.find("(= panic floor)") != std::string::npos);
      c.minEpoch = fl + 1;  // after a panic: stale, refused, red
      const Review rs = review_mandate(q, c, xy.data());
      l = find_line(rs, "Epoch");
      CHECK(!check_mandate(q, c, xy.data(), e) && l && l->tone == Tone::Bad);
      if (fl > 0) {
        c.minEpoch = fl - 1;  // above the floor: refused, red
        const Review ra = review_mandate(q, c, xy.data());
        l = find_line(ra, "Epoch");
        CHECK(!check_mandate(q, c, xy.data(), e) && l && l->tone == Tone::Bad &&
              l->value.find("ABOVE THE PANIC FLOOR") != std::string::npos);
      }
    }
  }
  // no sentinel pinned and none in the terms: allowed, shown as "no kill-switch lane" (amber)
  {
    std::vector<CborVal> v = g;
    v[0] = caveat(A(S_PULSE), pulse_terms(xy, A(S_AUSD), 1, 1, 1, 3, true, Addr()));
    Context c = ctx;
    c.sentinel = Addr();
    MandateReq q;
    CHECK(parse_mandate(mandate_with(v), q));
    std::string e;
    CHECK(check_mandate(q, c, xy.data(), e));
    const Review rn = review_mandate(q, c, xy.data());
    const RLine* l = find_line(rn, "Sentinel");
    CHECK(l && l->tone == Tone::Warn && l->value == "none - no kill-switch lane");
    MandateReq q2;
    CHECK(parse_mandate(mandate_with(g), q2));
    const Review rp = review_mandate(q2, c, xy.data());
    l = find_line(rp, "Sentinel");  // named, not pinned: red
    CHECK(l && l->tone == Tone::Bad && l->value == std::string(S_SENTINEL) + " (NOT PINNED)");
  }
  // firmware v1.2 (review probe "Vault choice"): without a pinned vault NOTHING is signed any more (v1.1 accepted any
  // delegator), and another vault is shown in red
  {
    Context c = ctx;
    c.vault = Addr();
    M m = mandate_with(g);
    m.set(5, cb(A(S_PAYEE)));
    MandateReq q;
    CHECK(parse_mandate(m, q));
    std::string e;
    CHECK(!check_mandate(q, c, xy.data(), e) && e.find("NO VAULT PINNED") == 0);
    const Review rv3 = review_mandate(q, ctx, xy.data());
    const RLine* l = find_line(rv3, "Vault");
    CHECK(l && l->value == S_PAYEE && l->tone == Tone::Bad && !rv3.ok);
  }
  // enforcer_name() (no context) knows the compiled-in Ripar enforcer on both chains; another address is only a
  // pulse co-sign enforcer on a chain without a compiled one, when it was pinned at pairing
  CHECK(enforcer_name(10143, A(S_PULSE)) != nullptr && enforcer_name(143, A(S_PULSE)) != nullptr);
  CHECK(enforcer_kind(10143, A(S_PULSE), ctx) == EnfKind::PulseCosign);
  CHECK(enforcer_kind(143, A(S_PULSE), ctx) == EnfKind::PulseCosign);
  CHECK(enforcer_kind(10143, A(S_PULSE), Context()) == EnfKind::PulseCosign);
  CHECK(enforcer_kind(1, A(S_PULSE), Context()) == EnfKind::Unknown);
  {
    Context other = ctx;
    other.pulseCosignEnforcer = A(S_OTHER_PULSE);
    CHECK(enforcer_kind(10143, A(S_OTHER_PULSE), other) == EnfKind::Unknown);  // the compiled one wins
    other.chainId = 777;
    CHECK(enforcer_kind(777, A(S_OTHER_PULSE), other) == EnfKind::PulseCosign);
  }

  CHECK_SECTION("mandate: Python vector (independent decoder) passes the policy");
  for (const pv::PolicyMandate& pm : pv::POLICY_MANDATE) {
    CborVal m;
    CHECK(cbor_decode(HX(pv::MANDATE[pm.mandate].cbor), m));
    MandateReq q;
    std::string e;
    if (!CHECK(parse_mandate_req(m, q, e))) continue;
    Context c;
    c.chainId = pm.chainId;
    c.delegationManager = A(pm.manager);
    c.pulseCosignEnforcer = A(pm.pulseEnforcer);
    c.vault = A(pm.vault);
    c.sentinel = A(pm.sentinel);
    c.minEpoch = pm.minEpoch;
    if (!CHECK(check_mandate(q, c, xy.data(), e))) std::printf("     %s: %s\n", pm.name, e.c_str());
    if (!CHECK_EQ(q.d.caveats.size(), pm.ndumps)) continue;
    for (size_t i = 0; i < pm.ndumps; i++) {
      CaveatView v;
      CHECK(decode_caveat(q.chainId, q.d.caveats[i], c, v, e));
      CHECK_EQ(dump(v), std::string(pm.dumps[i]));
    }
    const Review rv2 = review_mandate(q, c, xy.data());
    CHECK(rv2.ok);
    check_review_rules(rv2, pm.name);
    Context cmin = c;
    cmin.minEpoch = pm.minEpoch + 1;
    CHECK(!check_mandate(q, cmin, xy.data(), e) && e.find("STALE EPOCH") != std::string::npos);
    cmin.minEpoch = pm.minEpoch - 1;  // fork review N1: an epoch above the device's panic floor is refused too
    CHECK(!check_mandate(q, cmin, xy.data(), e) && e.find("IS ABOVE THE PANIC FLOOR") != std::string::npos);
  }
  // the other (random) Python mandates are all refused: random enforcers, no pulse caveat
  for (size_t i = 0; i < 5; i++) {
    CborVal m;
    CHECK(cbor_decode(HX(pv::MANDATE[i].cbor), m));
    MandateReq q;
    std::string e;
    CHECK(parse_mandate_req(m, q, e));
    CHECK(q.d.delegator == A(S_VAULT));  // v1.2 vectors: the demo device's derived vault
    Context c = ctx;
    c.chainId = q.chainId;
    c.vault = q.d.delegator;
    CHECK(!check_mandate(q, c, xy.data(), e) && e.find("MANDATE WITHOUT PULSE CO-SIGN") == 0);
    check_review_rules(review_mandate(q, c, xy.data()), pv::MANDATE[i].name);
  }
}

static void test_decoders() {
  CHECK_SECTION("caveat decoders: exact lengths + canonical words (M4)");
  const Bytes xy = HX(pv::DEMO_P1_XY);
  const Context ctx = pinned();
  const std::vector<CborVal> g = golden_caveats(xy);
  size_t checked = 0;
  for (const CborVal& cv : g) {
    Caveat c;
    std::memcpy(c.enforcer.v, cv.items[0].b.data(), 20);
    c.terms = cv.items[1].b;
    CaveatView v;
    std::string err;
    if (!CHECK(decode_caveat(10143, c, ctx, v, err))) std::printf("     %s\n", err.c_str());
    // one byte more / less is always refused (list enforcers: one byte off a multiple of 20)
    for (int delta : {-1, 1}) {
      Caveat d = c;
      if (delta < 0)
        d.terms.pop_back();
      else
        d.terms.push_back(0);
      CaveatView o;
      if (!CHECK(!decode_caveat(10143, d, ctx, o, err))) std::printf("     length %u accepted\n", unsigned(d.terms.size()));
      CHECK(!err.empty());
      checked++;
    }
    // any chain without the MetaMask deployment: refused
    CHECK(!decode_caveat(1, c, ctx, v, err));
  }
  CHECK_EQ(checked, size_t(18));
  // PulseCosign: every high word part must be zero, the bool 0/1
  Caveat pc;
  pc.enforcer = A(S_PULSE);
  pc.terms = g[0].items[1].b;
  static const size_t DIRTY[] = {64, 96, 128, 160, 187, 192, 215, 224, 254, 256, 267};
  for (size_t off : DIRTY) {
    Caveat d = pc;
    d.terms[off] = 1;
    CaveatView o;
    std::string err;
    if (!CHECK(!decode_caveat(10143, d, ctx, o, err))) std::printf("     dirty byte %u accepted\n", unsigned(off));
    CHECK(err.find("not canonical") != std::string::npos);
  }
  {
    Caveat d = pc;
    d.terms[255] = 2;  // bool = 2
    CaveatView o;
    std::string err;
    CHECK(!decode_caveat(10143, d, ctx, o, err));
    d.terms[255] = 0;
    CHECK(decode_caveat(10143, d, ctx, o, err) && !o.pulse.newPayeeNeedsHuman);
    PulseTerms pt;
    CHECK(decode_pulse_terms(pc.terms, pt, err));
    CHECK(pt.period == 86400 && pt.epoch == 3 && pt.newPayeeNeedsHuman && pt.token == A(S_AUSD));
    CHECK(pt.sentinel == A(S_SENTINEL) && pt.perTxAutoCap.low_u64() == 25000000 && pt.periodAutoCap.low_u64() == 50000000);
    CHECK(std::memcmp(pt.px.v, xy.data(), 32) == 0 && std::memcmp(pt.py.v, xy.data() + 32, 32) == 0);
  }
  // zero token, zero period, empty / too long address lists
  std::string err;
  CaveatView o;
  Caveat z;
  z.enforcer = A(S_ERC20_AMOUNT);
  z.terms = cat({Bytes(20, 0), word64(5)});
  CHECK(!decode_caveat(10143, z, ctx, o, err) && err.find("zero address") != std::string::npos);
  z.enforcer = A(S_PERIOD);
  z.terms = cat({ab(A(S_AUSD)), word64(5), word64(0), word64(0)});
  CHECK(!decode_caveat(10143, z, ctx, o, err) && err.find("duration is 0") != std::string::npos);
  z.enforcer = A(S_TARGETS);
  z.terms.clear();
  CHECK(!decode_caveat(10143, z, ctx, o, err));
  z.terms.assign(20 * 16, 0x42);
  CHECK(decode_caveat(10143, z, ctx, o, err) && o.addrs.size() == 16);
  z.terms.assign(20 * 17, 0x42);
  CHECK(!decode_caveat(10143, z, ctx, o, err) && err.find("more than 16") != std::string::npos);
  z.enforcer = A(S_TIMESTAMP);  // uint128 halves: the high half of "before" is part of the value, not padding
  z.terms = Bytes(32, 0xFF);
  CHECK(decode_caveat(10143, z, ctx, o, err));
  CHECK_EQ(u256_dec(o.before), std::string("340282366920938463463374607431768211455"));
  // NonceEnforcer / AllowedCalldata etc.: known names, refused with the reason
  z.enforcer = A(S_NONCE_ENF);
  z.terms = word64(0);
  CHECK(!decode_caveat(10143, z, ctx, o, err));
  CHECK_EQ(err, std::string("NonceEnforcer ") + S_NONCE_ENF + " is not supported (no terms decoder)");
  z.enforcer = Addr();
  CHECK(!decode_caveat(10143, z, ctx, o, err) && err.find("UNKNOWN ENFORCER") == 0);
}

static void test_deny_policy() {
  CHECK_SECTION("deny: pinned relay + agent (MINOR 7)");
  const Context ctx = pinned();
  DenyReq d;
  d.reqId = Bytes(16, 5);
  d.chainId = 10143;
  d.relay = A(S_RELAY);
  d.agentId = 7;
  d.requestHash = fill32(0x99);
  std::string err;
  CHECK(check_deny(d, ctx, err));
  DenyReq x = d;
  x.agentId = 8;  // the companion picks another agent to smear
  CHECK(!check_deny(x, ctx, err) && err.find("NOT THE PINNED AGENT: agent 8") == 0);
  x = d;
  x.relay = A(S_PAYEE);
  CHECK(!check_deny(x, ctx, err) && err.find("RELAY NOT PINNED") == 0);
  x = d;
  x.chainId = 143;
  CHECK(!check_deny(x, ctx, err) && err.find("WRONG CHAIN") == 0);
  Context c = ctx;
  c.hasAgentId = false;
  CHECK(!check_deny(d, c, err) && err.find("NO AGENT PINNED") == 0);
  c = ctx;
  c.relay = Addr();
  CHECK(!check_deny(d, c, err) && err.find("NO REPUTATION RELAY PINNED") == 0);
  c = ctx;
  c.relay = A(S_PAYEE);  // a stored relay that is not the compiled-in one (10143)
  CHECK(!check_deny(d, c, err) && err.find("PINNED RELAY DIFFERS FROM FIRMWARE TABLE") == 0);
  CHECK(!deny_from_cosign(CosignReq(), c, x, err) && err.find("CANNOT FILE A DENY: PINNED RELAY DIFFERS") == 0);
  c.chainId = 143;  // 143: the compiled-in relay too (firmware v1.2 review); a different stored one is refused
  x = d;
  x.chainId = 143;
  x.relay = A(S_PAYEE);
  CHECK(!check_deny(x, c, err) && err.find("PINNED RELAY DIFFERS FROM FIRMWARE TABLE") == 0);
  c.relay = A(S_RELAY_143);
  CHECK(!check_deny(x, c, err) && err.find("RELAY NOT PINNED") == 0);
  x.relay = A(S_RELAY_143);
  CHECK(check_deny(x, c, err));
  CHECK(deny_from_cosign(CosignReq(), c, x, err) && x.relay == A(S_RELAY_143) && x.chainId == 143);
  {
    Addr compiled;
    CHECK(compiled_relay(10143, compiled) && compiled == A(S_RELAY));
    CHECK(compiled_relay(143, compiled) && compiled == A(S_RELAY_143));
    CHECK(compiled_registry(10143, compiled) && compiled == A(S_REGISTRY));
    CHECK(compiled_registry(143, compiled) && compiled == A(S_REGISTRY));
  }
  for (const pv::Deny& v : pv::DENY) {  // companion requests: only the pinned relay + agent pass
    CborVal m;
    CHECK(cbor_decode(HX(v.cbor), m));
    DenyReq q;
    CHECK(parse_deny_req(m, q, err));
    const bool want = q.chainId == 10143 && q.relay == A(S_RELAY) && q.agentId == 7;
    CHECK_EQ(check_deny(q, ctx, err), want);
  }
  // deny from a co-sign review: built by the device, requestHash = hashStruct(HumanApproval) with presence 0
  CosignReq cr;
  CHECK(parse_cosign(cosign_golden(), cr));
  DenyReq built;
  CHECK(deny_from_cosign(cr, ctx, built, err));
  CHECK(built.reqId == cr.reqId && built.chainId == 10143 && built.relay == A(S_RELAY) && built.agentId == 7);
  HumanApproval h = cr.h;
  h.presenceHash = B32();
  CHECK(built.requestHash == hash_human_approval(h));
  CHECK(check_deny(built, ctx, err));
  const Review rv = review_deny(built, ctx, true);
  CHECK(rv.ok);
  check_review_rules(rv, "deny from cosign");
  const RLine* l = find_line(rv, "Request");
  CHECK(l && l->value == to_hex(built.requestHash.v, 32));
  CHECK(any_value_contains(rv, "computed on this device"));
  l = find_line(rv, "Agent id");
  CHECK(l && l->value == "7");
  c = ctx;
  c.hasAgentId = false;
  CHECK(!deny_from_cosign(cr, c, built, err));
  c = ctx;
  c.relay = Addr();
  CHECK(!deny_from_cosign(cr, c, built, err) && err == "CANNOT FILE A DENY: NO REPUTATION RELAY PINNED - pair again");
  CHECK(!deny_from_cosign(cr, Context(), built, err));
  const Review rv2 = review_deny(d, ctx, false);
  CHECK(any_value_contains(rv2, "from the companion (not checked)"));
}

static void test_device_initiated() {
  CHECK_SECTION("revoke / panic / reopen: pinned contracts + monotonic counters");
  Context ctx = pinned();
  std::string err;
  CHECK(check_revoke(ctx, err));
  CHECK(check_panic(ctx, err));
  CHECK(check_reopen(ctx, err));
  CHECK_EQ(panic_next_epoch(ctx), uint64_t(4));
  CHECK_EQ(reopen_next_nonce(ctx), uint64_t(5));
  Review rv = review_revoke(ctx);
  CHECK(rv.ok);
  check_review_rules(rv, "revoke");
  CHECK(find_line(rv, "Mandate") && find_line(rv, "Mandate")->value == MANDATE_HASH_HEX);
  // fork review m5: the enforcer shown is the one respond_revoke / respond_panic sign for (pinned_cosign_enforcer)
  {
    Addr signedFor;
    std::string e;
    CHECK(pinned_cosign_enforcer(ctx, ctx.chainId, signedFor, e));
    CHECK(find_line(rv, "Enforcer") && find_line(rv, "Enforcer")->value == addr_checksum(signedFor));
    CHECK(find_line(review_panic(ctx), "Enforcer")->value == addr_checksum(signedFor));
    Context none = ctx;  // paired, but no enforcer pinned and none compiled in (a chain without one): refused
    none.chainId = 777;
    none.pulseCosignEnforcer = Addr();
    const Review rn = review_revoke(none);
    CHECK(!rn.ok && find_line(rn, "Enforcer") && find_line(rn, "Enforcer")->value == "none pinned");
    check_review_rules(rn, "revoke, no enforcer");
    CHECK(find_line(review_panic(none), "Enforcer")->value == "none pinned");
  }
  rv = review_panic(ctx);
  CHECK(rv.ok && find_line(rv, "New min epoch")->value == "4");
  check_review_rules(rv, "panic");
  rv = review_reopen(ctx);
  CHECK(rv.ok && find_line(rv, "Nonce")->value == "5" && find_line(rv, "Vault")->value == S_VAULT);
  check_review_rules(rv, "reopen");
  context_after_panic(ctx, 4);
  CHECK_EQ(ctx.minEpoch, uint64_t(4));
  context_after_panic(ctx, 2);  // never back
  CHECK_EQ(ctx.minEpoch, uint64_t(4));
  context_after_reopen(ctx, 5);
  context_after_reopen(ctx, 1);
  CHECK_EQ(ctx.reopenNonce, uint64_t(5));
  // co-sign moves the device time forward only
  CosignReq cr;
  CHECK(parse_cosign(cosign_golden(), cr));
  context_after_cosign(ctx, cr);
  CHECK_EQ(ctx.notBefore, uint64_t(1790400000));
  cr.h.expiry = 1790000000;
  context_after_cosign(ctx, cr);
  CHECK_EQ(ctx.notBefore, uint64_t(1790400000));
  cr.h.expiry = 1ull << 40;
  context_after_cosign(ctx, cr);
  CHECK_EQ(ctx.notBefore, uint64_t(1790400000));
  // fork review m2 probe: 10 approved co-signs, each at the 7-day limit, moved the device time 70 days; now each one
  // moves it by at most NOT_BEFORE_STEP (1 day)
  CHECK_EQ(NOT_BEFORE_STEP, uint64_t(86400));
  for (int i = 0; i < 10; i++) {
    cr.h.expiry = effective_not_before(ctx.notBefore) + EXPIRY_WINDOW;
    CHECK(expiry_check(cr.h.expiry, ctx.notBefore, err));
    context_after_cosign(ctx, cr);
  }
  CHECK_EQ(ctx.notBefore, uint64_t(1790400000) + 10 * NOT_BEFORE_STEP);
  cr.h.expiry = ctx.notBefore + 3600;  // an ordinary co-sign a little ahead: followed exactly
  context_after_cosign(ctx, cr);
  CHECK_EQ(ctx.notBefore, uint64_t(1790400000) + 10 * NOT_BEFORE_STEP + 3600);
  {
    Context fresh;  // never paired with a clock: the step counts from the build floor
    cr.h.expiry = RIPAR_TIME_FLOOR + 5 * 86400;
    context_after_cosign(fresh, cr);
    CHECK_EQ(fresh.notBefore, uint64_t(RIPAR_TIME_FLOOR) + NOT_BEFORE_STEP);
  }
  // revoke: the mandate (and its terms) is forgotten, nothing else changes - PANIC FIRST stays set (earlier mandates
  // may still be live)
  {
    Context before = pinned(), after = before;
    context_after_revoke(after);
    CHECK(after.lastDelegationHash == B32() && after.pulseToken.is_zero() && after.period == 0 &&
          after.perTxAutoCap.is_zero() && after.periodAutoCap.is_zero() && !after.newPayeeNeedsHuman);
    CHECK(after.unpanickedMandates && after.hasAgentId && after.agentId == 7);
    after.lastDelegationHash = before.lastDelegationHash;
    after.pulseToken = before.pulseToken;
    after.perTxAutoCap = before.perTxAutoCap;
    after.periodAutoCap = before.periodAutoCap;
    after.period = before.period;
    after.newPayeeNeedsHuman = before.newPayeeNeedsHuman;
    uint8_t x[CONTEXT_BLOB_SIZE], y[CONTEXT_BLOB_SIZE];
    context_serialize(before, x);
    context_serialize(after, y);
    CHECK(std::memcmp(x, y, CONTEXT_BLOB_SIZE) == 0);
  }
  // panic: the flag is cleared only by an epoch above the device's floor (a signed panic always is)
  {
    Context p = pinned();
    CHECK(p.unpanickedMandates);
    context_after_panic(p, p.minEpoch);
    CHECK(p.unpanickedMandates && p.minEpoch == 3);
    context_after_panic(p, panic_next_epoch(p));
    CHECK(!p.unpanickedMandates && p.minEpoch == 4);
    CHECK(p.lastDelegationHash == fill32(0x22));  // remembered (revoke still possible), but killed on chain
  }

  Context c = pinned();
  c.lastDelegationHash = B32();
  CHECK(!check_revoke(c, err) && err.find("NO MANDATE TO REVOKE") == 0);
  CHECK(!review_revoke(c).ok);
  c = pinned();
  c.sentinel = Addr();
  CHECK(!check_reopen(c, err) && err.find("NO SENTINEL PINNED") == 0);
  c = pinned();
  c.vault = Addr();
  CHECK(!check_reopen(c, err) && err.find("NO VAULT PINNED") == 0);
  c = pinned();
  c.minEpoch = ~0ull;
  CHECK(!check_panic(c, err));
  c = pinned();
  c.reopenNonce = ~0ull;
  CHECK(!check_reopen(c, err));
  CHECK(!check_revoke(Context(), err) && err.find("NOT PAIRED") == 0);
  CHECK(!check_panic(Context(), err));
  CHECK(!check_reopen(Context(), err));
  check_review_rules(review_panic(Context()), "panic unpaired");
}

static void test_privy_review() {
  CHECK_SECTION("privy review: every value in full (M1)");
  const Bytes xy = HX(pv::DEMO_P1_XY);
  for (const pv::Privy& v : pv::PRIVY) {
    CborVal m;
    CHECK(cbor_decode(HX(v.cbor), m));
    PrivyReq r;
    std::string err;
    if (!CHECK(parse_privy_req(m, r, err))) continue;
    const Review rv = review_privy(r, xy.data());
    CHECK(rv.ok);
    check_review_rules(rv, v.name);
    std::vector<std::string> ids = {r.resourceId, r.appId};
    for (const std::string& s : r.policyIds) ids.push_back(s);
    for (const PrivySigner& s : r.signers) {
      ids.push_back(s.signerId);
      for (const std::string& p : s.overridePolicyIds) ids.push_back(p);
    }
    for (const std::string& s : r.userIds) ids.push_back(s);
    for (const std::string& s : r.keyQuorumIds) ids.push_back(s);
    for (const Bytes& k : r.publicKeyXY) ids.push_back(to_hex(k));
    if (r.hasDisplayName) ids.push_back(r.displayName);
    for (const std::string& id : ids) {
      bool found = false;
      for (const RLine& l : rv.lines) found = found || l.value == id || l.value == r.method + " " + r.path;
      if (!CHECK(found)) std::printf("     %s: value %s not shown in full\n", v.name, id.c_str());
    }
  }
  // key quorum with this device's key: marked; without it: warned
  CborVal m;
  CHECK(cbor_decode(HX(pv::PRIVY[5].cbor), m));
  PrivyReq r;
  std::string err;
  CHECK(parse_privy_req(m, r, err));
  Review rv = review_privy(r, xy.data());
  CHECK(find_line(rv, "Key 1/2") && find_line(rv, "Key 1/2")->value == "THIS DEVICE");
  CHECK(!any_value_contains(rv, "NOT IN THE NEW KEY LIST"));
  const Bytes other(64, 7);
  rv = review_privy(r, other.data());
  CHECK(any_value_contains(rv, "THIS DEVICE IS NOT IN THE NEW KEY LIST"));
  // removing every policy is shown in red
  CHECK(cbor_decode(HX(pv::PRIVY[4].cbor), m));
  CHECK(parse_privy_req(m, r, err));
  rv = review_privy(r, xy.data());
  CHECK(find_line(rv, "Policies") && find_line(rv, "Policies")->tone == Tone::Bad);
}

static void test_fingerprint() {
  CHECK_SECTION("address fingerprint: 32 bits (MINOR 3)");
  unsigned maxIdx = 0;
  for (int i = 0; i < 64; i++) {
    Addr a;
    for (int j = 0; j < 20; j++) a.v[j] = uint8_t(i * 7 + j * 13);
    uint8_t idx[4], k[32];
    addr_fingerprint(a, idx);
    keccak256(a.v, 20, k);
    CHECK_EQ_BYTES(idx, k, 4);
    for (uint8_t x : idx) maxIdx = x > maxIdx ? x : maxIdx;
  }
  CHECK(maxIdx > 15);  // the old nibble fingerprint never exceeded 15
}

int main() {
  test_context_blob();
  test_tokens();
  test_time();
  test_pair_policy();
  test_cosign_policy();
  test_mandate_policy();
  test_decoders();
  test_deny_policy();
  test_device_initiated();
  test_privy_review();
  test_fingerprint();
  CHECK_SECTION("vector sanity");
  CHECK_EQ(g_bad, 0);
  return CHECK_SUMMARY();
}
