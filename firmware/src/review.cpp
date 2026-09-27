// Review screen lines + strict caveat-terms decoders (include/review.h). Portable C++14 (host + device).
//
// Caveat terms layouts = getTermsInfo() of MetaMask delegation-framework v1.3.0 (security review M4), decoded with
// EXACT lengths (the device is stricter than abi.decode, which ignores trailing bytes):
//   ERC20TransferAmountEnforcer       token address (20) || maxTokens uint256 (32)                        52 bytes
//   NativeTokenTransferAmountEnforcer allowance uint256                                                    32 bytes
//   ValueLteEnforcer                  maxValue uint256                                                     32 bytes
//   LimitedCallsEnforcer              limit uint256                                                        32 bytes
//   ERC20PeriodTransferEnforcer       token (20) || periodAmount (32) || periodDuration (32) || start (32) 116 bytes
//   TimestampEnforcer                 afterThreshold uint128 (16) || beforeThreshold uint128 (16)          32 bytes
//   AllowedTargetsEnforcer, RedeemerEnforcer   n packed 20-byte addresses, 1 <= n <= 16                   20n bytes
//   Ripar PulseCosignEnforcer         abi.encode(Terms) - 9 canonical 32-byte words                       288 bytes
#include "review.h"

#include <cstring>

#include "abi.h"
#include "tokens.h"

namespace ripar {

namespace {

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

std::string pad(uint64_t v, size_t w) {
  std::string s = u64_text(v);
  while (s.size() < w) s = "0" + s;
  return s;
}

std::string A(const Addr& a) { return addr_checksum(a); }
std::string H(const B32& b) { return to_hex(b.v, 32); }

bool zero_bytes(const uint8_t* p, size_t n) {
  for (size_t i = 0; i < n; i++)
    if (p[i]) return false;
  return true;
}

bool is_max(const U256& a) {
  for (uint8_t b : a.v)
    if (b != 0xFF) return false;
  return true;
}

U256 u256_at(const uint8_t* p, size_t n) {  // big-endian, n <= 32
  U256 r;
  U256::from_be(p, n, r);
  return r;
}

Addr addr_at(const uint8_t* p) {
  Addr a;
  std::memcpy(a.v, p, 20);
  return a;
}

std::string amount_text(const TokenView& tv, const U256& a) {
  std::string s = token_amount(tv, a);
  if (is_max(a)) s += " (UNLIMITED)";
  return s;
}

std::string time_text(const U256& t) {
  if (t.fits_u64()) return utc_text(t.low_u64());
  return u256_dec(t) + " (unix s)";
}

TokenView asset_view(uint64_t chainId, bool native, const Addr& token) {
  TokenView tv;
  std::string e;
  token_resolve(chainId, native, token, nullptr, nullptr, tv, e);  // no companion claims: always resolves
  return tv;
}

class Out {
 public:
  explicit Out(Review& r) : r_(r) {}
  void add(const std::string& label, const std::string& value, Tone t = Tone::Normal) {
    r_.lines.push_back(RLine{label, value, t});
  }
  void refused(bool ok, const std::string& err) {
    r_.ok = ok;
    r_.refusal = ok ? std::string() : err;
    if (!ok) add("REFUSED", err, Tone::Bad);
  }
  // ERC-20 asset lines: verified table entry, or the UNKNOWN TOKEN warning; always the full contract address
  void token(const TokenView& tv) {
    if (tv.listed)
      add("Token", tv.symbol + " - " + tv.name, Tone::Good);
    else
      add("Token", "UNKNOWN TOKEN - decimals unverified", Tone::Bad);
    add("Token addr", A(tv.token));
    if (!tv.listed && !tv.symbol.empty()) add("Symbol", ascii_text(tv.symbol) + " (companion)", Tone::Warn);
  }

 private:
  Review& r_;
};

std::string of(size_t i, size_t n) { return u64_text(i + 1) + "/" + u64_text(n); }

// PulseCosignEnforcer AUTO period (contracts/SPEC.md v1.2 "AUTO windows"): 0 = a lifetime cap; otherwise fixed windows
// anchored at the first AUTO spend (so up to 2x the cap can leave within seconds across a window boundary)
std::string auto_period_text(uint32_t period) {
  if (period == 0) return "never resets (lifetime cap)";
  return duration_text(U256::from_u64(period)) + " (fixed windows from the first AUTO spend)";
}

// The PulseCosignEnforcer a revoke / panic is signed for: exactly what respond.cpp uses (policy.h
// pinned_cosign_enforcer, which prefers the compiled-in address), never just the stored one (security review m5).
std::string signing_enforcer(const Context& ctx) {
  Addr e;
  std::string why;
  return pinned_cosign_enforcer(ctx, ctx.chainId, e, why) ? A(e) : std::string("none pinned");
}

}  // namespace

// ===================================================================================================== formatting
std::string utc_text(uint64_t t) {
  // civil_from_days (H. Hinnant), days since 1970-01-01, unsigned (t >= 0); exact for every uint64
  const uint64_t days = t / 86400, sod = t % 86400;
  const uint64_t z = days + 719468;
  const uint64_t era = z / 146097;
  const uint64_t doe = z - era * 146097;
  const uint64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  uint64_t y = yoe + era * 400;
  const uint64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  const uint64_t mp = (5 * doy + 2) / 153;
  const uint64_t d = doy - (153 * mp + 2) / 5 + 1;
  const uint64_t m = mp < 10 ? mp + 3 : mp - 9;
  if (m <= 2) y++;
  return pad(y, 4) + "-" + pad(m, 2) + "-" + pad(d, 2) + " " + pad(sod / 3600, 2) + ":" + pad(sod % 3600 / 60, 2) +
         ":" + pad(sod % 60, 2) + " UTC";
}

std::string duration_text(const U256& seconds) {
  if (!seconds.fits_u64()) return u256_dec(seconds) + " s";
  const uint64_t n = seconds.low_u64();
  std::string o = u64_text(n) + " s";
  if (n < 60) return o;
  o += " =";
  const uint64_t d = n / 86400, h = n % 86400 / 3600, mi = n % 3600 / 60, s = n % 60;
  if (d) o += " " + u64_text(d) + " d";
  if (h) o += " " + u64_text(h) + " h";
  if (mi) o += " " + u64_text(mi) + " min";
  if (s) o += " " + u64_text(s) + " s";
  return o;
}

std::string ascii_text(const std::string& s) {
  std::string o;
  o.reserve(s.size());
  for (size_t i = 0; i < s.size(); i++) {
    const uint8_t b = uint8_t(s[i]);
    if (b >= 0x20 && b < 0x7F) {
      o += char(b);
      continue;
    }
    o += '?';
    if (b >= 0xC0)  // UTF-8 lead byte: one '?' for the whole sequence
      while (i + 1 < s.size() && (uint8_t(s[i + 1]) & 0xC0) == 0x80) i++;
  }
  return o;
}

// ===================================================================================================== decoders
bool decode_pulse_terms(const Bytes& t, PulseTerms& out, std::string& err) {
  if (t.size() != 288) {
    err = "Pulse co-sign terms must be 288 bytes (got " + u64_text(t.size()) + ")";
    return false;
  }
  const uint8_t* w = t.data();
  const char* bad = nullptr;
  if (!zero_bytes(w + 64, 12))
    bad = "token";
  else if (!zero_bytes(w + 96, 16))
    bad = "perTxAutoCap";
  else if (!zero_bytes(w + 128, 16))
    bad = "periodAutoCap";
  else if (!zero_bytes(w + 160, 28))
    bad = "period";
  else if (!zero_bytes(w + 192, 24))
    bad = "epoch";
  else if (!zero_bytes(w + 224, 31) || w[255] > 1)
    bad = "newPayeeNeedsHuman";
  else if (!zero_bytes(w + 256, 12))
    bad = "sentinel";
  if (bad) {
    err = std::string("Pulse co-sign terms: word ") + bad + " is not canonical ABI";
    return false;
  }
  PulseTerms p;
  std::memcpy(p.px.v, w, 32);
  std::memcpy(p.py.v, w + 32, 32);
  p.token = addr_at(w + 76);
  p.perTxAutoCap = u256_at(w + 96, 32);
  p.periodAutoCap = u256_at(w + 128, 32);
  p.period = (uint32_t(w[188]) << 24) | (uint32_t(w[189]) << 16) | (uint32_t(w[190]) << 8) | uint32_t(w[191]);
  uint64_t e = 0;
  for (int i = 0; i < 8; i++) e = (e << 8) | w[216 + i];
  p.epoch = e;
  p.newPayeeNeedsHuman = w[255] == 1;
  p.sentinel = addr_at(w + 268);
  out = p;
  return true;
}

bool decode_caveat(uint64_t chainId, const Caveat& c, const Context& ctx, CaveatView& out, std::string& err) {
  CaveatView v;
  v.kind = enforcer_kind(chainId, c.enforcer, ctx);
  const Bytes& t = c.terms;
  const uint8_t* p = t.data();
  const std::string what = enforcer_kind_text(v.kind);
  auto need = [&](size_t n) -> bool {
    if (t.size() == n) return true;
    err = what + ": terms must be " + u64_text(n) + " bytes (got " + u64_text(t.size()) + ")";
    return false;
  };
  switch (v.kind) {
    case EnfKind::Unknown: {
      const char* rn = enforcer_refused_name(chainId, c.enforcer);
      err = rn ? std::string(rn) + " " + A(c.enforcer) + " is not supported (no terms decoder)"
               : "UNKNOWN ENFORCER " + A(c.enforcer);
      return false;
    }
    case EnfKind::PulseCosign:
      if (!decode_pulse_terms(t, v.pulse, err)) return false;
      break;
    case EnfKind::ERC20TransferAmount:
      if (!need(52)) return false;
      v.token = addr_at(p);
      v.amount = u256_at(p + 20, 32);
      break;
    case EnfKind::NativeTokenTransferAmount:
    case EnfKind::ValueLte:
    case EnfKind::LimitedCalls:
      if (!need(32)) return false;
      v.amount = u256_at(p, 32);
      break;
    case EnfKind::ERC20PeriodTransfer:
      if (!need(116)) return false;
      v.token = addr_at(p);
      v.amount = u256_at(p + 20, 32);
      v.duration = u256_at(p + 52, 32);
      v.start = u256_at(p + 84, 32);
      if (v.duration.is_zero()) {
        err = what + ": the period duration is 0";
        return false;
      }
      break;
    case EnfKind::Timestamp:
      if (!need(32)) return false;
      v.after = u256_at(p, 16);
      v.before = u256_at(p + 16, 16);
      break;
    case EnfKind::AllowedTargets:
    case EnfKind::Redeemer: {
      if (t.empty() || t.size() % 20) {
        err = what + ": terms must be 1.." + u64_text(CAVEAT_MAX_ADDRS) + " packed 20-byte addresses (got " +
              u64_text(t.size()) + " bytes)";
        return false;
      }
      if (t.size() / 20 > CAVEAT_MAX_ADDRS) {
        err = what + ": more than " + u64_text(CAVEAT_MAX_ADDRS) + " addresses (too many to review)";
        return false;
      }
      for (size_t i = 0; i < t.size(); i += 20) v.addrs.push_back(addr_at(p + i));
      break;
    }
  }
  if ((v.kind == EnfKind::ERC20TransferAmount || v.kind == EnfKind::ERC20PeriodTransfer) && v.token.is_zero()) {
    err = what + ": the token is the zero address";
    return false;
  }
  out = v;
  err.clear();
  return true;
}

// ===================================================================================================== screens
Review review_pair(const PairReq& r, const Context& cur, const Addr& k1) {
  Review rv;
  rv.title = "PAIR DEVICE";
  Out o(rv);
  std::string err;
  o.refused(check_pair(r, cur, k1, err), err);
  // what will be pinned (compiled-in addresses fill the gaps, exactly as context_after_pair does)
  const Context next = context_after_pair(cur, r, k1);
  if (cur.paired()) {
    o.add("", "REPLACES the current pairing (" + chain_text(cur.chainId) + ")", Tone::Warn);
    // security review N2: every pinned value this pairing changes, old -> new, in red
    size_t changes = 0;
    const auto change = [&](const char* what, const std::string& was, const std::string& now) {
      if (was == now) return;
      o.add("CHANGES", std::string(what) + ": " + was + " -> " + now, Tone::Bad);
      changes++;
    };
    const auto AZ = [](const Addr& a) { return a.is_zero() ? std::string("not set") : A(a); };
    change("Chain", chain_text(cur.chainId), chain_text(next.chainId));
    change("Manager", AZ(cur.delegationManager), AZ(next.delegationManager));
    change("Co-sign enforcer", AZ(cur.pulseCosignEnforcer), AZ(next.pulseCosignEnforcer));
    change("Sentinel", AZ(cur.sentinel), AZ(next.sentinel));
    change("Relay", AZ(cur.relay), AZ(next.relay));
    change("Registry", AZ(cur.registry), AZ(next.registry));
    change("Vault", AZ(cur.vault), AZ(next.vault));
    if (!(cur.lastDelegationHash == B32()) && next.lastDelegationHash == B32()) {
      // PANIC FIRST (check_pair): allowed only when a panic signed after it already killed it
      o.add("CHANGES",
            "FORGETS mandate " + H(cur.lastDelegationHash) +
                (cur.unpanickedMandates ? " (still live: PANIC first)" : " (killed once this device's last PANIC is relayed)"),
            Tone::Bad);
      changes++;
    }
    if (changes == 0) o.add("", "no pinned contract changes", Tone::Dim);
    // PANIC FIRST lets the scope move once the device SIGNED a panic; the chain refuses the old mandates only once that
    // panic is RELAYED, which the device cannot see (v1.2 review): say so before the user confirms the move
    if (!cur.unpanickedMandates && cur.minEpoch > 0 && !same_mandate_scope(cur, next))
      o.add("PANIC", "mandates signed on " + chain_text(cur.chainId) + " die only once this device's PANIC (min epoch " +
                         u64_text(cur.minEpoch) + ") is relayed there - this device cannot check that. Confirm only if " +
                         "the on-chain min epoch of this device key is >= " + u64_text(cur.minEpoch),
            Tone::Bad);
  }
  o.add("Chain", chain_text(r.chainId), chain_find(r.chainId) ? Tone::Normal : Tone::Bad);
  o.add("Owner (K1)", A(k1));
  Addr fw;
  const bool regFw = compiled_registry(r.chainId, fw) && fw == r.registry;
  o.add("Registry", A(r.registry) + (regFw ? " (firmware table)" : ""), regFw ? Tone::Good : Tone::Normal);
  const bool mgrFw = compiled_delegation_manager(r.chainId, fw) && fw == next.delegationManager;
  if (next.delegationManager.is_zero())
    o.add("Manager", "not set - mandates will be refused", Tone::Warn);
  else
    o.add("Manager", A(next.delegationManager) + (mgrFw ? " (MetaMask v1.3.0)" : ""), mgrFw ? Tone::Good : Tone::Normal);
  const bool enfFw = compiled_cosign_enforcer(r.chainId, fw) && fw == next.pulseCosignEnforcer;
  if (next.pulseCosignEnforcer.is_zero())
    o.add("Co-sign", "not set - mandates and co-signs will be refused", Tone::Warn);
  else
    o.add("Co-sign", A(next.pulseCosignEnforcer) + (enfFw ? " (firmware table)" : ""), enfFw ? Tone::Good : Tone::Normal);
  o.add("Sentinel", next.sentinel.is_zero() ? std::string("not set - no reopen, mandates without a sentinel lane") : A(next.sentinel),
        next.sentinel.is_zero() ? Tone::Warn : Tone::Normal);
  const bool relayFw = compiled_relay(r.chainId, fw) && fw == next.relay;
  if (next.relay.is_zero())
    o.add("Relay", "not set - no deny reports", Tone::Warn);
  else
    o.add("Relay", A(next.relay) + (relayFw ? " (firmware table)" : ""), relayFw ? Tone::Good : Tone::Normal);
  // v1.2: the vault is derived on the device from K1 (vault.h); key 8 can only confirm it (check_pair)
  o.add("Vault", A(next.vault) + " (derived from this device)", Tone::Good);
  if (!r.vault.is_zero() && r.vault != next.vault) o.add("Key 8 vault", A(r.vault) + " (NOT THIS DEVICE'S VAULT)", Tone::Bad);
  const uint64_t nb = effective_not_before(cur.notBefore);
  if (!r.hasNow)
    o.add("Time", "not given - device time stays " + utc_text(nb), Tone::Warn);
  else if (r.now > nb + PAIR_TIME_JUMP_WARN)  // security review m2: a big jump widens the co-sign expiry window
    o.add("Time", utc_text(r.now) + " (companion clock) - MORE THAN 30 DAYS AFTER the device time " + utc_text(nb),
          Tone::Bad);
  else
    o.add("Time", utc_text(r.now) + " (companion clock - check it)", Tone::Warn);
  // monotonic counters: a companion floor (keys 10 / 11) can only raise them (security review N1)
  const bool epochUp = next.minEpoch > cur.minEpoch, nonceUp = next.reopenNonce > cur.reopenNonce;
  o.add("Min epoch",
        u64_text(next.minEpoch) + (epochUp ? " RAISED from " + u64_text(cur.minEpoch) + " (companion floor)" : "") +
            " - mandates must use it, next PANIC signs " + u64_text(panic_next_epoch(next)),
        epochUp ? Tone::Warn : Tone::Dim);
  o.add("Reopen nonce",
        u64_text(next.reopenNonce) +
            (nonceUp ? " RAISED from " + u64_text(cur.reopenNonce) + " (companion floor)" : "") +
            " - next REOPEN signs " + u64_text(reopen_next_nonce(next)),
        nonceUp ? Tone::Warn : Tone::Dim);
  o.add("Signs", "BindDevice(K1, P1 key) with P1 and K1", Tone::Dim);
  return rv;
}

Review review_cosign(const CosignReq& r, const Context& ctx) {
  Review rv;
  rv.title = "CO-SIGN PAYMENT";
  Out o(rv);
  std::string err;
  o.refused(check_cosign(r, ctx, err), err);
  const TokenView& tv = r.token;
  const std::string tok = tv.listed ? tv.symbol : std::string("UNKNOWN TOKEN");
  switch (r.call.kind) {
    case Erc20Call::None:
      o.add("Action", "Send " + (tv.listed ? tv.symbol : std::string("native coin")) + " (native)");
      o.add("Amount", amount_text(tv, r.h.value));
      o.add("To", A(r.h.target));
      if (!tv.listed) o.add("Asset", "native coin of an UNKNOWN CHAIN - decimals unverified", Tone::Bad);
      break;
    case Erc20Call::Transfer:
      o.add("Action", "Send " + tok + " (ERC-20 transfer)");
      o.add("Amount", amount_text(tv, r.call.amount));
      o.add("To", A(r.call.to));
      o.token(tv);
      break;
    case Erc20Call::TransferFrom: {
      const bool fromVault = r.call.from == r.h.delegator;
      o.add("Action", "Pull " + tok + " (ERC-20 transferFrom)", fromVault ? Tone::Normal : Tone::Warn);
      o.add("Amount", amount_text(tv, r.call.amount));
      o.add("From", A(r.call.from) + (fromVault ? " (vault)" : " (NOT the vault)"), fromVault ? Tone::Normal : Tone::Warn);
      o.add("To", A(r.call.to));
      o.token(tv);
      break;
    }
    case Erc20Call::Approve:
      o.add("Action", "APPROVE " + tok + " spending (ERC-20 approve)", Tone::Warn);
      o.add("Allowance", amount_text(tv, r.call.amount), Tone::Warn);
      o.add("Spender", A(r.call.to));
      o.token(tv);
      break;
    default: {
      const size_t n = r.calldata.size();
      o.add("Action", "UNKNOWN CALL " + to_hex(r.calldata.data(), n < 4 ? n : 4) + " (" + u64_text(n) + " bytes)",
            Tone::Bad);
      o.add("Contract", A(r.h.target));
      break;
    }
  }
  if (!tv.listed && r.hasDecimals) o.add("Decimals", u64_text(uint64_t(r.decimals)) + " (companion, unverified)", Tone::Warn);
  if (r.call.kind != Erc20Call::None && !r.h.value.is_zero())
    o.add("Native value", amount_text(asset_view(r.chainId, true, Addr()), r.h.value) + " ALSO SENT", Tone::Bad);
  o.add("Chain", chain_text(r.chainId));
  const bool vaultPinned = !ctx.vault.is_zero() && r.h.delegator == ctx.vault;
  o.add("Vault", A(r.h.delegator) + (vaultPinned ? " (derived from this device)" : ""),
        vaultPinned ? Tone::Good : Tone::Bad);
  o.add("Redeemer", A(r.h.redeemer));
  const bool known = !(ctx.lastDelegationHash == B32()) && r.h.delegationHash == ctx.lastDelegationHash;
  o.add("Mandate", H(r.h.delegationHash), known ? Tone::Good : Tone::Warn);
  if (!known) o.add("", "UNKNOWN MANDATE - not the last mandate this device signed", Tone::Warn);
  if (known && !ctx.unpanickedMandates)
    o.add("", "this device signed a PANIC after this mandate: once that PANIC is relayed, the chain refuses it",
          Tone::Warn);
  // PulseCosignEnforcer v1.2: a co-signed payment to a new payee whitelists it for the AUTO path of this mandate
  // (only when the co-sign can be signed at all: cosign_whitelists_payee checks check_cosign, v1.2 review)
  Addr payee;
  if (cosign_may_whitelist_payee(r, ctx, payee))
    o.add("", A(payee) + " may become an AUTO payee of mandate " + H(r.h.delegationHash) +
                  ": the agent could then pay it without a pulse, up to caps this device does not know",
          Tone::Warn);
  if (cosign_whitelists_payee(r, ctx, payee)) {
    const TokenView mt = asset_view(r.chainId, ctx.pulseToken.is_zero(), ctx.pulseToken);
    o.add("", A(payee) + " becomes an AUTO payee of this mandate: the agent can then pay it without a pulse, up to " +
                  amount_text(mt, ctx.perTxAutoCap) + " per payment and " + amount_text(mt, ctx.periodAutoCap) +
                  (ctx.period == 0 ? " in total (lifetime cap)"
                                   : " per " + duration_text(U256::from_u64(ctx.period)) +
                                         " window (fixed windows from the first AUTO spend)"),
          Tone::Warn);
  }
  o.add("Expires", utc_text(r.h.expiry));
  o.add("Nonce", u256_dec(r.h.nonce));
  if (r.hasBudget) o.add("Budget left", amount_text(tv, r.budgetLeft) + " (companion)", Tone::Dim);
  if (r.ai.present) o.add("AI says", ascii_text(r.ai.text) + " (companion)", Tone::Dim);
  if (r.ai.hasClaims) {
    const char* kind = r.call.kind == Erc20Call::None       ? "native send"
                       : r.call.kind == Erc20Call::Transfer ? "ERC-20 transfer"
                                                            : nullptr;
    if (!kind)
      o.add("AI claims", "NOT CHECKED - only a transfer can match", Tone::Warn);
    else if (r.aiMatches)
      o.add("AI claims", std::string("MATCH - recipient, token and amount (") + kind + ")", Tone::Good);
    else
      o.add("AI claims", "MISMATCH - the agent's claim differs from this request", Tone::Bad);
  }
  if (r.risk.present)
    o.add("Risk", ascii_text(r.risk.src) + ": " + ascii_text(r.risk.category) + " / " + ascii_text(r.risk.label) +
                      ", " + u64_text(r.risk.ageDays) + " days old (companion)",
          Tone::Warn);
  o.add("Enforcer", A(r.enforcer), Tone::Dim);
  return rv;
}

Review review_mandate(const MandateReq& r, const Context& ctx, const uint8_t p1xy[64]) {
  Review rv;
  rv.title = "SIGN MANDATE";
  Out o(rv);
  std::string err;
  o.refused(check_mandate(r, ctx, p1xy, err), err);
  if (!r.label.empty()) o.add("Label", ascii_text(r.label) + " (companion)", Tone::Dim);
  o.add("Agent id", r.hasAgentId ? u64_text(r.agentId) + " (companion)" : std::string("none"));
  o.add("Delegate", A(r.d.delegate));
  const bool vaultPinned = !ctx.vault.is_zero() && r.d.delegator == ctx.vault;
  o.add("Vault", A(r.d.delegator) + (vaultPinned ? " (derived from this device)" : ""),
        vaultPinned ? Tone::Good : Tone::Bad);
  o.add("Chain", chain_text(r.chainId));
  o.add("Manager", A(r.manager));
  const size_t n = r.d.caveats.size();
  for (size_t i = 0; i < n; i++) {
    const Caveat& c = r.d.caveats[i];
    CaveatView v;
    std::string e;
    const bool ok = decode_caveat(r.chainId, c, ctx, v, e);
    o.add("Rule " + of(i, n), ok ? enforcer_kind_text(v.kind) : "REFUSED", ok ? Tone::Normal : Tone::Bad);
    if (!ok) {
      o.add("", e, Tone::Bad);
    } else {
      switch (v.kind) {
        case EnfKind::PulseCosign: {
          const PulseTerms& t = v.pulse;
          const bool mine = p1xy && std::memcmp(t.px.v, p1xy, 32) == 0 && std::memcmp(t.py.v, p1xy + 32, 32) == 0;
          if (mine)
            o.add("Device key", "THIS DEVICE", Tone::Good);
          else
            o.add("Device key", "OTHER KEY " + to_hex(t.px.v, 32) + to_hex(t.py.v, 32, false), Tone::Bad);
          const TokenView tv = asset_view(r.chainId, t.token.is_zero(), t.token);
          if (t.token.is_zero())
            o.add("Metered", (tv.listed ? tv.symbol : std::string("native coin")) + " only (native)");
          else
            o.token(tv);
          o.add("Auto per tx", amount_text(tv, t.perTxAutoCap));
          o.add("Auto per period", amount_text(tv, t.periodAutoCap));
          o.add("Period", auto_period_text(t.period));
          o.add("Epoch",
                u64_text(t.epoch) + (t.epoch < ctx.minEpoch   ? " (STALE)"
                                     : t.epoch > ctx.minEpoch ? " (ABOVE THE PANIC FLOOR " + u64_text(ctx.minEpoch) + ")"
                                                              : " (= panic floor)"),
                t.epoch == ctx.minEpoch ? Tone::Normal : Tone::Bad);
          o.add("New payees", t.newPayeeNeedsHuman ? "need a pulse co-sign" : "AUTO path allowed",
                t.newPayeeNeedsHuman ? Tone::Good : Tone::Warn);
          if (t.sentinel.is_zero())
            o.add("Sentinel", "none - no kill-switch lane", t.sentinel == ctx.sentinel ? Tone::Warn : Tone::Bad);
          else
            o.add("Sentinel", A(t.sentinel) + (t.sentinel == ctx.sentinel ? "" : " (NOT PINNED)"),
                  t.sentinel == ctx.sentinel ? Tone::Good : Tone::Bad);
          break;
        }
        case EnfKind::ERC20TransferAmount: {
          const TokenView tv = asset_view(r.chainId, false, v.token);
          o.token(tv);
          o.add("Total cap", amount_text(tv, v.amount));
          break;
        }
        case EnfKind::NativeTokenTransferAmount:
          o.add("Total cap", amount_text(asset_view(r.chainId, true, Addr()), v.amount));
          break;
        case EnfKind::ValueLte:
          o.add("Max per call", amount_text(asset_view(r.chainId, true, Addr()), v.amount));
          break;
        case EnfKind::LimitedCalls:
          o.add("Max calls", u256_dec(v.amount));
          break;
        case EnfKind::ERC20PeriodTransfer: {
          const TokenView tv = asset_view(r.chainId, false, v.token);
          o.token(tv);
          o.add("Per period", amount_text(tv, v.amount));
          o.add("Period", duration_text(v.duration));
          o.add("Starts", time_text(v.start));
          break;
        }
        case EnfKind::Timestamp:
          o.add("Valid after", v.after.is_zero() ? std::string("no start limit") : time_text(v.after));
          o.add("Valid before", v.before.is_zero() ? std::string("no end") : time_text(v.before),
                v.before.is_zero() ? Tone::Warn : Tone::Normal);
          break;
        case EnfKind::AllowedTargets:
        case EnfKind::Redeemer:
          for (size_t j = 0; j < v.addrs.size(); j++)
            o.add((v.kind == EnfKind::AllowedTargets ? "Contract " : "Redeemer ") + of(j, v.addrs.size()),
                  A(v.addrs[j]));
          break;
        default:
          break;
      }
    }
    o.add("Enforcer", A(c.enforcer), Tone::Dim);
  }
  o.add("Salt", u256_dec(r.d.salt), Tone::Dim);
  o.add("Authority", "ROOT (new mandate, not a re-delegation)", Tone::Dim);
  return rv;
}

Review review_deny(const DenyReq& r, const Context& ctx, bool fromCosign) {
  Review rv;
  rv.title = "DENY + REPORT AGENT";
  Out o(rv);
  std::string err;
  o.refused(check_deny(r, ctx, err), err);
  o.add("Agent id", u64_text(r.agentId));
  o.add("Request", H(r.requestHash));
  o.add("", fromCosign ? "hash of the co-sign request just reviewed (computed on this device)"
                       : "request hash from the companion (not checked)",
        fromCosign ? Tone::Good : Tone::Warn);
  o.add("Effect", "negative ERC-8004 feedback for agent " + u64_text(r.agentId), Tone::Warn);
  o.add("Relay", A(r.relay));
  o.add("Chain", chain_text(r.chainId));
  o.add("Pulse", "optional (a deny can only restrict)", Tone::Dim);
  return rv;
}

Review review_privy(const PrivyReq& r, const uint8_t p1xy[64]) {
  Review rv;
  rv.title = "PRIVY AUTHORIZATION";
  Out o(rv);
  const bool known = r.kind == PrivyReq::WalletUpdate || r.kind == PrivyReq::KeyQuorumUpdate;
  o.refused(known, "NOT AN ALLOWED PRIVY REQUEST");
  const bool wallet = r.kind == PrivyReq::WalletUpdate;
  o.add("Action", wallet ? "Update agent wallet signers / policies" : "Update key quorum", Tone::Warn);
  o.add("Method", r.method + " " + r.path);
  o.add(wallet ? "Wallet id" : "Quorum id", r.resourceId);
  o.add("App id", r.appId);
  if (!r.idempotencyKey.empty()) o.add("Idempotency", r.idempotencyKey, Tone::Dim);
  if (wallet) {
    if (r.hasPolicyIds) {
      if (r.policyIds.empty()) o.add("Policies", "NONE - removes every policy", Tone::Bad);
      for (size_t i = 0; i < r.policyIds.size(); i++) o.add("Policy " + of(i, r.policyIds.size()), r.policyIds[i]);
    }
    if (r.hasSigners) {
      if (r.signers.empty()) o.add("Signers", "NONE - removes every extra signer", Tone::Warn);
      for (size_t i = 0; i < r.signers.size(); i++) {
        const PrivySigner& s = r.signers[i];
        o.add("Signer " + of(i, r.signers.size()), s.signerId, Tone::Warn);
        if (!s.hasOverride)
          o.add("", "policies: wallet default", Tone::Dim);
        else if (s.overridePolicyIds.empty())
          o.add("", "policies: NONE (override with no policy)", Tone::Bad);
        for (size_t j = 0; j < s.overridePolicyIds.size(); j++)
          o.add("Override " + of(j, s.overridePolicyIds.size()), s.overridePolicyIds[j]);
      }
    }
  } else {
    if (r.hasPublicKeys) {
      bool me = false;
      for (size_t i = 0; i < r.publicKeyXY.size(); i++) {
        const Bytes& xy = r.publicKeyXY[i];
        const bool mine = p1xy && xy.size() == 64 && std::memcmp(xy.data(), p1xy, 64) == 0;
        me = me || mine;
        o.add("Key " + of(i, r.publicKeyXY.size()), mine ? "THIS DEVICE" : "OTHER P-256 KEY",
              mine ? Tone::Good : Tone::Warn);
        o.add("", to_hex(xy), Tone::Dim);
      }
      if (!me) o.add("", "THIS DEVICE IS NOT IN THE NEW KEY LIST", Tone::Bad);
    }
    if (r.hasThreshold) o.add("Threshold", u64_text(r.threshold) + " signature(s) required");
    if (r.hasDisplayName) o.add("Name", r.displayName);
    if (r.hasUserIds) {
      if (r.userIds.empty()) o.add("Users", "none");
      for (size_t i = 0; i < r.userIds.size(); i++) o.add("User " + of(i, r.userIds.size()), r.userIds[i]);
    }
    if (r.hasKeyQuorumIds) {
      if (r.keyQuorumIds.empty()) o.add("Quorums", "none");
      for (size_t i = 0; i < r.keyQuorumIds.size(); i++)
        o.add("Quorum " + of(i, r.keyQuorumIds.size()), r.keyQuorumIds[i]);
    }
  }
  o.add("Signs", "sha256 of the exact JSON (" + u64_text(r.json.size()) + " bytes) with P1", Tone::Dim);
  return rv;
}

Review review_revoke(const Context& ctx) {
  Review rv;
  rv.title = "REVOKE MANDATE";
  Out o(rv);
  std::string err;
  o.refused(check_revoke(ctx, err), err);
  o.add("Mandate", H(ctx.lastDelegationHash));
  o.add("Effect", "the agent can no longer use this mandate; the device then forgets it", Tone::Warn);
  o.add("Enforcer", signing_enforcer(ctx));
  o.add("Chain", chain_text(ctx.chainId));
  return rv;
}

Review review_panic(const Context& ctx) {
  Review rv;
  rv.title = "PANIC";
  Out o(rv);
  std::string err;
  o.refused(check_panic(ctx, err), err);
  const uint64_t e = panic_next_epoch(ctx);
  o.add("New min epoch", u64_text(e));
  o.add("Effect", "kills every mandate with epoch below " + u64_text(e), Tone::Bad);
  o.add("Enforcer", signing_enforcer(ctx));
  o.add("Chain", chain_text(ctx.chainId));
  o.add("Pulse", "not needed (panic can only restrict)", Tone::Dim);
  return rv;
}

Review review_reopen(const Context& ctx) {
  Review rv;
  rv.title = "REOPEN AGENT LANE";
  Out o(rv);
  std::string err;
  o.refused(check_reopen(ctx, err), err);
  o.add("Vault", A(ctx.vault));
  o.add("Nonce", u64_text(reopen_next_nonce(ctx)));
  o.add("Effect", "re-opens the agent's AUTO path after a sentinel stop", Tone::Warn);
  o.add("Sentinel", A(ctx.sentinel));
  o.add("Chain", chain_text(ctx.chainId));
  return rv;
}

}  // namespace ripar
