// JSON views of an emulated device (emu_core.h Device::state_json / context_json / nvs_json).
//
// state_json() is what a companion needs to draw the 320x240 screen the way ui.cpp does ("display": the last frame
// drawn, with the review rows exactly as paged on the device) plus the live device state around it.
#include <cstdio>

#include "abi.h"
#include "emu_core.h"
#include "json_out.h"
#include "review.h"
#include "tokens.h"

namespace ripar {
namespace emu {

namespace {

// review.h Tone names for the review colours ("accent" is the device menu's selection colour)
const char* tone_name(UiColor c) {
  switch (c) {
    case UiColor::Good:
      return "good";
    case UiColor::Warn:
      return "warn";
    case UiColor::Bad:
      return "bad";
    case UiColor::Dim:
      return "dim";
    case UiColor::Accent:
      return "accent";
    default:
      return "normal";
  }
}

void color(JsonOut& j, const char* k, UiColor c) {
  j.kv(k, ui_color_name(c));
  std::string kh(k);
  kh += "Hex";
  j.kv(kh.c_str(), ui_color_hex(c));
}

void addr_or_null(JsonOut& j, const char* k, const Addr& a) {
  j.key(k);
  if (a.is_zero())
    j.null();
  else
    j.str(addr_checksum(a));
}

void context_fields(JsonOut& j, const Context& c) {
  j.kv("paired", c.paired());
  j.key("chainId").u64s(c.chainId);
  j.kv("chain", c.paired() ? chain_text(c.chainId) : std::string());
  addr_or_null(j, "delegationManager", c.delegationManager);
  addr_or_null(j, "pulseCosignEnforcer", c.pulseCosignEnforcer);
  addr_or_null(j, "sentinel", c.sentinel);
  addr_or_null(j, "relay", c.relay);
  addr_or_null(j, "registry", c.registry);
  addr_or_null(j, "vault", c.vault);
  j.key("lastDelegationHash");
  if (c.lastDelegationHash == B32())
    j.null();
  else
    j.str(to_hex(c.lastDelegationHash.v, 32));
  j.kv("hasAgentId", c.hasAgentId);
  j.key("agentId").u64s(c.agentId);
  j.key("minEpoch").u64s(c.minEpoch);
  j.key("reopenNonce").u64s(c.reopenNonce);
  j.key("notBefore").u64s(c.notBefore);
  j.kv("notBeforeUtc", utc_text(effective_not_before(c.notBefore)));
  // (layout v3) the pulse terms of the remembered mandate (review_cosign's AUTO payee line) and PANIC FIRST
  j.kv("pulseToken", addr_checksum(c.pulseToken));  // the zero address = the native coin (or no mandate remembered)
  j.kv("perTxAutoCap", u256_dec(c.perTxAutoCap)).kv("periodAutoCap", u256_dec(c.periodAutoCap));
  j.kv("period", c.period).kv("newPayeeNeedsHuman", c.newPayeeNeedsHuman);
  j.kv("unpanickedMandates", c.unpanickedMandates);
}

void rows(JsonOut& j, const std::vector<UiRow>& rs) {
  j.key("rows").arr();
  for (const UiRow& r : rs) {
    j.obj().kv("label", r.label).kv("value", r.value).kv("tone", tone_name(r.color));
    color(j, "color", r.color);
    j.kv("full", r.full).kv("last", r.last).end_obj();
  }
  j.end_arr();
}

}  // namespace

std::string Device::context_json() const {
  JsonOut j;
  j.obj();
  j.kv("version", unsigned(CONTEXT_VERSION));  // NVS layout version (context.h), CONTEXT_BLOB_SIZE bytes
  uint8_t blob[CONTEXT_BLOB_SIZE];
  context_serialize(ctx_, blob);
  j.kv("hex", to_hex(blob, sizeof blob, false));  // the RAM context (store_save_context blob layout)
  j.key("stored");
  if (store_.blob().empty())
    j.null();
  else
    j.str(to_hex(store_.blob(), false));  // what the emulated NVS holds (persist this one)
  context_fields(j, ctx_);
  j.end_obj();
  return j.text();
}

std::string Device::nvs_json() const {
  JsonOut j;
  j.obj().kv("emulator", true);
  j.key("seed");
  if (keys_.seed())
    j.str(to_hex(keys_.seed(), 32, false));
  else
    j.null();
  j.key("context");
  if (store_.blob().empty())
    j.null();
  else
    j.str(to_hex(store_.blob(), false));
  j.end_obj();
  return j.text();
}

std::string Device::state_json() const {
  JsonOut j;
  const Screen s = fsm_.screen();
  j.obj();
  j.kv("emulator", true).kv("emulatorId", EMULATOR_ID).kv("firmwareId", to_hex(fwid_, 8, false));
  j.kv("testMode", test_).kv("nowMs", now_);
  // the app thread: busy pushing the last frame to the LCD (kFramePushMs after each draw) or stalled (injected)
  j.key("app").obj().kv("busy", appBusy_).kv("busyUntilMs", appBusy_ ? appBusyUntil_ : 0u).kv("stalled", appStalled_);
  j.kv("passes", passes_).end_obj();
  j.key("hardware").obj().kv("camera", haveCam_).kv("pulseSensor", havePulse_).end_obj();
  j.kv("screen", screen_name(s)).kv("job", job_name(fsm_.job()));
  j.kv("keyDown", io_.key_down()).kv("keyRaw", io_.raw());
  j.kv("battery", io_.battery).kv("paired", ctx_.paired());
  j.kv("k1Short", keys_.k1_address().is_zero() ? std::string() : short_addr(k1_));
  j.kv("k1", k1_.is_zero() ? std::string() : addr_checksum(k1_));
  // the vault derived from K1 (vault.h vault_address: MetaMask SimpleFactory CREATE2, salt 0), the only one it pins
  j.kv("vault", k1_.is_zero() ? std::string() : addr_checksum(vault_));
  j.kv("p1", to_hex(p1xy_, 64, false));
  j.key("selftest").obj().kv("passed", selftestPassed_).kv("report", selftestReport_).end_obj();

  // ---- the LCD: the last frame drawn
  const Frame& f = frame_;
  j.key("display").obj();
  j.kv("seq", f.seq).kv("drawnAtMs", f.at);
  switch (f.kind) {
    case Frame::Boot:
      j.kv("kind", "boot").kv("title", f.title);
      j.key("lines").arr();
      for (const std::string& l : f.lines) j.str(l);
      j.end_arr();
      break;
    case Frame::Home:
      j.kv("kind", "home").kv("k1Short", f.k1short).kv("battery", f.battery).kv("paired", f.paired);
      j.kv("badge", f.paired ? "PAIRED" : "NOT PAIRED");
      color(j, "badgeColor", f.paired ? UiColor::Good : UiColor::Warn);
      j.key("hints").arr().str("press = SCAN").str("2s = PAIR").str("5s = PANIC").end_arr();
      break;
    case Frame::Message:
      j.kv("kind", "message").kv("title", f.title);
      color(j, "color", f.color);
      j.key("lines").arr();
      for (const std::string& l : f.lines) j.str(l);
      j.end_arr();
      break;
    case Frame::Scan: {
      j.kv("kind", "scan").kv("hint", f.hint).kv("progress", f.progress);
      char pct[8];
      const float p = f.progress > 1.0f ? 1.0f : f.progress;
      std::snprintf(pct, sizeof pct, "%d%%", int(p * 100.0f + 0.5f));
      j.kv("progressText", f.progress > 0.0f ? std::string(pct) : std::string());
      break;
    }
    case Frame::Review:
      j.kv("kind", "review").kv("title", f.review.title);
      rows(j, f.review.rows);
      j.kv("firstRow", f.review.firstRow).kv("rowsShown", f.review.rowsShown).kv("totalRows", f.review.totalRows);
      j.kv("visibleRows", REVIEW_VISIBLE_ROWS);
      j.kv("moreAbove", f.review.moreAbove).kv("moreBelow", f.review.moreBelow).kv("footer", f.review.footer);
      break;
    case Frame::Pulse:
      j.kv("kind", "pulse").kv("title", f.title);
      j.kv("bpmText", f.bpmText).kv("beatsText", f.beatsText).kv("elapsedText", f.elapsedText);
      j.kv("status", f.status);
      color(j, "statusColor", f.statusColor);
      j.kv("progress", f.pulse.progress).kv("passed", f.pulse.passed).kv("finger", f.pulse.finger);
      j.kv("heartBig", f.heartBig);
      color(j, "ringColor", f.pulse.passed ? UiColor::Good : UiColor::Accent);
      break;
    case Frame::Qr:
      j.kv("kind", "qr").kv("title", f.title).kv("footer", f.footer).kv("text", f.qr.text);
      j.kv("version", f.qr.version).kv("ecc", std::string(1, f.qr.ecc)).kv("scale", f.qr.scale);
      break;
  }
  j.end_obj();

  // ---- the review being shown / measured for
  j.key("review");
  if (s == Screen::Review || s == Screen::Pulse || s == Screen::Armed) {
    j.obj().kv("job", job_name(fsm_.job())).kv("title", review_.title).kv("ok", review_.ok);
    j.kv("refusal", review_.refusal).kv("allSeen", fsm_.review_all_seen()).kv("row", fsm_.review_row());
    j.kv("footerMore", footMore_).kv("footerEnd", footEnd_);
    j.key("lines").arr();
    for (const UiLine& l : lines_) {
      j.obj().kv("label", l.label).kv("value", l.value).kv("tone", tone_name(l.color));
      color(j, "color", l.color);
      j.end_obj();
    }
    j.end_arr().end_obj();
  } else {
    j.null();
  }

  // ---- device menu
  j.key("menu");
  if (s == Screen::Menu)
    j.obj().kv("index", fsm_.menu_index()).key("items").arr().str("REVOKE the last mandate").str("REOPEN the agent lane").str("BACK").end_arr().end_obj();
  else
    j.null();

  // ---- pulse: the last pulse_update() of this measurement (what the gate saw), and the synthetic finger
  j.key("pulse").obj();
  j.kv("sensorOn", pulseHw_.running()).kv("finger", pulse_.finger).kv("passed", pulse_.passed);
  j.kv("bpm", pulse_.bpm).kv("beats", pulse_.beats).kv("minBeats", PulseConfig().minBeats);
  j.kv("progress", pulse_.progress).kv("jitter", pulse_.jitter).kv("elapsedMs", pulse_.elapsedMs);
  j.kv("irDC", pulse_.irDC).kv("redDC", pulse_.redDC);
  {
    static const char* const kFaults[] = {"none", "stall", "unplug"};
    // the MAX30102 itself: fault injected, sampling, FIFO fill level + OVF counter, the last pulse_update() read
    j.key("sensor").obj().kv("fault", kFaults[int(pulseHw_.fault()) % 3]).kv("sampling", pulseHw_.sampling());
    j.kv("fifo", pulseHw_.fifo_level()).kv("ovf", pulseHw_.ovf()).kv("lastRead", pulseHw_.last_read());
    j.kv("lastLost", pulseHw_.last_lost()).kv("reads", pulseHw_.reads()).end_obj();
  }
  j.end_obj();
  {
    const PpgParams& p = pulseHw_.synth.params();
    static const char* const kShapes[] = {"ppg", "sine", "square", "flat"};
    j.key("fingerInput").obj().kv("on", p.on).kv("bpm", p.bpm).kv("amplitude", p.amplitude).kv("noise", p.noise);
    j.kv("hrv", p.hrv).kv("shape", kShapes[int(p.shape) & 3]).end_obj();
  }

  // ---- scanning
  j.key("scan").obj().kv("active", s == Screen::Scan).kv("hint", ui_sanitize(scanHint_)).kv("progress", scanProgress_);
  j.kv("received", unsigned(dec_.received_pure())).kv("seqLen", unsigned(dec_.seq_len())).end_obj();

  // ---- the QR on screen (Qr / PairQr): the upper-cased UR as ui_qr() encodes it
  j.key("qr");
  if ((s == Screen::Qr || s == Screen::PairQr) && !qrText_.empty()) {
    const UiQr q = ui_qr_model(qrText_);
    j.obj().kv("text", q.text).kv("title", qrTitle_).kv("footer", qrFooter_).kv("signed", s == Screen::Qr);
    j.kv("version", q.version).kv("ecc", std::string(1, q.ecc)).kv("fits", q.fits).end_obj();
  } else {
    j.null();
  }

  // ---- the message on screen
  j.key("message");
  if (s == Screen::Message || s == Screen::Fail || s == Screen::HomeHold) {
    j.obj();
    if (s == Screen::Message) {
      j.kv("title", msgTitle_).kv("body", msgBody_);
      color(j, "color", msgColor_);
    } else {
      j.kv("title", f.title).kv("body", f.body);
      color(j, "color", f.color);
    }
    j.end_obj();
  } else {
    j.null();
  }

  const EmuIo::Buzz& b = io_.buzz();
  j.key("buzz").obj().kv("ok", b.ok).kv("err", b.err).kv("beat", b.beat).kv("last", b.last).kv("lastAtMs", b.lastAt).end_obj();

  j.key("context").obj();
  context_fields(j, ctx_);
  j.end_obj();
  j.key("store").obj().kv("saves", store_.saves()).kv("failWrites", store_.failWrites);
  j.kv("contextHex", store_.blob().empty() ? std::string() : to_hex(store_.blob(), false)).end_obj();
  j.kv("signatures", signatures_).kv("lastOutput", lastOutput_);
  j.key("serial").arr();
  for (const std::string& l : serial_) j.str(l);
  j.end_arr();
  j.end_obj();
  return j.text();
}

}  // namespace emu
}  // namespace ripar
