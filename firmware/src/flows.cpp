// Ripar Wallet application (security review B1): one state machine from power-on to the response QR.
//
//   BOOT -> SELFTEST  keys_selftest(): crypto.cpp against published vectors and mbedTLS. A failure is terminal
//                     (Screen::Fail): nothing is ever signed.
//        -> KEYS      first run only: 64 TRNG bytes + raw MAX30102 samples + camera frames + timing, hashed into the
//                     `extra` input of keys_create() (which adds its own TRNG draw); then the self-test again, now
//                     covering the new device keys.
//        -> HOME      Short = SCAN; hold 2 s -> HOMEHOLD ("RELEASE = PAIRING QR"): released before 5 s = unsigned
//                     pairing QR (keys only), held on to 5 s = PANIC.
//        -> SCAN      viewfinder + multipart progress (UrDecoder); Long2s = cancel.
//        -> PARSE     req_type_from_ur + parse_*_req (format) and review_*() (policy.h check_* against the pinned
//                     Context); a format error is shown with the parser's exact reason, a policy refusal as the
//                     first review line (REFUSED + reason) and SIGN is never armed for it.
//        -> REVIEW    review.h lines, paged by display row (M2); SIGN can only be armed once the last row was drawn.
//                     On a co-sign review Long2s = DENY (built on the device: policy.h deny_from_cosign).
//        -> PULSE     pulse_start() only after the review was shown; pulse_stop() whenever Pulse / Armed is left.
//        -> ARMED     a Short press signs ONLY in the loop pass in which pulse_update().passed is true (Fsm::step
//                     gets both in one FsmIn; no remembered flag), and only a press that BEGAN on Armed: on every
//                     screen change the key queue is flushed and a press still down is swallowed (io_flush), and
//                     Fsm ignores key events until the key was seen up on the new screen.
//        -> SIGN      a fresh TRNG salt is drawn and the pulse evidence is read (after the `passed` check); then
//                     respond.h (portable, host-tested byte for byte against the Python reference) repeats the policy
//                     check, sets presenceHash = presence_hash(ev, salt), rebuilds the digest from the SAME parsed
//                     struct that produced the review, signs, builds the response and the new context.
//        -> QR        ur_encode(response); the CBOR, evidence, salt and signature buffers are wiped once the QR text
//                     exists, and the QR text when the screen is left. Short = HOME.
//
// The screen / key rules are the portable, host-tested state machine in include/fsm.h (test/host/test_fsm.cpp).
// This file is its device driver: one FsmIn per loop pass, then the side effects (camera, pulse sensor, drawing,
// parsing, signing, NVS). Every screen except HOME returns to HOME after 120 s without a key press.
//
// Context (include/context.h) is only replaced by a context_after_*() result, and only after the confirmation or
// signature it records; pairing, mandate and reopen responses are withheld when the new context cannot be saved
// (respond.h Save).
#include <Arduino.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "cbor.h"
#include "device.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "fsm.h"
#include "hashes.h"
#include "policy.h"
#include "protocol.h"
#include "respond.h"
#include "review.h"
#include "ur.h"

namespace ripar {
namespace {

constexpr uint32_t kScanDrawMs = 60;    // viewfinder refresh
constexpr uint32_t kPulseDrawMs = 80;   // pulse screen refresh
constexpr uint32_t kHomeDrawMs = 2000;  // battery refresh on the home screen

#ifndef RIPAR_LED_CHALLENGE
#define RIPAR_LED_CHALLENGE 0  // 1 = also require the MAX30102 LED-drive liveness challenge before arming (unverified)
#endif

Fsm g_fsm;

// ---- device identity + pinned context
Context g_ctx;  // from NVS; replaced only by a saved context_after_*() result
Addr g_k1;
uint8_t g_p1xy[64];
uint8_t g_fwid[8];
bool g_havePulse = false, g_haveCam = false;
std::string g_failText;

// ---- the request / device action being reviewed (one at a time)
PairReq g_pair;
CosignReq g_cosign;
MandateReq g_mandate;
DenyReq g_deny;
PrivyReq g_privy;
Review g_review;
std::vector<ReviewLine> g_lines;
std::string g_footMore, g_footEnd;

// ---- scanning
UrDecoder g_dec;
std::string g_scanHint;
float g_scanProgress = 0.0f;

// ---- pulse (drawing only: the gate uses the value polled in the same pass, see app_loop)
PulseResult g_pulse;

// ---- output / messages
std::string g_qrText, g_qrTitle, g_qrFooter;
std::string g_msgTitle, g_msgBody;
uint16_t g_msgColor = UI_TEXT;

// ---- pulse evidence + salt of the signature being made: wiped as soon as the response QR text is built (the
// signature buffers live in respond.cpp and are wiped there)
uint8_t g_salt[16], g_ev[12];

bool g_dirty = true;
bool g_changed = false;  // a screen change happened in this pass: flush the keys again after the new screen is drawn
uint32_t g_lastDraw = 0;

// ================================================================================================= small helpers
void wipe(void* p, size_t n) {
  volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
  while (n--) *v++ = 0;
}
void wipe_bytes(Bytes& b) {
  if (!b.empty()) wipe(b.data(), b.size());
  b.clear();
}
void wipe_str(std::string& s) {
  if (!s.empty()) wipe(&s[0], s.size());
  s.clear();
}
void wipe_sig_buffers() {
  wipe(g_salt, sizeof g_salt);
  wipe(g_ev, sizeof g_ev);
}

uint16_t tone_color(Tone t) {
  switch (t) {
    case Tone::Good:
      return UI_GOOD;
    case Tone::Warn:
      return UI_WARN;
    case Tone::Bad:
      return UI_BAD;
    case Tone::Dim:
      return UI_DIM;
    default:
      return UI_TEXT;
  }
}

// Drops queued key events; swallowHeld also makes a press that is still down produce nothing more (io_flush), so a
// press only ever acts on the screen that was displayed when it began. Not for HomeHold: the hold that entered it must
// still deliver its Hold5s (PANIC).
void drain_keys(bool swallowHeld) { io_flush(swallowHeld); }

std::string u64_text(uint64_t v) {
  char b[24];
  std::snprintf(b, sizeof b, "%llu", static_cast<unsigned long long>(v));
  return b;
}

// first 8 bytes of the SHA-256 of the running app image (the hash esptool appends to the image)
void firmware_id(uint8_t out[8]) {
  uint8_t sha[32] = {0};
  const esp_partition_t* part = esp_ota_get_running_partition();
  if (!part || esp_partition_get_sha256(part, sha) != ESP_OK) std::memset(sha, 0, sizeof sha);
  std::memcpy(out, sha, 8);
}

void clear_job() {
  g_pair = PairReq();
  g_cosign = CosignReq();
  g_mandate = MandateReq();
  g_deny = DenyReq();
  g_privy = PrivyReq();
  g_review = Review();
  g_lines.clear();
  g_footMore.clear();
  g_footEnd.clear();
}

// ================================================================================================= screen changes
// Exit / entry side effects of every screen change (made by Fsm::step or by the driver).
void on_change(Screen from, Screen to) {
  if (from != to) {
    if (from == Screen::Scan) {
      qrscan_stop();
      g_dec.reset();
    }
    const bool pulseFrom = from == Screen::Pulse || from == Screen::Armed;
    const bool pulseTo = to == Screen::Pulse || to == Screen::Armed;
    if (pulseFrom && !pulseTo) {
      pulse_stop();
      g_pulse = PulseResult();
    }
    if (from == Screen::Qr || from == Screen::PairQr) wipe_str(g_qrText);
    if (to == Screen::Home) clear_job();
    if (to == Screen::Scan) {
      g_dec.reset();
      g_scanProgress = 0.0f;
      g_scanHint = g_haveCam ? "Scan the request QR - hold 2 s = cancel" : "NO CAMERA DETECTED - hold 2 s = back";
      qrscan_start();
    }
    if (to == Screen::Pulse && from == Screen::Review) {  // the review has been shown: start measuring now
      g_pulse = PulseResult();
      pulse_start();
    }
  }
  // nothing pressed before this screen existed may act on it (Armed in particular); again after drawing (app_loop)
  drain_keys(to != Screen::HomeHold);
  g_changed = true;
  g_dirty = true;
  g_lastDraw = 0;
}

void go(Screen s) {
  const Screen from = g_fsm.screen();
  if (g_fsm.go(s, millis())) on_change(from, s);
}

void show_message(const std::string& title, const std::string& body, uint16_t color) {
  g_msgTitle = title;
  g_msgBody = body;
  g_msgColor = color;
  go(Screen::Message);
}

void refuse(const std::string& title, const std::string& why) {
  buzz_err();
  show_message(title, why.empty() ? std::string("refused") : why, UI_BAD);
}

// Builds the response QR text, then wipes the CBOR and every signing buffer. The QR text itself is wiped when the
// QR screen is left (on_change).
void show_qr(const char* urType, Bytes& cbor, const std::string& title, const std::string& footer) {
  std::string text = ur_encode(urType, cbor);
  wipe_bytes(cbor);
  wipe_sig_buffers();
  g_qrTitle = title;
  g_qrFooter = footer;
  go(Screen::Qr);
  g_qrText.swap(text);
  wipe_str(text);
  g_dirty = true;
  if (Serial) Serial.printf("ripar: output %s\n", urType);
}

// ================================================================================================= reviews
void open_review(Job job) {
  g_lines.clear();
  for (const RLine& l : g_review.lines) {
    ReviewLine rl;
    rl.label = l.label;
    rl.value = l.value;
    rl.color = tone_color(l.tone);
    g_lines.push_back(rl);
  }
  const bool cosign = job == Job::Cosign;
  g_footMore = cosign ? "press = more | hold 2s = DENY" : "press = more | hold 2s = cancel";
  if (!g_review.ok)
    g_footEnd = cosign ? "REFUSED: press = home | 2s = DENY" : "REFUSED: press = home";
  else if (!job_needs_pulse(job))
    g_footEnd = "press = SIGN (no pulse) | 2s = cancel";
  else
    g_footEnd = cosign ? "press = PULSE + SIGN | 2s = DENY" : "press = PULSE + SIGN | 2s = cancel";
  const Screen from = g_fsm.screen();
  if (g_fsm.open_review(job, g_review.ok, millis())) on_change(from, Screen::Review);
  g_review.ok ? buzz_ok() : buzz_err();
}

std::string ur_type_text(const std::string& t) {
  std::string s = ascii_text(t.size() > 48 ? t.substr(0, 48) : t);
  return t.size() > 48 ? s + "..." : s;  // display only: the type is refused either way
}

// PARSE: a complete UR from the camera -> review (or the parser's exact refusal)
void on_request(const std::string& urType, const Bytes& cbor) {
  const ReqType t = req_type_from_ur(urType);
  if (t == ReqType::Unknown)
    return refuse("NOT A RIPAR REQUEST", "UR type \"" + ur_type_text(urType) + "\" is not a request this device signs.");
  CborVal m;
  std::string err;
  if (!cbor_decode(cbor, m, &err)) return refuse("REQUEST REFUSED", "malformed CBOR: " + err);
  switch (t) {
    case ReqType::Pair: {
      PairReq r;
      if (!parse_pair_req(m, r, err)) return refuse("PAIRING REFUSED", err);
      g_pair = r;
      g_review = review_pair(g_pair, g_ctx, g_k1);
      return open_review(Job::Pair);
    }
    case ReqType::Cosign: {
      CosignReq r;
      if (!parse_cosign_req(m, r, err)) return refuse("CO-SIGN REFUSED", err);
      g_cosign = r;
      g_review = review_cosign(g_cosign, g_ctx);
      return open_review(Job::Cosign);
    }
    case ReqType::Mandate: {
      MandateReq r;
      if (!parse_mandate_req(m, r, err)) return refuse("MANDATE REFUSED", err);
      g_mandate = r;
      g_review = review_mandate(g_mandate, g_ctx, g_p1xy);
      return open_review(Job::Mandate);
    }
    case ReqType::Deny: {
      DenyReq r;
      if (!parse_deny_req(m, r, err)) return refuse("DENY REFUSED", err);
      g_deny = r;
      g_review = review_deny(g_deny, g_ctx, false);
      return open_review(Job::Deny);
    }
    case ReqType::Privy: {
      PrivyReq r;
      if (!parse_privy_req(m, r, err)) return refuse("PRIVY REQUEST REFUSED", err);
      g_privy = r;
      g_review = review_privy(g_privy, g_p1xy);
      return open_review(Job::Privy);
    }
    default:
      return refuse("NOT A RIPAR REQUEST", "unsupported request type");
  }
}

// Long2s on a co-sign review: the device builds the deny itself (pinned chain + relay + agent, requestHash of the
// reviewed request computed here) and shows its review; Short there signs it without the pulse.
void start_deny_from_cosign() {
  DenyReq d;
  std::string err;
  if (!deny_from_cosign(g_cosign, g_ctx, d, err)) return refuse("DENY NOT POSSIBLE", err);
  g_deny = d;
  g_review = review_deny(g_deny, g_ctx, true);
  open_review(Job::Deny);
}

void menu_select(int item) {
  if (item == MENU_REVOKE) {
    g_review = review_revoke(g_ctx);
    open_review(Job::Revoke);
  } else if (item == MENU_REOPEN) {
    g_review = review_reopen(g_ctx);
    open_review(Job::Reopen);
  } else {
    go(Screen::Home);
  }
}

// ================================================================================================= signing
// The keys of this device (keys.cpp: derive, sign, verify against the cached public key, wipe).
class DeviceSigner : public Signer {
 public:
  bool p1(const B32& digest, uint8_t rs[64]) override { return p1_sign(digest, rs); }
  bool k1(const B32& digest, uint8_t rsv[65]) override { return k1_sign(digest, rsv); }
};

// Stores the context that goes with a signature (respond.h Save) and shows the response QR. Save::Required: the
// response is withheld when the new context cannot be stored (pairing, mandate, reopen nonce).
void deliver(bool ok, Response& r, const std::string& title, const std::string& err) {
  if (!ok) {
    wipe_bytes(r.cbor);
    wipe_sig_buffers();
    return refuse("NOT SIGNED", err.empty() ? std::string("signing failed") : err);
  }
  std::string footer = "Scan this with the companion. press = done";
  if (r.save != Save::None) {
    const bool saved = store_save_context(r.next);
    // Restrict (panic): RAM follows even when NVS failed, so a second panic in this session signs a higher epoch
    // (security review m4). BestEffort: RAM keeps the old context when NVS failed (the stricter outcome).
    if (saved || r.save == Save::Restrict) g_ctx = r.next;
    if (!saved) {
      if (r.save == Save::Required) {
        wipe_bytes(r.cbor);
        wipe_sig_buffers();
        return refuse("NOT SIGNED", "could not store the new device context in NVS - signature withheld");
      }
      if (r.save == Save::Restrict)
        footer = "Relay NOW. WARNING: epoch not saved (lost on restart). press = done";
      else if (std::strcmp(r.urType, "ripar-revoke") == 0)
        footer = "WARNING: not saved - device still lists the mandate. press = done";
    }  // a co-sign whose "not before" time was not saved: the device time just stays older (stricter)
  }
  buzz_ok();
  show_qr(r.urType, r.cbor, title, footer);
}

// Act::Sign: the key polled in this loop pass was Short AND pulse_update().passed polled in this same pass was true.
void sign_with_pulse(bool pulsePassedThisPass) {
  if (!pulsePassedThisPass) {  // unreachable (Fsm only returns Sign then); fail closed
    go(Screen::Home);
    return;
  }
  DeviceSigner keys;
  Response r;
  std::string err, title;
  bool ok = false;
  switch (g_fsm.job()) {
    case Job::Cosign:
      trng_fill(g_salt, sizeof g_salt);  // fresh salt for this signature
      pulse_evidence(g_ev);              // read only now: `passed` was checked in this pass
      // re-checks the policy, sets presenceHash = presence_hash(ev, salt), rebuilds the digest from the reviewed
      // struct and signs it with P1
      ok = respond_cosign(g_cosign, g_ctx, g_ev, g_salt, keys, r, err);
      title = "CO-SIGNED";
      break;
    case Job::Mandate:
      ok = respond_mandate(g_mandate, g_ctx, g_p1xy, keys, r, err);
      title = "MANDATE SIGNED";
      break;
    case Job::Pair:
      ok = respond_pair(g_pair, g_ctx, g_k1, g_p1xy, g_fwid, keys, r, err);
      title = "PAIRED";
      break;
    case Job::Privy:
      ok = respond_privy(g_privy, keys, r, err);
      title = "PRIVY REQUEST SIGNED";
      break;
    case Job::Revoke:
      ok = respond_revoke(g_ctx, keys, r, err);
      title = "REVOKE SIGNED";
      break;
    case Job::Reopen:
      ok = respond_reopen(g_ctx, keys, r, err);
      title = "REOPEN SIGNED (nonce " + u64_text(reopen_next_nonce(g_ctx)) + ")";
      break;
    default:
      err = "nothing to sign";
      break;
  }
  deliver(ok, r, title, err);
}

// Act::SignNoPulse: a fully seen, allowed Deny review (companion deny-req or built from a co-sign review).
void sign_deny() {
  DeviceSigner keys;
  Response r;
  std::string err;
  bool ok = false;
  if (g_fsm.job() != Job::Deny) {
    err = "nothing to sign";
  } else {
    std::memset(g_ev, 0, sizeof g_ev);  // no pulse for a deny: all-zero evidence (docs/PROTOCOL.md section 4)
    trng_fill(g_salt, sizeof g_salt);
    ok = respond_deny(g_deny, g_ctx, g_ev, g_salt, keys, r, err);
  }
  deliver(ok, r, "DENY SIGNED (agent " + u64_text(g_deny.agentId) + ")", err);
}

// Act::Panic: Hold5s on HOMEHOLD (a hold that began on Home). No pulse (panic can only restrict). Pinned chain +
// PulseCosignEnforcer only.
void do_panic() {
  DeviceSigner keys;
  Response r;
  std::string err;
  const uint64_t epoch = panic_next_epoch(g_ctx);
  if (!respond_panic(g_ctx, keys, r, err)) {
    wipe_sig_buffers();
    return refuse("PANIC REFUSED", err);
  }
  deliver(true, r, "PANIC: min epoch " + u64_text(epoch), err);
}

// Long2s released on HOME: the unsigned keys-only pairing QR (nothing pinned).
void show_pair_qr() {
  Bytes cbor = build_pair(Bytes(), g_k1, g_p1xy, nullptr, nullptr, g_fwid);
  g_qrText = ur_encode("ripar-pair", cbor);
  g_qrTitle = "PAIR: keys only (nothing pinned)";
  g_qrFooter = "press = back | hold 2s = revoke / reopen";
  g_dirty = true;
}

// ================================================================================================= first run
// Entropy for the seed: 64 TRNG bytes, raw MAX30102 samples, camera frames and timing jitter, hashed. keys_create()
// then hashes this with its own 64 TRNG bytes and a timer value.
bool create_keys() {
  Sha256 pool;
  uint8_t buf[64];
  trng_fill(buf, sizeof buf);
  pool.update(buf, sizeof buf);
  wipe(buf, sizeof buf);
  int pulseSamples = 0, frames = 0;
  if (g_havePulse) {
    ui_boot("NEW DEVICE: creating keys (pulse sensor noise)...");
    pulse_start();
    uint32_t ir[32], red[32];
    const uint32_t t0 = millis();
    while (millis() - t0 < 1500) {
      const int n = pulse_raw_samples(ir, red, 32);
      if (n > 0) {
        pool.update(reinterpret_cast<const uint8_t*>(ir), size_t(n) * sizeof(uint32_t));
        pool.update(reinterpret_cast<const uint8_t*>(red), size_t(n) * sizeof(uint32_t));
        pulseSamples += n;
      }
      const uint32_t t = micros();
      pool.update(reinterpret_cast<const uint8_t*>(&t), sizeof t);
      delay(40);
    }
    pulse_stop();
    wipe(ir, sizeof ir);
    wipe(red, sizeof red);
  }
  if (g_haveCam) {
    ui_boot("NEW DEVICE: creating keys (camera noise)...");
    qrscan_start();
    const uint32_t t0 = millis();
    while (millis() - t0 < 1500) {
      int w = 0, h = 0;
      const uint8_t* f = qrscan_frame(w, h);
      if (f) {
        pool.update(f, size_t(w) * size_t(h));
        qrscan_release_frame();
        frames++;
      }
      const uint32_t t = micros();
      pool.update(reinterpret_cast<const uint8_t*>(&t), sizeof t);
      delay(100);
    }
    qrscan_stop();
    std::string junk;
    qrscan_poll(junk);  // a QR the decoder may have read meanwhile is not a request
  }
  uint8_t extra[32];
  pool.final(extra);
  ui_boot("NEW DEVICE: storing the seed...");
  const bool ok = keys_create(extra) && keys_init();
  wipe(extra, sizeof extra);
  if (Serial) Serial.printf("ripar: keys created=%d (pulse samples %d, camera frames %d)\n", ok, pulseSamples, frames);
  return ok;
}

void enter_fail(const std::string& why) {
  g_failText = why + "\nSIGNING IS DISABLED.";
  g_fsm.fail();
  buzz_err();
  ui_message("SELFTEST FAIL", g_failText, UI_BAD);
  if (Serial) Serial.printf("ripar: FAIL %s\n", why.c_str());
}

// only the failed checks + the summary line of keys_selftest()
std::string failed_lines(const std::string& report) {
  std::string out;
  size_t i = 0;
  while (i < report.size()) {
    size_t e = report.find('\n', i);
    if (e == std::string::npos) e = report.size();
    const std::string line = report.substr(i, e - i);
    if (line.compare(0, 4, "FAIL") == 0 || line.find("SELFTEST") != std::string::npos) out += line + "\n";
    i = e + 1;
  }
  return out;
}

// ================================================================================================= drawing
void draw(uint32_t now) {
  const Screen s = g_fsm.screen();
  switch (s) {
    case Screen::Fail:
      if (g_dirty) ui_message("SELFTEST FAIL", g_failText, UI_BAD);
      break;
    case Screen::Home:
      if (g_dirty || now - g_lastDraw >= kHomeDrawMs) {
        ui_home(short_addr(g_k1), battery_percent(), g_ctx.paired());
        g_lastDraw = now;
      }
      break;
    case Screen::HomeHold:
      if (g_dirty)
        ui_message("RELEASE = PAIRING QR",
                   "Keep holding to 5 s for PANIC: signs Panic(min epoch + 1) at once, no pulse needed.", UI_WARN);
      break;
    case Screen::Scan:
      if (g_dirty || now - g_lastDraw >= kScanDrawMs) {
        int w = 0, h = 0;
        const uint8_t* f = qrscan_frame(w, h);
        ui_scan(f, w, h, g_scanProgress, g_scanHint.c_str());
        if (f) qrscan_release_frame();
        g_lastDraw = now;
      }
      break;
    case Screen::Review:
      if (g_dirty) {
        const ReviewView v = ui_review(g_review.title.c_str(), g_lines, g_fsm.review_row(), g_footMore.c_str(),
                                       g_footEnd.c_str());
        g_fsm.review_drawn(v.firstRow, v.rowsShown, v.totalRows);
      }
      break;
    case Screen::Pulse:
    case Screen::Armed:
      if (g_dirty || now - g_lastDraw >= kPulseDrawMs) {
        const std::string title = !g_havePulse ? std::string("NO PULSE SENSOR - cannot sign")
                                  : s == Screen::Armed ? "ARMED: press SIGN (" + g_review.title + ")"
                                                       : "PULSE: " + g_review.title;
        ui_pulse(g_pulse, title.c_str());
        g_lastDraw = now;
      }
      break;
    case Screen::Qr:
    case Screen::PairQr:
      if (g_dirty) ui_qr(g_qrText, g_qrTitle.c_str(), g_qrFooter.c_str());
      break;
    case Screen::Message:
      if (g_dirty) ui_message(g_msgTitle.c_str(), g_msgBody, g_msgColor);
      break;
    case Screen::Menu:
      if (g_dirty) {
        static const char* const kItems[MENU_ITEMS] = {"REVOKE the last mandate", "REOPEN the agent lane", "BACK"};
        std::vector<ReviewLine> lines;
        for (int i = 0; i < MENU_ITEMS; i++) {
          ReviewLine l;
          l.value = std::string(i == g_fsm.menu_index() ? "> " : "   ") + kItems[i];
          l.color = i == g_fsm.menu_index() ? UI_ACCENT : UI_DIM;
          lines.push_back(l);
        }
        ReviewLine note;
        note.value = "Both need pulse + SIGN and use the contracts pinned at pairing.";
        note.color = UI_DIM;
        lines.push_back(note);
        ui_review("DEVICE ACTIONS", lines, 0, "press = next | hold 2s = select", "press = next | hold 2s = select");
      }
      break;
  }
  g_dirty = false;
}

// ================================================================================================= scanning
void tick_scan(uint32_t now) {
  std::string payload;
  if (!qrscan_poll(payload)) return;
  const UrDecoder::Result r = g_dec.receive(payload);
  if (r == UrDecoder::Complete) {
    buzz_ok();
    const std::string type = g_dec.type();
    const Bytes msg = g_dec.message();
    on_request(type, msg);  // -> Review or Message (the camera stops on leaving Scan)
    return;
  }
  if (r == UrDecoder::Accepted) {
    g_fsm.touch(now);
    const float p = g_dec.progress();
    if (p > g_scanProgress) buzz_beat();
    g_scanProgress = p;
    char hint[64];
    std::snprintf(hint, sizeof hint, "multipart: %u of %u parts - keep the code in view",
                  static_cast<unsigned>(g_dec.received_pure()), static_cast<unsigned>(g_dec.seq_len()));
    g_scanHint = hint;
  } else if (r == UrDecoder::Error) {
    buzz_err();
    g_scanHint = "bad QR part: " + g_dec.error();  // progress so far is kept
  } else {
    g_scanHint = "not a Ripar request QR";
  }
}

}  // namespace

// ================================================================================================= entry points
void app_setup() {
  io_init();
  ui_init();
  ui_boot("starting...");
  g_havePulse = pulse_init();
  g_haveCam = qrscan_init();
  firmware_id(g_fwid);
  keys_init();
  if (Serial)
    Serial.printf("ripar: pulse sensor %s, camera %s (PID 0x%04X), fw %s\n", g_havePulse ? "ok" : "MISSING",
                  g_haveCam ? "ok" : "MISSING", camera_pid(), to_hex(g_fwid, 8, false).c_str());

  // SELFTEST: crypto against published vectors + mbedTLS (and the device keys, if there are any)
  ui_boot("self-test: crypto vectors...");
  std::string report;
  if (!keys_selftest(report)) return enter_fail(failed_lines(report));
  if (Serial) Serial.print(failed_lines(report).c_str());

  // first run: create the keys, then test them too
  if (!keys_have_seed()) {
    if (!create_keys()) return enter_fail("key creation failed");
    ui_boot("self-test: new device keys...");
    report.clear();
    if (!keys_selftest(report)) return enter_fail(failed_lines(report));
  }
  if (!keys_init()) return enter_fail("cannot load the device keys");
  g_k1 = k1_address();
  p1_pubkey(g_p1xy);
  bool lost = false;
  if (!store_load_context(g_ctx)) {  // none / old layout / corrupt: unpaired
    g_ctx = Context();
    lost = store_has_context();  // something was stored but cannot be read: the counters restart at 0
  }
  if (Serial)
    Serial.printf("ripar: K1 %s, %s\n", addr_checksum(g_k1).c_str(),
                  g_ctx.paired() ? chain_text(g_ctx.chainId).c_str() : lost ? "PAIRING LOST" : "not paired");
  buzz_ok();
  go(Screen::Home);  // drains the key queue, draws the home screen
  if (lost) {
    // fork review N1: a PANIC / REOPEN signed now would repeat epoch / nonce 1, which the chain refuses
    buzz_err();
    show_message("PAIRING LOST",
                 "Stored pairing unreadable (old layout or corrupt). Panic epoch and reopen nonce restart at 0: pair "
                 "again with the on-chain floors (pair keys 10 / 11: minEpoch, reopenNonce) before PANIC or REOPEN.",
                 UI_WARN);
  }
}

void app_loop() {
  const uint32_t now = millis();
  FsmIn in;
  in.nowMs = now;
  in.key = io_poll_key_state(in.keyDown);  // event + debounced state, read atomically
  const Screen before = g_fsm.screen();
  if (before == Screen::Pulse || before == Screen::Armed) {
    g_pulse = pulse_update();  // polled AFTER the key, in the same pass: the gate sees both together
    in.pulsePassed = g_pulse.passed;
    if (g_pulse.beatNow) buzz_beat();
  }
  const Act a = g_fsm.step(in);
  const Screen after = g_fsm.screen();
  if (after != before) on_change(before, after);
#if RIPAR_LED_CHALLENGE
  if (after == Screen::Armed && before == Screen::Pulse && !pulse_led_challenge()) {
    buzz_err();
    // challenge failed: measure again from scratch (the review stays; Fsm returns to Pulse on the next pass)
    pulse_start();
  }
#endif
  switch (a) {
    case Act::Redraw:
      g_dirty = true;
      break;
    case Act::Ignored:
      buzz_err();
      break;
    case Act::PairQr:
      show_pair_qr();
      break;
    case Act::Panic:
      do_panic();
      break;
    case Act::MenuSelect:
      menu_select(g_fsm.menu_index());
      break;
    case Act::Sign:
      sign_with_pulse(in.pulsePassed);
      break;
    case Act::SignNoPulse:
      sign_deny();
      break;
    case Act::Deny:
      start_deny_from_cosign();
      break;
    case Act::Timeout:
      buzz_err();
      break;
    case Act::Home:
    case Act::None:
      break;
  }
  if (g_fsm.screen() == Screen::Scan) tick_scan(now);
  draw(now);
  // a press made while the previous screen was still displayed (before this one was drawn) is dropped too, and one
  // that is still down is swallowed until it is released
  if (g_changed) {
    drain_keys(g_fsm.screen() != Screen::HomeHold);
    g_changed = false;
  }
  delay(2);
}

}  // namespace ripar
