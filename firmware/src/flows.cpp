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
//
// RIPAR_BLE (env:ripar; docs/BLE_LINK.md): a Bluetooth LE fallback courier for when the camera cannot read the QR
// codes. The radio is dead at boot; the device menu's BLE LINK opens a review ("Turns the radio ON ...") that needs
// pulse + SIGN like a signature (Job::BleOn), then the pairing screen (Screen::BlePair, the only place where a phone
// can pair: numeric comparison, SIGN = confirm). A line written by the phone is fed into intake_part(), exactly like a
// camera-decoded QR part, and only while SCAN is on screen; the response QR on screen is also sent to the phone. The
// radio goes off on BLE OFF, PANIC, after 5 min without link traffic, and with the power; while it is alive every
// screen shows RADIO ON (ui.cpp). env:ripar-airgap (RIPAR_BLE=0) builds none of this.
//
// RIPAR_WIFI (env:ripar only; docs/WIFI_LINK.md) - a TEMPORARY TEST FEATURE, removed by building env:ripar-ble or
// env:ripar-airgap: the paired phone sends a Wi-Fi network over the BLE PROV characteristic (accepted only while Home
// or the pairing screen is shown); it is only stored after the JOIN WI-FI review is confirmed with SIGN
// (Job::WifiJoin, no pulse; hold 2 s rejects). Wi-Fi only starts with a stored network AND WI-FI ON chosen in the
// menu (Job::WifiOn, also SIGN without pulse; the choice is persisted and then also starts Wi-Fi at boot). While the
// Wi-Fi driver is alive, every screen shows WIFI ON (or BLE+WIFI), Home says NOT AIR-GAPPED and shows the IP address
// and the per-boot 8-digit link code. The HTTP link (wifi_link.cpp) feeds UR lines into intake_part() exactly like the
// BLE RX lines, only on SCAN, and serves the same STATUS JSON and the QR on screen. WI-FI OFF, FORGET WI-FI and PANIC
// turn it off (and clear the persisted choice).
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
#include "vault.h"
#if RIPAR_BLE
#include "ble_link.h"
#include "ble_proto.h"
#endif
#if RIPAR_WIFI
#include "wifi_link.h"
#include "wifi_proto.h"
#endif

namespace ripar {
namespace {

constexpr uint32_t kScanDrawMs = 60;    // viewfinder refresh
constexpr uint32_t kPulseDrawMs = 80;   // pulse screen refresh
constexpr uint32_t kHomeDrawMs = 2000;  // battery refresh on the home screen

#ifndef RIPAR_LED_CHALLENGE
#define RIPAR_LED_CHALLENGE 0  // 1 = also require the MAX30102 LED-drive liveness challenge before arming (unverified)
#endif

#if RIPAR_WIFI
Fsm g_fsm(Fsm::DEFAULT_TIMEOUT_MS, MENU_ITEMS_WIFI);  // + BLE items, WI-FI ON / WI-FI OFF, FORGET WI-FI before BACK
#elif RIPAR_BLE
Fsm g_fsm(Fsm::DEFAULT_TIMEOUT_MS, MENU_ITEMS_BLE);  // + BLE LINK / BLE OFF, FORGET PHONE before BACK
#else
Fsm g_fsm;
#endif

// ---- device identity + pinned context
Context g_ctx;  // from NVS; replaced only by a saved context_after_*() result
Addr g_k1;
Addr g_vault;  // vault_address(g_k1): the only vault this device pins (vault.h)
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

#if RIPAR_BLE
// ---- Bluetooth LE fallback courier
std::string g_bleName;           // "RIPAR-XXXX": shown on the BLE LINK review, advertised once the radio is on
std::string g_linkNote;          // STATUS "note" (why a BLE / Wi-Fi line was ignored); cleared on every screen change
std::string g_blePairMsg;        // pairing screen status
bool g_bleCodeDrawn = false;     // the pending comparison value has been drawn on the pairing screen ...
uint32_t g_bleDrawnCode = 0;     // ... this one
std::string g_k1Short, g_fwHex;  // for the STATUS JSON
uint32_t g_badgeCheck = 0;       // last time the radio badges were compared with the drivers
constexpr const char* kNotOnScan = "ignored: not on SCAN (press SIGN on the device first)";
#endif
#if RIPAR_WIFI
wifip::Creds g_wifiNew;          // the network under review (JOIN WI-FI); wiped when the review is left
#endif

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
#if RIPAR_BLE
    const bool bleOn = ble_link_on();
#if RIPAR_WIFI
    const bool wifiOn = wifi_link_on();
#else
    const bool wifiOn = false;
#endif
    if (to == Screen::Scan && (bleOn || wifiOn)) {
      const std::string via = bleOn && wifiOn ? "BLE / Wi-Fi" : bleOn ? "BLE" : "Wi-Fi";
      g_scanHint = g_haveCam ? "Scan the QR, or send it from the phone (" + via + ") - 2 s = cancel"
                             : "Send the request from the phone (" + via + ") - hold 2 s = cancel";
    }
    if (from == Screen::BlePair) {  // the pairing window closes with its screen (a pending code is rejected)
      ble_link_pairing_window(false);
      g_bleCodeDrawn = false;
      g_blePairMsg.clear();
    }
    if (to == Screen::BlePair) ble_link_pairing_window(true);
    g_linkNote.clear();
#endif
#if RIPAR_WIFI
    if (from == Screen::Review) g_wifiNew.wipe();  // a JOIN WI-FI review that was left: forget what was sent
#endif
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
  else if (job == Job::WifiJoin)
    g_footEnd = "press = SAVE (no pulse) | 2s = reject";
  else if (job == Job::WifiOn)
    g_footEnd = "press = WI-FI ON (no pulse) | 2s = cancel";
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

#if RIPAR_BLE
// ================================================================================================= Bluetooth LE
// The badges follow the drivers themselves (Bluetooth controller, Wi-Fi driver): they stay on if a teardown step
// failed. Compared on every change made here and every 100 ms (app_loop).
void update_badges() {
  bool changed = false;
  const bool ble = ble_link_radio_alive();
  if (ble != ui_radio_badge()) {
    ui_set_radio_badge(ble);
    changed = true;
  }
#if RIPAR_WIFI
  const bool wifi = wifi_link_radio_alive();
  if (wifi != ui_wifi_badge()) {
    ui_set_wifi_badge(wifi);
    changed = true;
  }
#endif
  if (changed) g_dirty = true;
}

void radio_badge() {
  update_badges();
  g_dirty = true;
}

// ---- shared by the BLE and the Wi-Fi courier: the same STATUS JSON, the same intake, the same output
std::string link_status() {
  blep::StatusInfo st;
  st.screen = g_fsm.screen();
  st.paired = g_ctx.paired();
  st.k1 = g_k1Short;
  st.fw = g_fwHex;
  st.got = unsigned(g_dec.received_pure());
  st.of = unsigned(g_dec.seq_len());
  st.note = g_linkNote;
  st.radio = ble_link_on();
#if RIPAR_WIFI
  st.wifi = wifi_state_text(wifi_link_state());
  st.ip = wifi_link_ip();
#endif
  return blep::status_json(st);
}

const std::string& link_output() {  // the UR text of the QR on screen (empty when none)
  static const std::string kNone;
  const Screen s = g_fsm.screen();
  return (s == Screen::Qr || s == Screen::PairQr) ? g_qrText : kNone;
}

UrDecoder::Result intake_part(const std::string& payload, uint32_t now);

// One line (UR part) from the phone, over BLE or Wi-Fi: the camera's intake, only while SCAN is shown.
void link_line(const std::string& line, uint32_t now) {
  if (g_fsm.screen() == Screen::Scan) {
    const UrDecoder::Result r = intake_part(line, now);
    if (r == UrDecoder::Error || r == UrDecoder::Ignored)
      g_linkNote = "part not used: " + g_scanHint;
    else if (g_fsm.screen() == Screen::Scan)
      g_linkNote.clear();
  } else {
    g_linkNote = kNotOnScan;
  }
}

void radio_off(const char* why) {
  if (!ble_link_on() && !ble_link_radio_alive()) return;
  ble_link_disable();
  radio_badge();
  if (Serial)
    Serial.printf("ripar: radio off (%s)%s\n", why, ble_link_radio_alive() ? " - CONTROLLER STILL ALIVE" : "");
}

Review review_ble_on() {
  Review r;
  r.title = "BLE LINK: TURN THE RADIO ON?";
  r.ok = true;
  auto add = [&r](const char* label, const std::string& value, Tone tone) {
    r.lines.push_back(RLine{label, value, tone});
  };
  add("", "Turns the radio ON. Ripar is not air-gapped while it is on.", Tone::Bad);
  add("Use", "fallback courier when the camera cannot read the QR codes; QR stays the primary path", Tone::Normal);
  add("Name", g_bleName + " (Bluetooth LE)", Tone::Normal);
  add("Pairing", "one phone; LE Secure Connections; you confirm its 6-digit code on this screen", Tone::Normal);
  add("Signing", "unchanged: every request is still reviewed here and needs pulse + SIGN", Tone::Good);
  add("Off", "BLE OFF in this menu, PANIC, 5 min without link traffic, or power off", Tone::Normal);
  add("Badge", "RADIO ON is shown on every screen while the radio is on", Tone::Warn);
  return r;
}

// Act::Sign on the BleOn review (pulse + SIGN passed): nothing is signed, the radio is turned on
void enable_radio() {
  wipe_sig_buffers();
  ui_message("RADIO STARTING", "Bluetooth LE is starting as " + g_bleName + "...", UI_WARN);
  std::string err;
  const bool ok = ble_link_enable(g_bleName, err);
  radio_badge();
  if (!ok)
    return refuse("RADIO NOT STARTED",
                  err + (ble_link_radio_alive() ? " - CONTROLLER STILL ALIVE" : " - the radio is off."));
  if (g_k1Short.empty()) g_k1Short = short_addr(g_k1);
  if (g_fwHex.empty()) g_fwHex = to_hex(g_fwid, 8, false);
  buzz_ok();
  g_blePairMsg.clear();
  go(Screen::BlePair);
}

// SIGN / hold 2 s on the pairing screen
void ble_pair_key(bool yes) {
  uint32_t code = 0;
  if (ble_link_code(code)) {
    if (!g_bleCodeDrawn || code != g_bleDrawnCode) {  // not on screen yet: a press cannot confirm what it did not see
      buzz_err();
      return;
    }
    ble_link_answer(yes);
    g_bleCodeDrawn = false;
    g_blePairMsg = yes ? "Code confirmed - finishing the pairing..." : "Code REJECTED: the phone was not paired.";
    if (yes)
      buzz_ok();
    else
      buzz_err();
    g_dirty = true;
    return;
  }
  if (yes) {
    go(Screen::Home);  // done; the radio stays on (badge)
    return;
  }
  radio_off("pairing screen");
  show_message("RADIO OFF", "Bluetooth is off again (controller de-initialised). Ripar is air-gapped.", UI_GOOD);
}

void draw_ble_pair() {
  uint32_t code = 0;
  const bool pending = ble_link_code(code);
  const BleLinkView v = ble_link_view();
  char codeText[16] = "";
  if (pending) std::snprintf(codeText, sizeof codeText, "%03u %03u", unsigned(code / 1000), unsigned(code % 1000));
  std::string body;
  if (pending)
    body = "Does the phone show the same 6 digits? Confirm only a phone you are holding.";
  else if (!g_blePairMsg.empty())
    body = g_blePairMsg;
  else if (v.authenticated)
    body = "A paired phone is connected (encrypted).";
  else if (v.connected)
    body = "A phone connected - waiting for it to pair...";
  else
    body = "Pairing is open only while this screen is shown. In the Ripar app, connect to " + ble_link_name() + ".";
  if (!pending && ble_link_bonded_count() > 0) body += " A new pairing replaces the paired phone.";
  ui_ble_pair(ble_link_name().c_str(), codeText, body,
              pending ? "press = CONFIRM | hold 2s = REJECT" : "press = home (radio stays on) | 2s = RADIO OFF");
  g_bleCodeDrawn = pending;
  g_bleDrawnCode = code;
}
#endif

#if RIPAR_WIFI
// ================================================================================================= Wi-Fi (test)
// TEMPORARY TEST FEATURE (docs/WIFI_LINK.md). Everything here is removed with RIPAR_WIFI=0.
void wifi_off(const char* why, bool clearChoice) {
  if (clearChoice && wifi_auto_on() && !wifi_set_auto_on(false) && Serial)
    Serial.println("ripar: wifi: could not clear the WI-FI ON choice in NVS");
  if (!wifi_link_on() && !wifi_link_radio_alive()) return;
  wifi_link_disable();
  radio_badge();
  if (Serial)
    Serial.printf("ripar: wifi off (%s)%s\n", why, wifi_link_radio_alive() ? " - DRIVER STILL INITIALISED" : "");
}

bool wifi_start(std::string& err) {
  ui_message("WI-FI STARTING", "Wi-Fi is starting (test feature). Ripar is not air-gapped while it is on.", UI_WARN);
  const bool ok = wifi_link_enable(err);
  radio_badge();
  if (!ok && wifi_link_radio_alive()) err += " - DRIVER STILL INITIALISED";
  return ok;
}

// Home: "192.168.1.23  CODE 1234 5678" (or the connection state instead of the address)
std::string wifi_home_line() {
  if (!wifi_link_on()) return std::string();
  const std::string code = "CODE " + wifip::code_display(wifi_link_code());
  if (wifi_link_state() == WifiState::On) return wifi_link_ip() + "  " + code;
  return "WI-FI " + wifi_link_detail() + "...  " + code;
}

Review review_wifi_join(const wifip::Creds& c) {
  Review r;
  bool altered = false;
  const std::string ssid = wifip::ssid_display(c.ssid, &altered);
  r.title = "JOIN WI-FI " + ssid + "?";
  r.ok = true;
  auto add = [&r](const char* label, const std::string& value, Tone tone) {
    r.lines.push_back(RLine{label, value, tone});
  };
  add("", "TEST FEATURE: stores this Wi-Fi network on the device. Nothing is signed.", Tone::Warn);
  add("Network", ssid + (altered ? " (bytes that are not printable ASCII shown as ?)" : ""), Tone::Normal);
  add("Password", c.pass.empty() ? std::string("NONE: open network") : std::string("set (never shown)"),
      c.pass.empty() ? Tone::Warn : Tone::Normal);
  add("From", "the paired phone (Bluetooth, PROV)", Tone::Normal);
  std::string old;
  if (wifi_creds_ssid(old) && old != c.ssid)
    add("Replaces", "the stored network " + wifip::ssid_display(old), Tone::Warn);
  add("Wi-Fi", wifi_link_on() ? "is on: it reconnects to this network now"
                              : "stays OFF until you choose WI-FI ON in the device menu",
      Tone::Normal);
  add("Signing", "unchanged: every request is still reviewed here and needs pulse + SIGN", Tone::Good);
  return r;
}

Review review_wifi_on(const std::string& ssid) {
  Review r;
  r.title = "WI-FI ON: TURN WI-FI ON?";
  r.ok = true;
  auto add = [&r](const char* label, const std::string& value, Tone tone) {
    r.lines.push_back(RLine{label, value, tone});
  };
  add("", "TEST FEATURE: turns Wi-Fi ON. Ripar is not air-gapped while it is on.", Tone::Bad);
  add("Network", wifip::ssid_display(ssid), Tone::Normal);
  add("Stays on", "also after a restart, until WI-FI OFF, FORGET WI-FI or PANIC", Tone::Warn);
  add("Link", "HTTP on port 80 (" + wifi_link_host() + ".local once connected); every request needs the 8-digit "
              "code shown on Home",
      Tone::Normal);
  add("Signing", "unchanged: every request is still reviewed here and needs pulse + SIGN", Tone::Good);
  add("Badge", "WIFI ON is shown on every screen while Wi-Fi is on", Tone::Warn);
  return r;
}

// A PROV value from the paired phone: reviewed on the device, stored only after SIGN
void wifi_prov(const std::string& json) {
  wifip::Creds c;
  std::string err;
  if (!wifip::parse_prov(json, c, err)) {
    g_linkNote = "wifi setup refused: " + err;
    buzz_err();
    return;
  }
  const Screen s = g_fsm.screen();
  uint32_t code = 0;
  const bool idle = s == Screen::Home || (s == Screen::BlePair && !ble_link_code(code));
  if (!idle) {  // never on top of a request, a review or a pairing code
    c.wipe();
    g_linkNote = "wifi setup ignored: the device must show HOME (or BLE PAIRING)";
    return;
  }
  g_wifiNew.wipe();
  g_wifiNew.ssid = c.ssid;
  g_wifiNew.pass = c.pass;
  c.wipe();
  g_review = review_wifi_join(g_wifiNew);
  open_review(Job::WifiJoin);
}

// Act::Confirm on a fully seen JOIN WI-FI review
void wifi_join_confirmed() {
  wifip::Creds c;
  c.ssid = g_wifiNew.ssid;
  c.pass = g_wifiNew.pass;
  g_wifiNew.wipe();
  const bool saved = !c.ssid.empty() && wifi_creds_save(c);
  const std::string ssid = wifip::ssid_display(c.ssid);
  c.wipe();
  if (!saved) return refuse("WI-FI NOT SAVED", "Could not store the network in NVS (namespace ripar-wifi).");
  if (wifi_link_on()) {  // reconnect with the new network
    wifi_off("new network", false);
    std::string err;
    if (!wifi_start(err)) return refuse("WI-FI NOT STARTED", "Network \"" + ssid + "\" stored, but: " + err);
    buzz_ok();
    return show_message("WI-FI SAVED", "Network \"" + ssid + "\" stored. Wi-Fi reconnects to it now; the address "
                        "and the link code are on Home.", UI_WARN);
  }
  buzz_ok();
  show_message("WI-FI SAVED", "Network \"" + ssid + "\" stored. Wi-Fi stays OFF until you choose WI-FI ON in the "
               "device menu (Home: hold 2 s and release, then hold 2 s on the pairing QR).", UI_GOOD);
}

// Act::Confirm on a fully seen WI-FI ON review
void wifi_on_confirmed() {
  std::string err;
  if (!wifi_start(err)) {
    wifi_off("start failed", false);
    return refuse("WI-FI NOT STARTED", err);
  }
  if (!wifi_set_auto_on(true) && Serial) Serial.println("ripar: wifi: could not store the WI-FI ON choice");
  buzz_ok();
  go(Screen::Home);  // NOT AIR-GAPPED, the WIFI ON badge, the address and the link code
}

// The device side of the HTTP link (include/wifi_proto.h LinkApp), called from wifi_link_tick on the app loop
class FlowsLink : public wifip::LinkApp {
 public:
  explicit FlowsLink(uint32_t now) : now_(now) {}
  std::string status_json() override { return link_status(); }
  bool on_scan() override { return g_fsm.screen() == Screen::Scan; }
  void rx_line(const std::string& line) override { link_line(line, now_); }
  void rx_refused() override { g_linkNote = kNotOnScan; }
  std::string output() override { return link_output(); }

 private:
  uint32_t now_;
};

void wifi_tick(uint32_t now) {
  if (!wifi_link_on()) return;
  FlowsLink app(now);
  if (wifi_link_tick(now, app) == WifiEvt::StateChange) g_dirty = true;  // Home shows the address
}
#endif

// Act::Confirm: a fully seen review of a device setting (RIPAR_WIFI jobs); nothing is signed
void confirm_setting() {
#if RIPAR_WIFI
  if (g_fsm.job() == Job::WifiJoin) return wifi_join_confirmed();
  if (g_fsm.job() == Job::WifiOn) return wifi_on_confirmed();
#endif
  go(Screen::Home);
}

void menu_select(int item) {
  if (item == MENU_REVOKE) {
    g_review = review_revoke(g_ctx);
    open_review(Job::Revoke);
  } else if (item == MENU_REOPEN) {
    g_review = review_reopen(g_ctx);
    open_review(Job::Reopen);
#if RIPAR_BLE
  } else if (item == MENU_BLE) {
    if (ble_link_on() || ble_link_radio_alive()) {  // BLE OFF
      radio_off("BLE OFF");
      buzz_ok();
      show_message("RADIO OFF", "Bluetooth is off again (controller de-initialised). Ripar is air-gapped.", UI_GOOD);
    } else {  // BLE LINK: review + pulse + SIGN, then the radio is turned on
      uint8_t rnd[2];
      trng_fill(rnd, sizeof rnd);
      g_bleName = blep::adv_name(uint16_t(rnd[0] << 8 | rnd[1]));
      g_review = review_ble_on();
      open_review(Job::BleOn);
    }
  } else if (item == MENU_FORGET) {
    const bool on = ble_link_on();
    ble_link_forget_phone();
    buzz_ok();
    show_message("PHONE FORGOTTEN",
                 on ? "The Bluetooth bond is deleted and the phone disconnected. It must pair again."
                    : "The Bluetooth bond is deleted before the radio is next turned on. The phone must pair again.",
                 UI_GOOD);
#endif
#if RIPAR_WIFI
  } else if (item == MENU_WIFI) {
    if (wifi_link_on() || wifi_link_radio_alive()) {  // WI-FI OFF
      wifi_off("WI-FI OFF", true);
      if (wifi_link_radio_alive()) {
        buzz_err();
        show_message("WI-FI NOT OFF", "The Wi-Fi driver is still initialised (the badge stays). Restart the device: "
                     "Wi-Fi will not start again (the WI-FI ON choice is cleared).", UI_BAD);
      } else {
        buzz_ok();
        show_message("WI-FI OFF",
                     std::string("Wi-Fi is off (driver de-initialised) and stays off after a restart.") +
                         (ble_link_on() ? " Bluetooth is still on." : " Ripar is air-gapped."),
                     UI_GOOD);
      }
    } else {  // WI-FI ON: review, then SIGN (no pulse)
      std::string ssid;
      if (!wifi_creds_ssid(ssid)) {
        buzz_err();
        show_message("NO WI-FI NETWORK",
                     "Send one from the Ripar app first: BLE LINK, pair the phone, then the app's Wi-Fi setup. "
                     "The device shows it for you to confirm.",
                     UI_WARN);
      } else {
        g_review = review_wifi_on(ssid);
        open_review(Job::WifiOn);
      }
    }
  } else if (item == MENU_WIFI_FORGET) {
    wifi_off("FORGET WI-FI", true);
    const bool ok = wifi_creds_forget();
    if (ok)
      buzz_ok();
    else
      buzz_err();
    show_message(ok ? "WI-FI FORGOTTEN" : "WI-FI NOT FORGOTTEN",
                 ok ? "The stored network and the WI-FI ON choice are erased (NVS ripar-wifi). Wi-Fi is off."
                    : "Could not erase NVS namespace ripar-wifi. Wi-Fi is off.",
                 ok ? UI_GOOD : UI_BAD);
#endif
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
#if RIPAR_BLE
    case Job::BleOn:  // a confirmation, not a signature
      return enable_radio();
#endif
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
#if RIPAR_BLE
  radio_off("PANIC");  // PANIC always leaves the device radio-free
#endif
#if RIPAR_WIFI
  wifi_off("PANIC", true);  // and Wi-Fi stays off after a restart
#endif
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
#if RIPAR_WIFI
        ui_home(short_addr(g_k1), battery_percent(), g_ctx.paired(), wifi_home_line());
#else
        ui_home(short_addr(g_k1), battery_percent(), g_ctx.paired());
#endif
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
#if RIPAR_WIFI
        const bool radio = ble_link_on() || ble_link_radio_alive();
        const bool wifi = wifi_link_on() || wifi_link_radio_alive();
        const char* const kItems[MENU_ITEMS_WIFI] = {
            "REVOKE the last mandate", "REOPEN the agent lane",
            radio ? "BLE OFF (radio off now)" : "BLE LINK (radio on: phone courier)", "FORGET PHONE (Bluetooth bond)",
            wifi ? "WI-FI OFF (test link off now)" : "WI-FI ON (test link: not air-gapped)",
            "FORGET WI-FI (stored network)", "BACK"};
        const char* const kNote = "REVOKE, REOPEN and BLE LINK need pulse + SIGN. Wi-Fi: test feature.";
#elif RIPAR_BLE
        const bool radio = ble_link_on() || ble_link_radio_alive();
        const char* const kItems[MENU_ITEMS_BLE] = {
            "REVOKE the last mandate", "REOPEN the agent lane",
            radio ? "BLE OFF (radio off now)" : "BLE LINK (radio on: phone courier)", "FORGET PHONE (Bluetooth bond)",
            "BACK"};
        const char* const kNote = "REVOKE, REOPEN and BLE LINK need pulse + SIGN.";
#else
        static const char* const kItems[MENU_ITEMS] = {"REVOKE the last mandate", "REOPEN the agent lane", "BACK"};
        const char* const kNote = "Both need pulse + SIGN and use the contracts pinned at pairing.";
#endif
        std::vector<ReviewLine> lines;
        for (int i = 0; i < g_fsm.menu_items(); i++) {
          ReviewLine l;
          l.value = std::string(i == g_fsm.menu_index() ? "> " : "   ") + kItems[i];
          l.color = i == g_fsm.menu_index() ? UI_ACCENT : UI_DIM;
          lines.push_back(l);
        }
        ReviewLine note;
        note.value = kNote;
        note.color = UI_DIM;
        lines.push_back(note);
        ui_review("DEVICE ACTIONS", lines, 0, "press = next | hold 2s = select", "press = next | hold 2s = select");
      }
      break;
    case Screen::BlePair:
#if RIPAR_BLE
      if (g_dirty) draw_ble_pair();
#endif
      break;
  }
  g_dirty = false;
}

// ================================================================================================= scanning
// One UR part: from the camera (tick_scan) or, in RIPAR_BLE builds, a line from the phone (ble_tick). Both take the
// same decoder -> on_request -> review -> pulse -> SIGN path.
UrDecoder::Result intake_part(const std::string& payload, uint32_t now) {
  const UrDecoder::Result r = g_dec.receive(payload);
  if (r == UrDecoder::Complete) {
    buzz_ok();
    const std::string type = g_dec.type();
    const Bytes msg = g_dec.message();
    on_request(type, msg);  // -> Review or Message (the camera stops on leaving Scan)
    return r;
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
  return r;
}

void tick_scan(uint32_t now) {
  std::string payload;
  if (!qrscan_poll(payload)) return;
  intake_part(payload, now);
}

#if RIPAR_BLE
// Once per pass while the radio is on: phone lines -> intake_part (only on SCAN), STATUS / TX, link events.
void ble_tick(uint32_t now) {
  if (!ble_link_on()) return;
  std::string line;
  for (int n = 0; n < 16 && ble_link_poll_line(line); n++) link_line(line, now);
#if RIPAR_WIFI
  std::string prov;
  if (ble_link_poll_prov(prov)) {  // Wi-Fi credentials: reviewed on the device (JOIN WI-FI), stored only after SIGN
    wifi_prov(prov);
    wifip::wipe_str(prov);
  }
#endif
  const Screen s = g_fsm.screen();
  const BleEvt e = ble_link_tick(now, link_status(), link_output());
  switch (e) {
    case BleEvt::AutoOff:
      radio_badge();
      buzz_err();
      if (s == Screen::BlePair) go(Screen::Home);
      break;
    case BleEvt::CodeShown:
      if (s == Screen::BlePair) {
        go(Screen::BlePair);  // re-entered: a press that began before the code was drawn cannot confirm it
        buzz_beat();
      }
      break;
    case BleEvt::Paired:
      g_blePairMsg = "PAIRED. This phone is now the only paired phone. press = home";
      buzz_ok();
      g_dirty = true;
      break;
    case BleEvt::PairFailed:
      if (s == Screen::BlePair) {
        g_blePairMsg = "Pairing failed or was rejected. Try again from the phone while this screen is shown.";
        g_bleCodeDrawn = false;
        buzz_err();
        g_dirty = true;
      }
      break;
    case BleEvt::LinkChange:
      if (s == Screen::BlePair) g_dirty = true;
      break;
    case BleEvt::None:
      break;
  }
}
#endif

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
  g_vault = vault_address(g_k1);
  p1_pubkey(g_p1xy);
  bool lost = false;
  if (!store_load_context(g_ctx)) {  // none / older layout (v1, v2 before firmware v1.2) / corrupt: unpaired
    g_ctx = Context();
    lost = store_has_context();  // something was stored but cannot be read: the counters restart at 0
  } else if (g_ctx.paired() && g_ctx.vault != g_vault) {
    // a context pinned for another K1 (cannot happen without writing NVS behind the firmware's back): fail closed
    g_ctx = Context();
    lost = true;
  }
  if (Serial)
    Serial.printf("ripar: K1 %s, vault %s, %s\n", addr_checksum(g_k1).c_str(), addr_checksum(g_vault).c_str(),
                  g_ctx.paired() ? chain_text(g_ctx.chainId).c_str() : lost ? "PAIRING LOST" : "not paired");
#if RIPAR_BLE
  g_k1Short = short_addr(g_k1);  // STATUS JSON (BLE and Wi-Fi)
  g_fwHex = to_hex(g_fwid, 8, false);
#endif
  std::string wifiErr;
  bool wifiFailed = false;
#if RIPAR_WIFI
  // TEST FEATURE: WI-FI ON was chosen (and persisted) earlier, and a network is stored: Wi-Fi starts now (after the
  // self-test and the keys; never on a failed self-test)
  if (wifi_auto_on()) {
    std::string ssid;
    if (!wifi_creds_ssid(ssid)) {
      wifi_set_auto_on(false);  // the choice without a network: dropped
    } else if (!wifi_start(wifiErr)) {
      wifi_off("start at boot failed", false);
      wifiFailed = true;
    }
  }
#endif
  buzz_ok();
  go(Screen::Home);  // drains the key queue, draws the home screen
  if (wifiFailed)
    show_message("WI-FI NOT STARTED", wifiErr + ". The WI-FI ON choice is kept (tried again at the next start); "
                 "FORGET WI-FI in the menu clears it.", UI_WARN);
  if (lost) {
    // fork review N1: a PANIC / REOPEN signed now would repeat epoch / nonce 1, which the chain refuses
    buzz_err();
    show_message("PAIRING LOST",
                 "Stored pairing unreadable (older firmware layout, or corrupt). Panic epoch and reopen nonce restart "
                 "at 0: pair again with the on-chain floors (pair keys 10 / 11: minEpoch, reopenNonce) before PANIC or "
                 "REOPEN.",
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
    case Act::BleConfirm:  // Screen::BlePair only (RIPAR_BLE)
#if RIPAR_BLE
      ble_pair_key(true);
#endif
      break;
    case Act::BleReject:
#if RIPAR_BLE
      ble_pair_key(false);
#endif
      break;
    case Act::Confirm:  // a fully seen WifiJoin / WifiOn review (RIPAR_WIFI): nothing is signed
      confirm_setting();
      break;
    case Act::Home:
    case Act::None:
      break;
  }
  if (g_fsm.screen() == Screen::Scan) tick_scan(now);
#if RIPAR_BLE
  ble_tick(now);
#endif
#if RIPAR_WIFI
  wifi_tick(now);
#endif
#if RIPAR_BLE
  if (uint32_t(now - g_badgeCheck) >= 100) {
    g_badgeCheck = now;
    update_badges();
  }
#endif
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
