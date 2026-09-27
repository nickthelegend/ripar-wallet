// Emulator driver: src/flows.cpp, function by function, over the emulated hardware of emu_hw.h. Each block says
// which flows.cpp function it mirrors; differences are listed where they occur (search "EMULATOR:").
//
// Kept identical: the Fsm (fsm.h) gets exactly one FsmIn per loop pass with the key event + debounced key state read
// together and pulse_update().passed polled in the same pass; on every screen change the same exit / entry side
// effects run (camera + pulse sensor on / off, key-queue drain with swallow, buffer wipes); requests are parsed,
// reviewed, re-checked and signed by the same portable functions; the context is replaced only by a context_after_*()
// result under the same Save rules; the same texts, footers and titles are shown.
#include "emu_core.h"

#include <cstdio>
#include <cstring>

#include "cbor.h"
#include "crypto.h"
#include "hashes.h"
#include "policy.h"
#include "respond.h"
#include "vault.h"

namespace ripar {
namespace emu {

const char* const EMULATOR_ID = "ripar-emulator v1";

const char* screen_name(Screen s) {
  switch (s) {
    case Screen::Fail:
      return "fail";
    case Screen::Home:
      return "home";
    case Screen::HomeHold:
      return "homeHold";
    case Screen::Scan:
      return "scan";
    case Screen::Review:
      return "review";
    case Screen::Pulse:
      return "pulse";
    case Screen::Armed:
      return "armed";
    case Screen::Qr:
      return "qr";
    case Screen::Message:
      return "message";
    case Screen::PairQr:
      return "pairQr";
    case Screen::Menu:
      return "menu";
    case Screen::BlePair:  // Bluetooth pairing (RIPAR_BLE device builds only): never entered by the emulator
      return "blePair";
  }
  return "?";
}

const char* job_name(Job j) {
  switch (j) {
    case Job::Pair:
      return "pair";
    case Job::Cosign:
      return "cosign";
    case Job::Mandate:
      return "mandate";
    case Job::Deny:
      return "deny";
    case Job::Privy:
      return "privy";
    case Job::Revoke:
      return "revoke";
    case Job::Reopen:
      return "reopen";
    default:
      return "none";
  }
}

namespace {

constexpr uint32_t kStepMs = 5;         // io.cpp key timer period; one app_loop() pass per step (app thread free)
// ui.cpp flush(): every frame is composed in a 320x240 RGB565 sprite and pushed to the ST7789 over SPI at 40 MHz
// (Bus_SPI freq_write): 320 * 240 * 16 bit / 40 MHz = 30.72 ms, the lower bound of a draw (the sprite composition and
// the PSRAM reads come on top). The app thread is busy for that long after every draw; the key timer is not.
constexpr uint32_t kFramePushMs = 31;
constexpr uint32_t kScanDrawMs = 60;    // viewfinder refresh
constexpr uint32_t kPulseDrawMs = 80;   // pulse screen refresh
constexpr uint32_t kHomeDrawMs = 2000;  // battery refresh on the home screen
constexpr size_t kSerialLines = 64;

// test/host/crypto_vectors.h DEMO_SEED = sha256("ripar demo seed") (tools/make_request.py DEMO_SEED)
const char* const kDemoSeedText = "ripar demo seed";

// ---- flows.cpp small helpers
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

// mirrors flows.cpp tone_color()
UiColor tone_color(Tone t) {
  switch (t) {
    case Tone::Good:
      return UiColor::Good;
    case Tone::Warn:
      return UiColor::Warn;
    case Tone::Bad:
      return UiColor::Bad;
    case Tone::Dim:
      return UiColor::Dim;
    default:
      return UiColor::Text;
  }
}

// mirrors flows.cpp u64_text()
std::string u64_text(uint64_t v) {
  char b[24];
  std::snprintf(b, sizeof b, "%llu", static_cast<unsigned long long>(v));
  return b;
}

// mirrors flows.cpp ur_type_text()
std::string ur_type_text(const std::string& t) {
  std::string s = ascii_text(t.size() > 48 ? t.substr(0, 48) : t);
  return t.size() > 48 ? s + "..." : s;  // display only: the type is refused either way
}

// mirrors flows.cpp failed_lines(): only the failed checks + the summary line of keys_selftest()
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

// mirrors flows.cpp DeviceSigner: the keys of this device (derive, sign, verify against the cached public key, wipe)
class DeviceSigner : public Signer {
 public:
  explicit DeviceSigner(EmuKeys& k) : k_(k) {}
  bool p1(const B32& digest, uint8_t rs[64]) override { return k_.p1_sign(digest, rs); }
  bool k1(const B32& digest, uint8_t rsv[65]) override { return k_.k1_sign(digest, rsv); }

 private:
  EmuKeys& k_;
};

}  // namespace

// ================================================================================================= power-on
Device::Device(const Options& o) {
  test_ = o.test;
  selftestFault_ = o.selftestFault;
  optCamera_ = o.camera;
  optPulse_ = o.pulseSensor;
  now_ = o.clockMs;
  io_.battery = o.battery;
  if (o.haveContext) store_.preload(o.context);
  // the emulated TRNG (keys.cpp trng_fill): HMAC-DRBG from the companion's entropy; fixed in test mode
  if (test_) {
    Bytes s = o.trngSeed;
    if (s.empty()) {
      const char* t = "ripar-emulator test trng";
      s.resize(32);
      sha256(reinterpret_cast<const uint8_t*>(t), std::strlen(t), s.data());
    }
    trng_.instantiate(s.data(), s.size());
  } else {
    Bytes s = o.entropy;
    const char* dom = "ripar-emulator trng";
    s.insert(s.end(), dom, dom + std::strlen(dom));
    trng_.instantiate(s.data(), s.size());
    wipe_bytes(s);
  }
  // synthetic PPG noise
  uint64_t ppg = o.ppgSeed;
  if (!test_) {
    uint8_t b[8];
    trng_.fill(b, sizeof b);
    ppg = 0;
    for (int i = 0; i < 8; i++) ppg = (ppg << 8) | b[i];
  }
  pulseHw_.synth.seed(ppg);
  // the emulated NVS seed: restored, or DEMO_SEED in test mode; otherwise the first run creates it (create_keys)
  if (o.haveSeed) {
    keys_.store_seed(o.seed);
  } else if (test_) {
    uint8_t demo[32];
    sha256(reinterpret_cast<const uint8_t*>(kDemoSeedText), std::strlen(kDemoSeedText), demo);
    keys_.store_seed(demo);
    wipe(demo, sizeof demo);
  }
  entropy_ = o.entropy;
  app_setup();
  wipe_bytes(entropy_);
}

Device::~Device() {
  wipe_sig_buffers();
  wipe_str(qrText_);
  wipe_bytes(entropy_);
  keys_.wipe_all();
}

void Device::inject_trng(const Bytes& b) {
  if (test_) trng_.inject(b);
}

void Device::serial(const std::string& line) {
  serial_.push_back(line);
  if (serial_.size() > kSerialLines) serial_.erase(serial_.begin());
}

// ================================================================================================= time
void Device::tick(uint32_t ms) {
  pending_ += ms;
  while (pending_ >= kStepMs) {
    pending_ -= kStepMs;
    step();
  }
}

// EMULATOR: the device's key timer runs every 5 ms (io.cpp), the MAX30102 samples at 100 Hz on its own, and
// app_loop() runs back to back (a pass + delay(2)). Here each 5 ms step is one key-timer tick, the sensor catching up
// to now, and one app_loop() pass when the app thread is free. A pass that drew a frame keeps the app thread busy for
// kFramePushMs (the SPI push of the sprite, ui.cpp flush()); the step whose 5 ms slot [now, now + 5) contains the end
// of the push runs that pass's post-draw key drain (flows.cpp app_loop: `if (g_changed) drain_keys(...)`) after its
// key-timer tick, then the next pass. So, as on the device, a press the key timer saw before a screen change is
// stable (debounced) by the time the post-draw drain runs and is swallowed, however late in the old screen's life it
// began; a press first seen after the change pass acts on the new screen.
void Device::step() {
  now_ += kStepMs;
  io_.timer_tick(now_);
  pulseHw_.sensor_tick(now_);
  if (postDrawPending_ && int32_t(postDrawAt_ - now_) < int32_t(kStepMs)) {  // the frame push ends in this slot
    postDrawPending_ = false;
    post_draw();
  }
  if (appBusy_) {
    if (int32_t(appBusyUntil_ - now_) >= int32_t(kStepMs)) return;  // still pushing / stalled for this whole slot
    appBusy_ = appStalled_ = false;
  }
  app_loop();
}

void Device::app_busy(uint32_t until, bool stall) {
  if (!appBusy_ || int32_t(until - appBusyUntil_) > 0) appBusyUntil_ = until;
  appBusy_ = true;
  appStalled_ = appStalled_ || stall;
}

// EMULATOR fault injection: the app thread blocks (e.g. a slow flash write) until now + ms, or until the frame push in
// progress ends if that is later; the key timer, the camera handoff and the sensor keep running.
void Device::stall_app(uint32_t ms) {
  const uint32_t until = now_ + ms;
  if (ms == 0 || (appBusy_ && int32_t(until - appBusyUntil_) <= 0)) return;  // within the frame push: no effect
  app_busy(until, true);
}

// the camera decodes one QR (qrscan.cpp deliver()), then the next app_loop() pass polls it (tick_scan)
ScanStatus Device::scan(const std::string& qrText) {
  scanStatus_ = ScanStatus();
  const EmuCam::Submit d = cam_.submit(qrText, now_);
  if (d == EmuCam::Submit::Off) {  // the camera only runs on the Scan screen
    scanStatus_.result = "camera-off";
    scanStatus_.hint = cam_.present() ? "the camera is off (press on HOME to scan)" : "no camera";
  } else if (d != EmuCam::Submit::Delivered || appStalled_) {
    // nothing reaches the app now: an empty payload, the same payload again within 1 s (qrscan.cpp kRepeatMs), or the
    // app thread is stalled (the payload waits in the handoff slot; a later one replaces it)
    scanStatus_.result = d == EmuCam::Submit::Empty ? "empty" : d == EmuCam::Submit::Repeat ? "repeat" : "pending";
    scanStatus_.progress = scanProgress_;
    scanStatus_.seqLen = unsigned(dec_.seq_len());
    scanStatus_.received = unsigned(dec_.received_pure());
    scanStatus_.hint = ui_sanitize(scanHint_);
  } else {
    // up to the next pass (after the frame push in progress, if any); it polls the slot on SCAN, or leaves SCAN
    // (camera stopped, slot emptied)
    for (int i = 0; i < 64 && cam_.has_pending(); i++) step();
  }
  scanStatus_.screen = screen_name(fsm_.screen());
  return scanStatus_;
}

// ================================================================================================= small helpers
// mirrors flows.cpp wipe_sig_buffers()
void Device::wipe_sig_buffers() {
  wipe(salt_, sizeof salt_);
  wipe(ev_, sizeof ev_);
}

// mirrors flows.cpp firmware_id(). EMULATOR: the device uses the SHA-256 of its app image; the emulator uses
// sha256("ripar-emulator v1"), so a companion can tell an emulated device from a real one.
void Device::firmware_id(uint8_t out[8]) {
  uint8_t sha[32];
  sha256(reinterpret_cast<const uint8_t*>(EMULATOR_ID), std::strlen(EMULATOR_ID), sha);
  std::memcpy(out, sha, 8);
}

// mirrors flows.cpp clear_job()
void Device::clear_job() {
  pair_ = PairReq();
  cosign_ = CosignReq();
  mandate_ = MandateReq();
  deny_ = DenyReq();
  privy_ = PrivyReq();
  review_ = Review();
  lines_.clear();
  footMore_.clear();
  footEnd_.clear();
}

// ================================================================================================= screen changes
// mirrors flows.cpp on_change(): exit / entry side effects of every screen change
void Device::on_change(Screen from, Screen to) {
  if (from != to) {
    if (from == Screen::Scan) {
      cam_.stop();  // qrscan_stop()
      dec_.reset();
    }
    const bool pulseFrom = from == Screen::Pulse || from == Screen::Armed;
    const bool pulseTo = to == Screen::Pulse || to == Screen::Armed;
    if (pulseFrom && !pulseTo) {
      pulseHw_.stop();
      pulse_ = PulseResult();
    }
    if (from == Screen::Qr || from == Screen::PairQr) wipe_str(qrText_);
    if (to == Screen::Home) clear_job();
    if (to == Screen::Scan) {
      dec_.reset();
      scanProgress_ = 0.0f;
      scanHint_ = haveCam_ ? "Scan the request QR - hold 2 s = cancel" : "NO CAMERA DETECTED - hold 2 s = back";
      cam_.start();  // qrscan_start()
    }
    if (to == Screen::Pulse && from == Screen::Review) {  // the review has been shown: start measuring now
      pulse_ = PulseResult();
      pulseHw_.start(now_);
    }
  }
  // nothing pressed before this screen existed may act on it (Armed in particular); again after drawing (app_loop)
  drain_keys(to != Screen::HomeHold);
  changed_ = true;
  dirty_ = true;
  lastDraw_ = 0;
}

// mirrors flows.cpp go()
void Device::go(Screen s) {
  const Screen from = fsm_.screen();
  if (fsm_.go(s, now_)) on_change(from, s);
}

// mirrors flows.cpp show_message()
void Device::show_message(const std::string& title, const std::string& body, UiColor color) {
  msgTitle_ = title;
  msgBody_ = body;
  msgColor_ = color;
  go(Screen::Message);
}

// mirrors flows.cpp refuse()
void Device::refuse(const std::string& title, const std::string& why) {
  io_.buzz_err(now_);
  show_message(title, why.empty() ? std::string("refused") : why, UiColor::Bad);
}

// mirrors flows.cpp show_qr(): builds the response QR text, then wipes the CBOR and every signing buffer
void Device::show_qr(const char* urType, Bytes& cbor, const std::string& title, const std::string& footer) {
  std::string text = ur_encode(urType, cbor);
  wipe_bytes(cbor);
  wipe_sig_buffers();
  qrTitle_ = title;
  qrFooter_ = footer;
  go(Screen::Qr);
  qrText_.swap(text);
  wipe_str(text);
  dirty_ = true;
  lastOutput_ = urType;
  signatures_++;
  serial(std::string("ripar: output ") + urType);
}

// ================================================================================================= reviews
// mirrors flows.cpp open_review()
void Device::open_review(Job job) {
  lines_.clear();
  for (const RLine& l : review_.lines) {
    UiLine rl;
    rl.label = l.label;
    rl.value = l.value;
    rl.color = tone_color(l.tone);
    lines_.push_back(rl);
  }
  const bool cosign = job == Job::Cosign;
  footMore_ = cosign ? "press = more | hold 2s = DENY" : "press = more | hold 2s = cancel";
  if (!review_.ok)
    footEnd_ = cosign ? "REFUSED: press = home | 2s = DENY" : "REFUSED: press = home";
  else if (!job_needs_pulse(job))
    footEnd_ = "press = SIGN (no pulse) | 2s = cancel";
  else
    footEnd_ = cosign ? "press = PULSE + SIGN | 2s = DENY" : "press = PULSE + SIGN | 2s = cancel";
  const Screen from = fsm_.screen();
  if (fsm_.open_review(job, review_.ok, now_)) on_change(from, Screen::Review);
  review_.ok ? io_.buzz_ok(now_) : io_.buzz_err(now_);
}

// mirrors flows.cpp on_request(): PARSE, a complete UR from the camera -> review (or the parser's exact refusal)
void Device::on_request(const std::string& urType, const Bytes& cbor) {
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
      pair_ = r;
      review_ = review_pair(pair_, ctx_, k1_);
      return open_review(Job::Pair);
    }
    case ReqType::Cosign: {
      CosignReq r;
      if (!parse_cosign_req(m, r, err)) return refuse("CO-SIGN REFUSED", err);
      cosign_ = r;
      review_ = review_cosign(cosign_, ctx_);
      return open_review(Job::Cosign);
    }
    case ReqType::Mandate: {
      MandateReq r;
      if (!parse_mandate_req(m, r, err)) return refuse("MANDATE REFUSED", err);
      mandate_ = r;
      review_ = review_mandate(mandate_, ctx_, p1xy_);
      return open_review(Job::Mandate);
    }
    case ReqType::Deny: {
      DenyReq r;
      if (!parse_deny_req(m, r, err)) return refuse("DENY REFUSED", err);
      deny_ = r;
      review_ = review_deny(deny_, ctx_, false);
      return open_review(Job::Deny);
    }
    case ReqType::Privy: {
      PrivyReq r;
      if (!parse_privy_req(m, r, err)) return refuse("PRIVY REQUEST REFUSED", err);
      privy_ = r;
      review_ = review_privy(privy_, p1xy_);
      return open_review(Job::Privy);
    }
    default:
      return refuse("NOT A RIPAR REQUEST", "unsupported request type");
  }
}

// mirrors flows.cpp start_deny_from_cosign(): Long2s on a co-sign review, the device builds the deny itself
void Device::start_deny_from_cosign() {
  DenyReq d;
  std::string err;
  if (!deny_from_cosign(cosign_, ctx_, d, err)) return refuse("DENY NOT POSSIBLE", err);
  deny_ = d;
  review_ = review_deny(deny_, ctx_, true);
  open_review(Job::Deny);
}

// mirrors flows.cpp menu_select()
void Device::menu_select(int item) {
  if (item == MENU_REVOKE) {
    review_ = review_revoke(ctx_);
    open_review(Job::Revoke);
  } else if (item == MENU_REOPEN) {
    review_ = review_reopen(ctx_);
    open_review(Job::Reopen);
  } else {
    go(Screen::Home);
  }
}

// ================================================================================================= signing
// mirrors flows.cpp deliver(): stores the context that goes with a signature (respond.h Save), shows the response QR
void Device::deliver(bool ok, Response& r, const std::string& title, const std::string& err) {
  if (!ok) {
    wipe_bytes(r.cbor);
    wipe_sig_buffers();
    return refuse("NOT SIGNED", err.empty() ? std::string("signing failed") : err);
  }
  std::string footer = "Scan this with the companion. press = done";
  if (r.save != Save::None) {
    const bool saved = store_.save_context(r.next);
    // Restrict (panic): RAM follows even when NVS failed; BestEffort: RAM keeps the old context when NVS failed
    if (saved || r.save == Save::Restrict) ctx_ = r.next;
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
  io_.buzz_ok(now_);
  show_qr(r.urType, r.cbor, title, footer);
}

// mirrors flows.cpp sign_with_pulse(): Act::Sign, the key polled in this pass was Short AND pulse_update().passed
// polled in this same pass was true
void Device::sign_with_pulse(bool pulsePassedThisPass) {
  if (!pulsePassedThisPass) {  // unreachable (Fsm only returns Sign then); fail closed
    go(Screen::Home);
    return;
  }
  DeviceSigner keys(keys_);
  Response r;
  std::string err, title;
  bool ok = false;
  switch (fsm_.job()) {
    case Job::Cosign:
      trng_.fill(salt_, sizeof salt_);  // fresh salt for this signature
      pulseHw_.evidence(ev_);           // read only now: `passed` was checked in this pass
      ok = respond_cosign(cosign_, ctx_, ev_, salt_, keys, r, err);
      title = "CO-SIGNED";
      break;
    case Job::Mandate:
      ok = respond_mandate(mandate_, ctx_, p1xy_, keys, r, err);
      title = "MANDATE SIGNED";
      break;
    case Job::Pair:
      ok = respond_pair(pair_, ctx_, k1_, p1xy_, fwid_, keys, r, err);
      title = "PAIRED";
      break;
    case Job::Privy:
      ok = respond_privy(privy_, keys, r, err);
      title = "PRIVY REQUEST SIGNED";
      break;
    case Job::Revoke:
      ok = respond_revoke(ctx_, keys, r, err);
      title = "REVOKE SIGNED";
      break;
    case Job::Reopen:
      ok = respond_reopen(ctx_, keys, r, err);
      title = "REOPEN SIGNED (nonce " + u64_text(reopen_next_nonce(ctx_)) + ")";
      break;
    default:
      err = "nothing to sign";
      break;
  }
  deliver(ok, r, title, err);
}

// mirrors flows.cpp sign_deny(): Act::SignNoPulse, a fully seen, allowed Deny review
void Device::sign_deny() {
  DeviceSigner keys(keys_);
  Response r;
  std::string err;
  bool ok = false;
  if (fsm_.job() != Job::Deny) {
    err = "nothing to sign";
  } else {
    std::memset(ev_, 0, sizeof ev_);  // no pulse for a deny: all-zero evidence (docs/PROTOCOL.md section 4)
    trng_.fill(salt_, sizeof salt_);
    ok = respond_deny(deny_, ctx_, ev_, salt_, keys, r, err);
  }
  deliver(ok, r, "DENY SIGNED (agent " + u64_text(deny_.agentId) + ")", err);
}

// mirrors flows.cpp do_panic(): Act::Panic, Hold5s on HOMEHOLD; no pulse (panic can only restrict)
void Device::do_panic() {
  DeviceSigner keys(keys_);
  Response r;
  std::string err;
  const uint64_t epoch = panic_next_epoch(ctx_);
  if (!respond_panic(ctx_, keys, r, err)) {
    wipe_sig_buffers();
    return refuse("PANIC REFUSED", err);
  }
  deliver(true, r, "PANIC: min epoch " + u64_text(epoch), err);
}

// mirrors flows.cpp show_pair_qr(): Long2s released on HOME, the unsigned keys-only pairing QR (nothing pinned)
void Device::show_pair_qr() {
  Bytes cbor = build_pair(Bytes(), k1_, p1xy_, nullptr, nullptr, fwid_);
  qrText_ = ur_encode("ripar-pair", cbor);
  qrTitle_ = "PAIR: keys only (nothing pinned)";
  qrFooter_ = "press = back | hold 2s = revoke / reopen";
  dirty_ = true;
}

// ================================================================================================= first run
// mirrors flows.cpp create_keys(). EMULATOR: the device hashes 64 TRNG bytes, raw MAX30102 samples, camera frames and
// timing jitter into `extra`, and keys_create() hashes that with 64 more TRNG bytes and a timer value. The emulator's
// pool is the entropy the companion drew with crypto.getRandomValues(); seed = sha256(pool).
bool Device::create_keys() {
  ui_boot("NEW DEVICE: creating keys (companion entropy)...");
  if (entropy_.size() < 32) {
    serial("ripar: keys created=0 (less than 32 entropy bytes)");
    return false;
  }
  ui_boot("NEW DEVICE: storing the seed...");
  const bool ok = keys_.create(entropy_) && keys_.init();
  serial(std::string("ripar: keys created=") + (ok ? "1" : "0") + " (entropy bytes " + u64_text(entropy_.size()) + ")");
  return ok;
}

// mirrors flows.cpp enter_fail()
void Device::enter_fail(const std::string& why) {
  failText_ = why + "\nSIGNING IS DISABLED.";
  fsm_.fail();
  io_.buzz_err(now_);
  ui_message("SELFTEST FAIL", failText_, UiColor::Bad);
  serial("ripar: FAIL " + why);
}

// ================================================================================================= drawing
void Device::new_frame(Frame::Kind k) {
  const uint32_t seq = frame_.seq + 1;
  frame_ = Frame();
  frame_.kind = k;
  frame_.seq = seq;
  frame_.at = now_;
}

void Device::ui_boot(const std::string& status) {
  new_frame(Frame::Boot);
  frame_.title = "RIPAR";
  frame_.body = status;
  frame_.lines = ui_wrap(status, LCD_W - 20);
  if (frame_.lines.size() > 2) frame_.lines.resize(2);
}

void Device::ui_home(const std::string& k1short, int battery, bool paired) {
  new_frame(Frame::Home);
  frame_.k1short = k1short;
  frame_.battery = battery;
  frame_.paired = paired;
}

void Device::ui_scan(float progress, const std::string& hint) {
  new_frame(Frame::Scan);
  frame_.progress = progress;
  frame_.hint = ui_sanitize(hint);
}

UiReview Device::ui_review(const std::string& title, const std::vector<UiLine>& lines, int firstRow,
                           const std::string& footerMore, const std::string& footerEnd) {
  new_frame(Frame::Review);
  frame_.review = ui_review_model(title, lines, firstRow, footerMore, footerEnd);
  frame_.title = frame_.review.title;
  frame_.footer = frame_.review.footer;
  return frame_.review;
}

void Device::ui_pulse(const PulseResult& p, const std::string& title, uint32_t now) {
  if (p.beatNow) lastBeat_ = now;  // ui_pulse()'s static lastBeat
  new_frame(Frame::Pulse);
  frame_.title = ui_sanitize(title);
  frame_.pulse = p;
  frame_.heartBig = p.finger && lastBeat_ != 0 && now - lastBeat_ < 180;
  char buf[32];
  if (p.finger && p.bpm > 0.0f)
    std::snprintf(buf, sizeof buf, "%d", int(p.bpm + 0.5f));
  else
    std::snprintf(buf, sizeof buf, "--");
  frame_.bpmText = buf;
  std::snprintf(buf, sizeof buf, "beats %d / %d", p.beats, PulseConfig().minBeats);
  frame_.beatsText = buf;
  std::snprintf(buf, sizeof buf, "%.1f s", double(p.elapsedMs) / 1000.0);
  frame_.elapsedText = buf;
  if (!p.finger) {
    frame_.status = "Place your thumb on the sensor";
    frame_.statusColor = UiColor::Warn;
  } else if (p.passed) {
    frame_.status = "PULSE OK - press SIGN";
    frame_.statusColor = UiColor::Good;
  } else {
    frame_.status = "Measuring... keep still";
    frame_.statusColor = UiColor::Text;
  }
}

void Device::ui_qr(const std::string& text, const std::string& title, const std::string& footer) {
  const UiQr q = ui_qr_model(text);
  if (!q.fits) {
    ui_message("QR TOO LARGE", "The response does not fit in one QR code on this screen.", UiColor::Bad);
    return;
  }
  new_frame(Frame::Qr);
  frame_.qr = q;
  frame_.title = ui_sanitize(title);
  frame_.footer = ui_sanitize(footer);
}

void Device::ui_message(const std::string& title, const std::string& body, UiColor color) {
  new_frame(Frame::Message);
  frame_.title = ui_sanitize(title);
  frame_.color = color;
  frame_.body = body;
  frame_.lines = ui_message_lines(body);
}

// mirrors flows.cpp draw()
void Device::draw(uint32_t now) {
  const Screen s = fsm_.screen();
  switch (s) {
    case Screen::Fail:
      if (dirty_) ui_message("SELFTEST FAIL", failText_, UiColor::Bad);
      break;
    case Screen::Home:
      if (dirty_ || now - lastDraw_ >= kHomeDrawMs) {
        ui_home(short_addr(k1_), io_.battery, ctx_.paired());
        lastDraw_ = now;
      }
      break;
    case Screen::HomeHold:
      if (dirty_)
        ui_message("RELEASE = PAIRING QR",
                   "Keep holding to 5 s for PANIC: signs Panic(min epoch + 1) at once, no pulse needed.", UiColor::Warn);
      break;
    case Screen::Scan:
      if (dirty_ || now - lastDraw_ >= kScanDrawMs) {
        ui_scan(scanProgress_, scanHint_);  // EMULATOR: no viewfinder image
        lastDraw_ = now;
      }
      break;
    case Screen::Review:
      if (dirty_) {
        const UiReview v = ui_review(review_.title, lines_, fsm_.review_row(), footMore_, footEnd_);
        fsm_.review_drawn(v.firstRow, v.rowsShown, v.totalRows);
      }
      break;
    case Screen::Pulse:
    case Screen::Armed:
      if (dirty_ || now - lastDraw_ >= kPulseDrawMs) {
        const std::string title = !havePulse_ ? std::string("NO PULSE SENSOR - cannot sign")
                                  : s == Screen::Armed ? "ARMED: press SIGN (" + review_.title + ")"
                                                       : "PULSE: " + review_.title;
        ui_pulse(pulse_, title, now);
        lastDraw_ = now;
      }
      break;
    case Screen::Qr:
    case Screen::PairQr:
      if (dirty_) ui_qr(qrText_, qrTitle_, qrFooter_);
      break;
    case Screen::Message:
      if (dirty_) ui_message(msgTitle_, msgBody_, msgColor_);
      break;
    case Screen::Menu:
      if (dirty_) {
        static const char* const kItems[MENU_ITEMS] = {"REVOKE the last mandate", "REOPEN the agent lane", "BACK"};
        std::vector<UiLine> lines;
        for (int i = 0; i < MENU_ITEMS; i++) {
          UiLine l;
          l.value = std::string(i == fsm_.menu_index() ? "> " : "   ") + kItems[i];
          l.color = i == fsm_.menu_index() ? UiColor::Accent : UiColor::Dim;
          lines.push_back(l);
        }
        UiLine note;
        note.value = "Both need pulse + SIGN and use the contracts pinned at pairing.";
        note.color = UiColor::Dim;
        lines.push_back(note);
        ui_review("DEVICE ACTIONS", lines, 0, "press = next | hold 2s = select", "press = next | hold 2s = select");
      }
      break;
    case Screen::BlePair:  // the emulator has no radio (RIPAR_BLE device builds only): never entered
      break;
  }
  dirty_ = false;
}

// ================================================================================================= scanning
// mirrors flows.cpp tick_scan()
void Device::tick_scan(uint32_t now) {
  std::string payload;
  if (!cam_.poll(payload)) return;
  const UrDecoder::Result r = dec_.receive(payload);
  if (r == UrDecoder::Complete) {
    io_.buzz_ok(now);
    const std::string type = dec_.type();
    const Bytes msg = dec_.message();
    scanStatus_.result = "complete";
    scanStatus_.progress = 1.0f;
    scanStatus_.seqLen = unsigned(dec_.seq_len());
    scanStatus_.received = scanStatus_.seqLen ? scanStatus_.seqLen : 1;
    on_request(type, msg);  // -> Review or Message (the camera stops on leaving Scan)
    return;
  }
  if (r == UrDecoder::Accepted) {
    fsm_.touch(now);
    const float p = dec_.progress();
    if (p > scanProgress_) io_.buzz_beat(now);
    scanProgress_ = p;
    char hint[64];
    std::snprintf(hint, sizeof hint, "multipart: %u of %u parts - keep the code in view",
                  static_cast<unsigned>(dec_.received_pure()), static_cast<unsigned>(dec_.seq_len()));
    scanHint_ = hint;
    scanStatus_.result = "accepted";
  } else if (r == UrDecoder::Error) {
    io_.buzz_err(now);
    scanHint_ = "bad QR part: " + dec_.error();  // progress so far is kept
    scanStatus_.result = "error";
  } else {
    scanHint_ = "not a Ripar request QR";
    scanStatus_.result = "ignored";
  }
  scanStatus_.progress = scanProgress_;
  scanStatus_.seqLen = unsigned(dec_.seq_len());
  scanStatus_.received = unsigned(dec_.received_pure());
  scanStatus_.hint = scanHint_;
}

// ================================================================================================= entry points
// mirrors flows.cpp app_setup()
void Device::app_setup() {
  io_.init(now_);
  ui_boot("starting...");
  havePulse_ = pulseHw_.init(optPulse_);
  haveCam_ = cam_.init(optCamera_);
  firmware_id(fwid_);
  keys_.init();
  serial(std::string("ripar: pulse sensor ") + (havePulse_ ? "ok" : "MISSING") + ", camera " +
         (haveCam_ ? "ok" : "MISSING") + " (emulated), fw " + to_hex(fwid_, 8, false));

  // SELFTEST: crypto against published vectors + the Python reference (and the device keys, if there are any)
  ui_boot("self-test: crypto vectors...");
  std::string report;
  selftestPassed_ = keys_.selftest(report, selftestFault_);
  selftestReport_ = report;
  if (!selftestPassed_) return enter_fail(failed_lines(report));
  serial(failed_lines(report));

  // first run: create the keys, then test them too
  if (!keys_.have_seed()) {
    if (!create_keys()) return enter_fail("key creation failed");
    ui_boot("self-test: new device keys...");
    report.clear();
    selftestPassed_ = keys_.selftest(report, selftestFault_);
    selftestReport_ = report;
    if (!selftestPassed_) return enter_fail(failed_lines(report));
  }
  if (!keys_.init()) return enter_fail("cannot load the device keys");
  k1_ = keys_.k1_address();
  vault_ = vault_address(k1_);
  keys_.p1_pubkey(p1xy_);
  bool lost = false;
  if (!store_.load_context(ctx_)) {  // none / older layout (v1, v2 before firmware v1.2) / corrupt: unpaired
    ctx_ = Context();
    lost = store_.has_context();  // something was stored but cannot be read: the counters restart at 0
  } else if (ctx_.paired() && ctx_.vault != vault_) {
    // a context pinned for another K1 (cannot happen without writing NVS behind the firmware's back): fail closed.
    // EMULATOR: reachable here by restoring an exportNvs() context with another device's seed
    ctx_ = Context();
    lost = true;
  }
  serial("ripar: K1 " + addr_checksum(k1_) + ", vault " + addr_checksum(vault_) + ", " +
         (ctx_.paired() ? chain_text(ctx_.chainId) : lost ? std::string("PAIRING LOST") : std::string("not paired")));
  io_.buzz_ok(now_);
  go(Screen::Home);  // drains the key queue, draws the home screen
  if (lost) {
    io_.buzz_err(now_);
    show_message("PAIRING LOST",
                 "Stored pairing unreadable (older firmware layout, or corrupt). Panic epoch and reopen nonce restart "
                 "at 0: pair again with the on-chain floors (pair keys 10 / 11: minEpoch, reopenNonce) before PANIC or "
                 "REOPEN.",
                 UiColor::Warn);
  }
  // EMULATOR: the device draws in its first app_loop() pass; draw now so state() has a screen right after power-on
  // (with that pass's frame push and post-draw key drain)
  draw_and_push(now_);
}

// mirrors flows.cpp app_loop(): one pass
void Device::app_loop() {
  const uint32_t now = now_;
  passes_++;
  FsmIn in;
  in.nowMs = now;
  in.key = io_.poll_key_state(now, in.keyDown);  // event + debounced state, read atomically
  const Screen before = fsm_.screen();
  if (before == Screen::Pulse || before == Screen::Armed) {
    pulse_ = pulseHw_.update(now);  // polled AFTER the key, in the same pass: the gate sees both together
    in.pulsePassed = pulse_.passed;
    if (pulse_.beatNow) io_.buzz_beat(now);
  }
  const Act a = fsm_.step(in);
  const Screen after = fsm_.screen();
  if (after != before) on_change(before, after);
  // RIPAR_LED_CHALLENGE: 0 in the device build (docs/FIRMWARE.md), so not emulated
  switch (a) {
    case Act::Redraw:
      dirty_ = true;
      break;
    case Act::Ignored:
      io_.buzz_err(now);
      break;
    case Act::PairQr:
      show_pair_qr();
      break;
    case Act::Panic:
      do_panic();
      break;
    case Act::MenuSelect:
      menu_select(fsm_.menu_index());
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
      io_.buzz_err(now);
      break;
    case Act::Home:
    case Act::None:
    case Act::BleConfirm:  // only on Screen::BlePair, which the emulator (no radio) never enters
    case Act::BleReject:
      break;
  }
  if (fsm_.screen() == Screen::Scan) tick_scan(now);
  draw_and_push(now);
}

// draw(), then (after the frame push, Device::step) the rest of the pass
void Device::draw_and_push(uint32_t now) {
  const uint32_t seq = frame_.seq;
  draw(now);
  if (frame_.seq != seq) {  // a frame was drawn: the SPI push keeps the app thread busy, the key timer runs on
    postDrawPending_ = true;
    postDrawAt_ = now + kFramePushMs;
    app_busy(postDrawAt_, false);
    return;
  }
  post_draw();
}

// mirrors the tail of flows.cpp app_loop()
void Device::post_draw() {
  // a press made while the previous screen was still displayed (before this one was drawn) is dropped too, and one
  // that is still down is swallowed until it is released
  if (changed_) {
    drain_keys(fsm_.screen() != Screen::HomeHold);
    changed_ = false;
  }
}

}  // namespace emu
}  // namespace ripar
