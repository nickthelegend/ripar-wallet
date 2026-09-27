// Ripar device emulator: the firmware's portable modules (fsm, protocol, policy, review, respond, context, ur, cbor,
// crypto, pulse_algo, ...) driven by a C++ port of the device driver src/flows.cpp, over emulated hardware
// (emu_hw.h) in emulated time. One Device = one emulated signer.
//
// Parity rule: every decision the device makes is made here by the SAME portable code (Fsm::step for every key,
// review_*() for every review line, respond_*() for every signature, context_after_*() for every context change,
// PulseDetector for the pulse gate). emu_core.cpp only re-does what flows.cpp does around them, function by function.
//
// Time: the emulator has its own millis() clock. It advances only through tick(): each 5 ms step runs the key timer
// (io.cpp), the pulse sensor's sampling, and one app_loop() pass unless the app thread is still busy. It is busy for
// kFramePushMs after every frame it draws (ui.cpp flush() pushes the whole 320x240 RGB565 sprite over SPI at 40 MHz:
// 153,600 bytes = 30.72 ms at least), and the post-draw key drain of a screen change runs when that push is done, as
// on the device. The key timer and the sensor keep running meanwhile.
#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "context.h"
#include "emu_hw.h"
#include "emu_ui.h"
#include "fsm.h"
#include "protocol.h"
#include "pulse_algo.h"
#include "respond.h"
#include "review.h"
#include "ur.h"

namespace ripar {
namespace emu {

// "ripar-emulator v1": the pairing response's firmware id is the first 8 bytes of its SHA-256
extern const char* const EMULATOR_ID;

const char* screen_name(Screen s);  // "home", "homeHold", "scan", "review", "pulse", "armed", "qr", ...
const char* job_name(Job j);        // "none", "pair", "cosign", "mandate", "deny", "privy", "revoke", "reopen"

struct Options {
  Bytes entropy;               // >= 32 bytes from crypto.getRandomValues: first-run seed pool + TRNG seed
  bool haveSeed = false;       // restore an emulated device: its NVS seed
  uint8_t seed[32] = {0};
  bool haveContext = false;    // the NVS context blob the JS side persisted (hex of context_serialize())
  Bytes context;
  bool test = false;           // deterministic test mode (seed = DEMO_SEED unless given, fixed TRNG / PPG seeds)
  Bytes trngSeed;              // test mode: DRBG seed (default: sha256("ripar-emulator test trng"))
  uint64_t ppgSeed = 1;        // synthetic PPG noise seed (test mode: fixed; otherwise from the TRNG)
  bool selftestFault = false;  // corrupt one expected self-test value -> SELFTEST FAIL
  uint32_t clockMs = 1000;     // millis() at power-on
  int battery = 87;
  bool camera = true;          // hardware present at power-on (the device also runs without them:
  bool pulseSensor = true;     //   no camera = nothing can be scanned, no sensor = only deny / PANIC)
};

// what the last scan() did (qrscan.cpp deliver(), then tick_scan's UrDecoder result)
struct ScanStatus {
  // none | camera-off | empty | repeat (same payload within 1 s: not delivered) | pending (the app thread is stalled:
  // in the handoff slot) | ignored | accepted | complete | error
  std::string result = "none";
  float progress = 0;
  unsigned received = 0, seqLen = 0;
  std::string hint;
  std::string screen;  // screen after the pass
};

// the last screen drawn (what the LCD shows)
struct Frame {
  enum Kind : uint8_t { Boot, Home, Message, Scan, Review, Pulse, Qr };
  Kind kind = Boot;
  uint32_t seq = 0, at = 0;  // draw counter, millis() of the draw
  std::string title;
  UiColor color = UiColor::Text;
  // Boot / Message
  std::string body;
  std::vector<std::string> lines;
  // Home
  std::string k1short;
  int battery = -1;
  bool paired = false;
  // Scan
  float progress = 0;
  std::string hint;
  // Review / Menu
  UiReview review;
  // Pulse
  PulseResult pulse;
  bool heartBig = false;
  std::string bpmText, beatsText, elapsedText, status;
  UiColor statusColor = UiColor::Text;
  // Qr
  UiQr qr;
  std::string footer;
};

class Device {
 public:
  explicit Device(const Options& o);  // power-on: app_setup()
  ~Device();

  // ---- the outside world
  void key(bool down) { io_.set_raw(down); }  // BOOT key level (sampled by the 5 ms key timer)
  bool key_raw() const { return io_.raw(); }
  void tick(uint32_t ms);                     // advance emulated time (5 ms steps)
  ScanStatus scan(const std::string& qrText); // the camera decodes one QR (then one 5 ms step)
  void finger(const PpgParams& p) { pulseHw_.synth.set(p, now_); }
  const PpgParams& finger_params() const { return pulseHw_.synth.params(); }
  void inject_trng(const Bytes& b);           // test mode only
  void add_entropy(const Bytes& b) { trng_.reseed(b.data(), b.size()); }
  void set_nvs_fail(bool f) { store_.failWrites = f; }
  void set_battery(int b) { io_.battery = b; }
  void set_pulse_fault(EmuPulse::Fault f) { pulseHw_.set_fault(f); }  // I2C stall / hot unplug of the MAX30102
  void stall_app(uint32_t ms);  // fault injection: the app thread blocks for `ms` (key timer + sensor keep running)
  bool test_mode() const { return test_; }
  uint32_t now() const { return now_; }

  // ---- JSON views (emu_state.cpp)
  std::string state_json() const;
  std::string context_json() const;
  std::string nvs_json() const;

 private:
  // hardware
  EmuIo io_;
  EmuPulse pulseHw_;
  EmuCam cam_;
  EmuStore store_;
  EmuTrng trng_;
  EmuKeys keys_;
  Bytes entropy_;  // first-run seed pool, wiped after key creation
  bool test_ = false, selftestFault_ = false, optCamera_ = true, optPulse_ = true;
  uint32_t now_ = 0, pending_ = 0;
  std::string selftestReport_;
  bool selftestPassed_ = false;
  std::vector<std::string> serial_;  // the device's serial log lines
  Frame frame_;
  uint32_t lastBeat_ = 0;  // ui_pulse()'s static lastBeat
  ScanStatus scanStatus_;
  uint32_t signatures_ = 0;
  std::string lastOutput_;  // UR type of the last response shown ("ripar: output <type>")

  // ---- flows.cpp globals (same names without g_)
  Fsm fsm_;
  Context ctx_;
  Addr k1_;
  Addr vault_;  // vault_address(k1_): the only vault this device pins (vault.h; flows.cpp g_vault)
  uint8_t p1xy_[64] = {0};
  uint8_t fwid_[8] = {0};
  bool havePulse_ = false, haveCam_ = false;
  std::string failText_;
  PairReq pair_;
  CosignReq cosign_;
  MandateReq mandate_;
  DenyReq deny_;
  PrivyReq privy_;
  Review review_;
  std::vector<UiLine> lines_;
  std::string footMore_, footEnd_;
  UrDecoder dec_;
  std::string scanHint_;
  float scanProgress_ = 0.0f;
  PulseResult pulse_;
  std::string qrText_, qrTitle_, qrFooter_;
  std::string msgTitle_, msgBody_;
  UiColor msgColor_ = UiColor::Text;
  uint8_t salt_[16] = {0}, ev_[12] = {0};
  bool dirty_ = true, changed_ = false;
  uint32_t lastDraw_ = 0;

  // ---- the app thread's time (EMULATOR: the device's pass takes time; here only the frame push and an injected stall)
  bool appBusy_ = false, appStalled_ = false;
  uint32_t appBusyUntil_ = 0;    // millis() when the frame push / the stall ends
  bool postDrawPending_ = false;  // the post-draw part of the last pass runs when its frame push ends
  uint32_t postDrawAt_ = 0;
  uint32_t passes_ = 0;           // app_loop() passes run

  // ---- flows.cpp functions
  void step();  // one 5 ms step: key timer, sensor, app_loop() (when the app thread is free)
  void app_busy(uint32_t until, bool stall);
  void post_draw();  // the tail of app_loop() after draw(): the second key drain of a screen change
  void draw_and_push(uint32_t now);  // draw(); a drawn frame keeps the app thread busy for kFramePushMs
  void serial(const std::string& line);
  void wipe_sig_buffers();
  void drain_keys(bool swallowHeld) { io_.flush(swallowHeld); }
  void firmware_id(uint8_t out[8]);
  void clear_job();
  void on_change(Screen from, Screen to);
  void go(Screen s);
  void show_message(const std::string& title, const std::string& body, UiColor color);
  void refuse(const std::string& title, const std::string& why);
  void show_qr(const char* urType, Bytes& cbor, const std::string& title, const std::string& footer);
  void open_review(Job job);
  void on_request(const std::string& urType, const Bytes& cbor);
  void start_deny_from_cosign();
  void menu_select(int item);
  void deliver(bool ok, Response& r, const std::string& title, const std::string& err);
  void sign_with_pulse(bool pulsePassedThisPass);
  void sign_deny();
  void do_panic();
  void show_pair_qr();
  bool create_keys();
  void enter_fail(const std::string& why);
  void draw(uint32_t now);
  void tick_scan(uint32_t now);
  void app_setup();
  void app_loop();
  // ui.cpp screens -> frame_
  void ui_boot(const std::string& status);
  void ui_home(const std::string& k1short, int battery, bool paired);
  void ui_scan(float progress, const std::string& hint);
  UiReview ui_review(const std::string& title, const std::vector<UiLine>& lines, int firstRow,
                     const std::string& footerMore, const std::string& footerEnd);
  void ui_pulse(const PulseResult& p, const std::string& title, uint32_t now);
  void ui_qr(const std::string& text, const std::string& title, const std::string& footer);
  void ui_message(const std::string& title, const std::string& body, UiColor color);
  void new_frame(Frame::Kind k);

};

}  // namespace emu
}  // namespace ripar
