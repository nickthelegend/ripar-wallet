// Device-only modules (ESP32-S3, Arduino-ESP32 2.0.x): keys, sensors, camera, display, storage, buttons.
#pragma once
#include <functional>
#include <string>
#include <vector>

#include "context.h"
#include "fsm.h"  // Key (BOOT key events)
#include "pulse_algo.h"
#include "util.h"

namespace ripar {

// ---------------- keys.cpp (mbedTLS) ----------------
// Seed lives in NVS namespace "ripar" key "seed" (32 bytes). K1 = BIP32 secp256k1 m/44'/60'/0'/0/0,
// P1 = SLIP-10 nist256p1 m/7951'/0'. All signatures RFC6979 + low-s.
bool keys_init();                               // load seed (false if none yet)
bool keys_create(const uint8_t extra32[32]);    // new seed = sha256(esp_random pool || extra32); stores it
bool keys_have_seed();
void keys_wipe();
Addr k1_address();
void p1_pubkey(uint8_t xy64[64]);
bool k1_sign(const B32& digest, uint8_t rsv65[65]);  // v = 27/28
bool p1_sign(const B32& digest, uint8_t rs64[64]);
bool p1_sign_der(const B32& digest, Bytes& der);
// derivation from an explicit seed (used by the self-test vectors)
bool derive_keys_from_seed(const uint8_t seed[32], uint8_t k1priv[32], uint8_t p1priv[32]);
bool keys_selftest(std::string& report);        // RFC6979 P-256 vector, secp256k1 vectors, sign/verify
void trng_fill(uint8_t* p, size_t n);           // esp_fill_random

// ---------------- store.cpp (NVS) ----------------
// Context (include/context.h): chain + contracts pinned at pairing (chainId, DelegationManager, PulseCosignEnforcer,
// sentinel, relay, registry, vault), the last mandate this device signed (lastDelegationHash, agentId) and the
// monotonic counters (minEpoch, reopenNonce, notBefore). NVS layout version 2 (src/context.cpp). Only written with
// a Context returned by the policy.h context_after_*() helpers (pairing / the device's own signatures).
bool store_load_context(Context& c);        // false = none / old layout / corrupt -> treat as unpaired
bool store_has_context();                   // a context blob is stored (whether or not it can be loaded)
bool store_save_context(const Context& c);  // writes, then reads back and compares

// ---------------- io.cpp ----------------
// Key (fsm.h): BOOT key events (released after <1s / held 2s / held 5s)
void io_init();
Key io_poll_key();          // non-blocking, debounced
// the next event AND the debounced key state, read atomically (the timer updates both in one critical section)
Key io_poll_key_state(bool& down);
// drops every queued event; swallowHeld: a press that is still down produces no further event (no Short on its
// release, no Long2s / Hold5s) - call it on every screen change so a press only acts on the screen it began on
void io_flush(bool swallowHeld);
bool io_key_down();
void buzz(int freqHz, int ms);  // non-blocking tone on PIN_BUZZER (LEDC)
void buzz_ok();
void buzz_err();
void buzz_beat();
int battery_percent();      // -1 if unknown

// ---------------- pulse.cpp (MAX30102 on shared I2C) ----------------
bool pulse_init();          // probe 0x57, PART_ID 0x15
void pulse_start();         // LEDs on, 100 Hz, FIFO
void pulse_stop();          // shutdown mode
const PulseResult& pulse_update();  // drain FIFO into PulseDetector; call every loop
void pulse_evidence(uint8_t ev12[12]);
// raw FIFO samples (18-bit IR / red) while running, NOT fed to the detector: entropy for first-run key creation.
// Returns the count (0 when stopped / absent / I2C error).
int pulse_raw_samples(uint32_t* ir, uint32_t* red, int maxN);
// liveness challenge (P1 F12): change LED drive and check the DC follows; returns true if it did
bool pulse_led_challenge();

// ---------------- qrscan.cpp (esp32-camera + quirc on core 0) ----------------
bool qrscan_init();         // camera probe; false if absent
void qrscan_start();        // power up, grayscale QVGA 320x240
void qrscan_stop();         // power down (PWDN)
bool qrscan_poll(std::string& payload);  // latest decoded QR text since last poll
// latest grayscale frame for the viewfinder (320x240, 1 byte/px) or nullptr; call qrscan_release_frame after use
const uint8_t* qrscan_frame(int& w, int& h);
void qrscan_release_frame();
int camera_pid();           // sensor PID (0 if none)

// ---------------- ui.cpp (LovyanGFX, landscape 320x240) ----------------
// RGB565 colours of the UI (review.h Tone -> Normal UI_TEXT, Good UI_GOOD, Warn UI_WARN, Bad UI_BAD, Dim UI_DIM)
constexpr uint16_t ui_rgb(uint8_t r, uint8_t g, uint8_t b) {
  return uint16_t(((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3));
}
constexpr uint16_t UI_TEXT = ui_rgb(255, 255, 255);
constexpr uint16_t UI_DIM = ui_rgb(140, 140, 140);
constexpr uint16_t UI_ACCENT = ui_rgb(0, 200, 170);
constexpr uint16_t UI_GOOD = ui_rgb(40, 210, 80);
constexpr uint16_t UI_WARN = ui_rgb(255, 176, 0);
constexpr uint16_t UI_BAD = ui_rgb(240, 40, 40);

struct ReviewLine {
  std::string label, value;
  uint16_t color = 0xFFFF;
};
// What a ui_review() call put on screen (display rows, after clamping).
struct ReviewView {
  int firstRow = 0;   // first display row drawn
  int rowsShown = 0;  // rows drawn
  int totalRows = 0;  // rows of all lines
  bool moreAbove = false, moreBelow = false;  // rows hidden above / below (indicators drawn)
};
void ui_init();
void ui_boot(const char* status);
void ui_home(const std::string& k1short, int battery, bool paired);
void ui_scan(const uint8_t* gray, int w, int h, float progress, const char* hint);
// Review screen (security review M2): every line is split into display rows first (label column + wrapped value, or
// the full width when the label is empty); `firstRow` is the first ROW to draw, clamped with fsm.h
// review_clamp_first(). Arrows + a scrollbar show whenever rows are hidden. The footer is `footerMore` while rows
// are hidden below and `footerEnd` once the last row is on screen. Report the result to Fsm::review_drawn().
ReviewView ui_review(const char* title, const std::vector<ReviewLine>& lines, int firstRow, const char* footerMore,
                     const char* footerEnd);
void ui_pulse(const PulseResult& p, const char* title);
void ui_qr(const std::string& text, const char* title, const char* footer);
void ui_message(const char* title, const std::string& body, uint16_t color);
void ui_fingerprint(int x, int y, const uint8_t idx[4]);  // 4 icons

// ---------------- flows.cpp ----------------
void app_setup();
void app_loop();

}  // namespace ripar
