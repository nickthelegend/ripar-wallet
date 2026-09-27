// Device bring-up / link check for env chk_device (no flows.cpp, no protocol code).
// Serial 115200 prints the key self-test and the probe results. BOOT key:
//   Short  -> next screen (home, scan, pulse, qr, review+fingerprint, message)
//   Long2s -> screen action: scan = restart camera, pulse = LED challenge,
//             home = create a seed if none exists (writes NVS!)
//   Hold5s -> buzz_err (stands in for PANIC)
// The signing entry points are exercised by keys_selftest() (device keys, fixed internal digest) when a seed exists.
#include <Arduino.h>

#include <cctype>
#include <cstdio>
#include <string>
#include <vector>

#include "board.h"
#include "device.h"

using namespace ripar;

namespace {

enum Screen { kHome, kScan, kPulse, kQr, kReview, kMessage, kCount };
int g_screen = kHome;
bool g_pulseOk = false, g_camOk = false;
uint32_t g_lastDraw = 0;
std::string g_lastQr;
int g_qrCount = 0;

// keep every device entry point referenced so the link step reports anything missing
void (*volatile g_keep[])() = {&keys_wipe, &pulse_stop, &qrscan_stop, &qrscan_release_frame};
bool (*volatile g_keepStore)(const Context&) = &store_save_context;  // link check only, never called

std::string k1_short() { return keys_have_seed() ? short_addr(k1_address()) : std::string(); }

void enter(int s) {
  if (g_screen == kScan && s != kScan) qrscan_stop();
  if (g_screen == kPulse && s != kPulse) pulse_stop();
  g_screen = s;
  if (s == kScan && g_camOk) qrscan_start();
  if (s == kPulse && g_pulseOk) pulse_start();
  g_lastDraw = 0;
}

void draw_static() {
  switch (g_screen) {
    case kHome:
      ui_home(k1_short(), battery_percent(), false);
      break;
    case kQr: {
      uint8_t xy[64];
      p1_pubkey(xy);
      std::string ur = "UR:RIPAR-PAIR/" + to_hex(xy, 16, false);
      for (auto& ch : ur) ch = char(toupper(ch));
      ui_qr(ur, "PAIR", "scan with the companion");
      break;
    }
    case kReview: {
      std::vector<ReviewLine> lines;
      lines.push_back({"Action", "Transfer", 0xFFFF});
      lines.push_back({"Amount", "12.5 AUSD", 0x07E0});
      lines.push_back({"To", short_addr(k1_address()), 0xFFFF});
      lines.push_back({"", "A long companion-provided note that has to wrap over several lines on the screen.",
                       0xFD20});
      for (int i = 0; i < 8; i++) lines.push_back({"Line " + std::to_string(i), "value", 0xFFFF});
      ui_review("CO-SIGN", lines, 0, "press = more", "SIGN: press | DENY: hold 2s");
      const uint8_t fp[4] = {0x03, 0x4A, 0x95, 0xFE};
      ui_fingerprint(180, 34, fp);
      break;
    }
    case kMessage: {
      char b[160];
      std::snprintf(b, sizeof b, "pulse sensor: %s\ncamera: %s (PID 0x%04X)\nbattery: %d%%\nseed: %s",
                    g_pulseOk ? "ok" : "missing", g_camOk ? "ok" : "missing", camera_pid(), battery_percent(),
                    keys_have_seed() ? "yes" : "no");
      ui_message("DEVICE CHECK", b, 0x07E0);
      break;
    }
    default:
      break;
  }
}

}  // namespace

void setup() {
  Serial.begin(115200);
  delay(200);
  io_init();
  ui_init();
  ui_boot("device check...");
  g_pulseOk = pulse_init();
  g_camOk = qrscan_init();
  keys_init();
  Serial.printf("pulse=%d camera=%d pid=0x%04X battery=%d\n", g_pulseOk, g_camOk, camera_pid(), battery_percent());

  std::string report;
  const bool ok = keys_selftest(report);
  Serial.print(report.c_str());
  Context ctx;
  Serial.printf("context in NVS: %s\n", store_load_context(ctx) ? "yes" : "no");
  ui_message(ok ? "SELFTEST PASS" : "SELFTEST FAIL", report, ok ? 0x07E0 : 0xF800);
  ok ? buzz_ok() : buzz_err();
  delay(1500);
#ifdef RIPAR_CHECK_START_PULSE
  enter(kPulse);  // bench option: start on the pulse screen
#else
  enter(kHome);
#endif
}

void loop() {
  const Key k = io_poll_key();
  if (k == Key::Short) {
    buzz_beat();
    enter((g_screen + 1) % kCount);
  } else if (k == Key::Hold5s) {
    buzz_err();
  } else if (k == Key::Long2s) {
    if (g_screen == kScan) {
      qrscan_stop();
      qrscan_start();
    } else if (g_screen == kPulse) {
      const bool live = pulse_led_challenge();
      Serial.printf("LED challenge: %s\n", live ? "followed" : "FAILED");
      live ? buzz_ok() : buzz_err();
    } else if (g_screen == kHome && !keys_have_seed()) {
      uint8_t extra[32];
      trng_fill(extra, sizeof extra);
      const bool created = keys_create(extra) && keys_init();
      Serial.printf("keys_create: %s\n", created ? "ok" : "FAILED");
      // (no store_save_context here: the pinned Context is only ever written by the pairing flow / the device's
      // own signatures - security review M3; a fake context would make the real firmware look paired)
      g_lastDraw = 0;
    }
  }

  const uint32_t now = millis();
  switch (g_screen) {
    case kScan: {
      std::string payload;
      if (qrscan_poll(payload)) {
        g_qrCount++;
        g_lastQr = payload;
        Serial.printf("QR[%d]: %s\n", g_qrCount, payload.c_str());
        buzz_beat();
      }
      if (now - g_lastDraw >= 50) {
        int w = 0, h = 0;
        const uint8_t* f = qrscan_frame(w, h);
        char hint[48];
        std::snprintf(hint, sizeof hint, "%d codes read", g_qrCount);
        ui_scan(f, w, h, float(g_qrCount % 10) / 10.0f, hint);
        if (f) qrscan_release_frame();
        g_lastDraw = now;
      }
      break;
    }
    case kPulse: {
      const PulseResult& p = pulse_update();
      if (p.beatNow) buzz_beat();
      if (now - g_lastDraw >= 50) {
        ui_pulse(p, g_pulseOk ? "PULSE CHECK" : "NO PULSE SENSOR");
        g_lastDraw = now;
      }
      static uint32_t lastLog = 0;
      if (p.beatNow || now - lastLog >= 1000) {  // serial pulse log for bench checks
        Serial.printf("pulse: finger=%d beat=%d bpm=%.1f beats=%d jitter=%.3f ir=%lu red=%lu t=%lums regular=%.2f window=%d passed=%d\n",
                      p.finger, p.beatNow, p.bpm, p.beats, p.jitter, (unsigned long)p.irDC, (unsigned long)p.redDC,
                      (unsigned long)p.elapsedMs, p.regular, p.windowOk, p.passed);
        lastLog = now;
      }
      if (p.passed) {
        uint8_t ev[12];
        pulse_evidence(ev);
      }
      break;
    }
    default:
      if (g_lastDraw == 0 || (g_screen == kHome && now - g_lastDraw >= 2000)) {
        draw_static();
        g_lastDraw = now == 0 ? 1 : now;
      }
      break;
  }

  (void)g_keep;
  (void)g_keepStore;
  delay(5);
}
