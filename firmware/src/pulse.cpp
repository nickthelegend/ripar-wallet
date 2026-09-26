// MAX30102 pulse sensor on the shared I2C bus (Wire, SDA 48 / SCL 47, 400 kHz). Polled, INT pin unused.
//
// Configuration: SpO2 mode (red = LED1, IR = LED2), 100 samples/s, 411 us pulse width (18-bit ADC),
// ADC full scale 4096 nA, FIFO averaging off, FIFO rollover on, both LEDs at 0x24 x 0.2 mA = 7.2 mA.
// FIFO sample layout in SpO2 mode: 3 bytes LED1 (red) then 3 bytes LED2 (IR), 18-bit values, MSB first.
//
// Timing: the FIFO holds 32 samples (320 ms). pulse_update() must run at least every ~250 ms. Sample
// timestamps come from a sample clock (+10 ms per sample, + lost samples counted by OVF_COUNTER), re-synced
// to millis() after a long stall, so the detector always sees monotonically increasing times. A real gap
// (FIFO overflow after a stall > 320 ms) shows up as a timestamp gap, and PulseDetector restarts the
// measurement on gaps > 250 ms: a stalled loop can never produce a "passed" from non-contiguous data.
//
// pulse_led_challenge() is built to stay inside that budget: its baseline is the last 8 samples already fed
// to the detector, and it withholds only ~10 samples (~100 ms) from the detector, so a passed measurement
// survives the challenge (the challenge can run between "pulse passed" and the SIGN press).
#include <Arduino.h>
#include <Wire.h>

#include "board.h"
#include "device.h"

namespace ripar {
namespace {

constexpr uint8_t kAddr = I2C_ADDR_MAX30102;
constexpr uint8_t REG_INT_EN1 = 0x02, REG_INT_EN2 = 0x03;
constexpr uint8_t REG_FIFO_WR = 0x04, REG_FIFO_OVF = 0x05, REG_FIFO_RD = 0x06, REG_FIFO_DATA = 0x07;
constexpr uint8_t REG_FIFO_CFG = 0x08, REG_MODE = 0x09, REG_SPO2 = 0x0A;
constexpr uint8_t REG_LED1_PA = 0x0C, REG_LED2_PA = 0x0D;  // LED1 = red, LED2 = IR
constexpr uint8_t REG_PART_ID = 0xFF;
constexpr uint8_t kPartId = 0x15;

constexpr uint8_t kModeSpO2 = 0x03;
constexpr uint8_t kModeShutdown = 0x80;
constexpr uint8_t kModeReset = 0x40;
constexpr uint8_t kSpO2Cfg = (0x1 << 5) | (0x1 << 2) | 0x3;  // ADC_RGE 4096 nA | SR 100 sps | PW 411 us
constexpr uint8_t kFifoCfg = 0x10;                           // SMP_AVE 1 (off) | FIFO_ROLLOVER_EN
constexpr uint8_t kLedPA = 0x24;                             // 7.2 mA
constexpr uint32_t kSampleMs = 10;
constexpr int kFifoDepth = 32;
constexpr int kChunk = 16;  // samples per I2C burst (96 bytes < 128-byte Wire buffer)

bool g_present = false;
bool g_running = false;
PulseDetector g_det;
PulseResult g_out;
uint32_t g_clock = 0;    // timestamp of the last sample fed, ms since pulse_start
uint32_t g_startMs = 0;
uint32_t g_lastSampleMs = 0;          // millis() of the last pulse_update() that got samples
constexpr uint32_t kStaleMs = 250;    // no samples for this long -> result is no longer "passed"

// the last kHist raw samples fed to the detector (nominal LED drive): baseline for the LED challenge
constexpr int kHist = 8;
uint32_t g_histIr[kHist], g_histRed[kHist];
int g_histPos = 0, g_histN = 0;

void hist_clear() { g_histPos = g_histN = 0; }
void hist_push(uint32_t ir, uint32_t red) {
  g_histIr[g_histPos] = ir;
  g_histRed[g_histPos] = red;
  g_histPos = (g_histPos + 1) % kHist;
  if (g_histN < kHist) g_histN++;
}

bool wr(uint8_t reg, uint8_t v) {
  Wire.beginTransmission(kAddr);
  Wire.write(reg);
  Wire.write(v);
  return Wire.endTransmission() == 0;
}

bool rdn(uint8_t reg, uint8_t* p, size_t n) {
  Wire.beginTransmission(kAddr);
  Wire.write(reg);
  if (Wire.endTransmission(false) != 0) return false;
  const size_t got = Wire.requestFrom(uint16_t(kAddr), n, true);
  if (got != n) {
    while (Wire.available()) Wire.read();
    return false;
  }
  for (size_t i = 0; i < n; i++) p[i] = uint8_t(Wire.read());
  return true;
}

bool rd(uint8_t reg, uint8_t& v) { return rdn(reg, &v, 1); }

bool fifo_clear() {
  return wr(REG_FIFO_WR, 0) && wr(REG_FIFO_OVF, 0) && wr(REG_FIFO_RD, 0);
}

bool set_leds(uint8_t pa) { return wr(REG_LED1_PA, pa) && wr(REG_LED2_PA, pa); }

// Reads up to maxN samples. Returns the count (0 on I2C error); lost = samples dropped by the FIFO.
int fifo_read(uint32_t* ir, uint32_t* red, int maxN, int& lost) {
  lost = 0;
  uint8_t ptr[3];  // WR, OVF, RD (auto-increment from 0x04)
  if (!rdn(REG_FIFO_WR, ptr, 3)) return 0;
  int n = (ptr[0] - ptr[2]) & 0x1F;
  if (n == 0 && ptr[1] != 0) n = kFifoDepth;  // full FIFO with rollover
  lost = ptr[1] & 0x1F;
  if (n > maxN) n = maxN;
  int done = 0;
  uint8_t buf[kChunk * 6];
  while (done < n) {
    const int k = (n - done) > kChunk ? kChunk : (n - done);
    if (!rdn(REG_FIFO_DATA, buf, size_t(k) * 6)) break;
    for (int i = 0; i < k; i++) {
      const uint8_t* s = buf + i * 6;
      red[done + i] = ((uint32_t(s[0]) << 16) | (uint32_t(s[1]) << 8) | s[2]) & 0x3FFFF;
      ir[done + i] = ((uint32_t(s[3]) << 16) | (uint32_t(s[4]) << 8) | s[5]) & 0x3FFFF;
    }
    done += k;
  }
  return done;
}

// Blocking: takes exactly n samples out of the FIFO (waiting for them if needed) WITHOUT feeding the detector,
// advancing the sample clock over them (plus any lost ones), and adds them to *sIr / *sRed when given.
// ~n * 10 ms. drainOnly: take whatever is in the FIFO right now instead (n ignored, no waiting).
bool take_samples(int n, uint64_t* sIr, uint64_t* sRed, bool drainOnly = false) {
  uint32_t ir[kFifoDepth], red[kFifoDepth];
  int got = 0;
  const uint32_t t0 = millis();
  const uint32_t timeout = uint32_t(n) * kSampleMs * 3 + 100;
  for (;;) {
    int lost = 0;
    const int want = drainOnly ? kFifoDepth : n - got;
    const int k = want > 0 ? fifo_read(ir, red, want, lost) : 0;
    g_clock += uint32_t(lost + k) * kSampleMs;
    for (int i = 0; i < k; i++) {
      if (sIr) *sIr += ir[i];
      if (sRed) *sRed += red[i];
    }
    got += k;
    if (drainOnly || got >= n) return true;
    if (millis() - t0 > timeout) return false;
    delay(2);
  }
}

}  // namespace

bool pulse_init() {
  g_present = false;
  g_running = false;
  Wire.begin(PIN_I2C_SDA, PIN_I2C_SCL, 400000);
  Wire.setTimeOut(20);
  Wire.beginTransmission(kAddr);
  if (Wire.endTransmission() != 0) return false;
  uint8_t id = 0;
  if (!rd(REG_PART_ID, id) || id != kPartId) return false;
  if (!wr(REG_MODE, kModeReset)) return false;
  const uint32_t t0 = millis();
  uint8_t mode = kModeReset;
  while (millis() - t0 < 100) {
    delay(2);
    if (rd(REG_MODE, mode) && !(mode & kModeReset)) break;
  }
  if (mode & kModeReset) return false;
  // park it: LEDs off, shutdown (registers keep their values)
  set_leds(0);
  wr(REG_MODE, kModeShutdown | kModeSpO2);
  g_present = true;
  return true;
}

void pulse_start() {
  g_det.reset();
  g_out = PulseResult();
  hist_clear();
  g_clock = 0;
  g_startMs = millis();
  if (!g_present) return;
  bool ok = wr(REG_MODE, kModeShutdown | kModeSpO2);  // configure while shut down
  ok = ok && wr(REG_INT_EN1, 0) && wr(REG_INT_EN2, 0);
  ok = ok && wr(REG_FIFO_CFG, kFifoCfg);
  ok = ok && wr(REG_SPO2, kSpO2Cfg);
  ok = ok && set_leds(kLedPA);
  ok = ok && fifo_clear();
  ok = ok && wr(REG_MODE, kModeSpO2);  // SHDN = 0: start sampling
  g_running = ok;
  g_startMs = millis();
  g_lastSampleMs = g_startMs;
}

// Fail closed: once stopped, pulse_update() reports no finger / not passed. pulse_evidence() still returns the
// evidence of the finished measurement (the detector is only reset by pulse_start()).
void pulse_stop() {
  g_running = false;
  g_out = PulseResult();
  if (!g_present) return;
  set_leds(0);
  wr(REG_MODE, kModeShutdown | kModeSpO2);
}

const PulseResult& pulse_update() {
  g_out.beatNow = false;
  if (!g_running) return g_out;
  uint32_t ir[kFifoDepth], red[kFifoDepth];
  int lost = 0;
  const int n = fifo_read(ir, red, kFifoDepth, lost);
  if (n <= 0) {
    // no samples (I2C fault, sensor reset / unplugged): "thumb still on the pad" can no longer be checked
    if (millis() - g_lastSampleMs > kStaleMs) {
      g_out.passed = false;
      g_out.finger = false;
    }
    return g_out;
  }
  g_lastSampleMs = millis();
  g_clock += uint32_t(lost) * kSampleMs;
  // re-sync after a stall longer than the FIFO: the newest sample was taken ~now
  const uint32_t now = millis() - g_startMs;
  const uint32_t firstEst = now > uint32_t(n - 1) * kSampleMs ? now - uint32_t(n - 1) * kSampleMs : 0;
  if (firstEst > g_clock + kSampleMs + 200) g_clock = firstEst - kSampleMs;
  bool beat = false;
  for (int i = 0; i < n; i++) {
    g_clock += kSampleMs;
    beat = g_det.add(ir[i], red[i], g_clock).beatNow || beat;
    hist_push(ir[i], red[i]);
  }
  g_out = g_det.result();
  g_out.beatNow = beat;
  return g_out;
}

void pulse_evidence(uint8_t ev12[12]) { g_det.evidence(ev12); }

// First-run key creation only (flows.cpp): raw samples straight from the FIFO, not fed to the detector.
int pulse_raw_samples(uint32_t* ir, uint32_t* red, int maxN) {
  if (!g_present || !g_running || !ir || !red || maxN <= 0) return 0;
  int lost = 0;
  const int n = fifo_read(ir, red, maxN > kFifoDepth ? kFifoDepth : maxN, lost);
  g_clock += uint32_t(lost + (n > 0 ? n : 0)) * kSampleMs;
  return n > 0 ? n : 0;
}

// Liveness challenge (P1 F12): drop both LED currents to a random 39..64 % of nominal, check that the
// reflected IR and red DC levels follow proportionally, then restore. A replayed or externally injected
// signal does not track an LED drive change it cannot predict. Blocking, ~100 ms.
//   baseline = mean of the last 8 samples fed to the detector (flushed first, so they are the newest ones)
//   low      = mean of 6 samples at the reduced drive, after 2 transitional samples are discarded
//   restore  = everything sampled before the restore write + 1 transitional sample is discarded
// About 10 samples are withheld from the detector and the sample clock advances over them, so it sees a
// ~100 ms timestamp gap (< the 250 ms that would restart its measurement): a passed result stays passed.
bool pulse_led_challenge() {
  if (!g_present || !g_running) return false;
  constexpr int kSkip = 2, kLow = 6;
  // 1. feed everything pending to the detector; wait (feeding) until the history holds kHist samples
  const uint32_t t0 = millis();
  pulse_update();
  while (g_histN < kHist) {
    if (millis() - t0 > 400) return false;
    delay(5);
    pulse_update();
  }
  uint64_t sIr = 0, sRed = 0;
  for (int i = 0; i < kHist; i++) {
    sIr += g_histIr[i];
    sRed += g_histRed[i];
  }
  const uint32_t baseIr = uint32_t(sIr / kHist), baseRed = uint32_t(sRed / kHist);
  // 2. reduced drive
  uint8_t rnd = 0;
  trng_fill(&rnd, 1);  // TRNG (SAR-ADC entropy source on): the level must not be predictable (review MINOR 6)
  const uint8_t level = uint8_t(14 + rnd % 10);  // 14..23 of 36
  uint64_t lIr = 0, lRed = 0;
  bool ok = set_leds(level);
  ok = ok && take_samples(kSkip, nullptr, nullptr) && take_samples(kLow, &lIr, &lRed);
  // 3. restore (retry once: leaving the LEDs dimmed would bias every later sample)
  bool restored = set_leds(kLedPA) || set_leds(kLedPA);
  take_samples(0, nullptr, nullptr, true);  // sampled at the reduced drive before the restore took effect
  take_samples(1, nullptr, nullptr);        // transitional
  hist_clear();  // the history predates the gap; a back-to-back challenge needs fresh samples
  if (!restored) {  // the drive level is unknown now: stop measuring, fail closed (pulse_start() recovers)
    g_running = false;
    g_det.reset();
    g_out = PulseResult();
    wr(REG_MODE, kModeShutdown | kModeSpO2);
  }
  if (!ok || !restored) return false;

  const PulseConfig cfg = PulseConfig();
  const uint32_t kSat = 250000;  // near the 18-bit ceiling the DC cannot follow a change
  if (baseIr < cfg.fingerIrMin || baseIr > kSat) return false;
  if (baseRed < 10000 || baseRed > kSat) return false;
  const float expect = float(level) / float(kLedPA);
  const float rIr = float(lIr / kLow) / float(baseIr);
  const float rRed = float(lRed / kLow) / float(baseRed);
  const float tol = 0.15f;
  return fabsf(rIr - expect) <= tol && fabsf(rRed - expect) <= tol;
}

}  // namespace ripar
