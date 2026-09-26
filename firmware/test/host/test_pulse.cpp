// DEPS: pulse_algo
// Host tests for src/pulse_algo.cpp. Every input is a synthetic MAX30102-like IR/red stream at 100 Hz, generated
// here with a deterministic PRNG: a PPG beat train (systolic wave, dicrotic wave, diastolic tail) with heart-rate
// variability, respiratory sinus arrhythmia and amplitude modulation, baseline wander, sensor noise and a
// finger-landing transient, plus the spoofs / failure cases the pulse gate has to reject.
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <vector>

#include "check.h"
#include "pulse_algo.h"

using namespace ripar;

namespace {

const double kPi = 3.14159265358979323846;

struct Rng {
  uint64_t s;
  explicit Rng(uint64_t seed) : s(seed * 0x9E3779B97F4A7C15ull + 12345) {}
  uint64_t next() {  // splitmix64
    uint64_t z = (s += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
  }
  double uni() { return double(next() >> 11) * (1.0 / 9007199254740992.0); }
  double gauss() {
    double u1 = uni();
    if (u1 < 1e-300) u1 = 1e-300;
    const double u2 = uni();
    return std::sqrt(-2.0 * std::log(u1)) * std::cos(2.0 * kPi * u2);
  }
};

enum Kind { PPG, SINE, SQUARE, FLAT, NOFINGER, CONSTANT, RED_UNCORR, RED_DEAD, RED_STUCK, SATURATED };

struct Sim {
  Kind kind = PPG;
  double bpm = 60;
  double hrv = 0.03;      // random beat-to-beat RR variation (std, fraction of RR)
  double rsa = 0.03;      // respiratory sinus arrhythmia (amplitude, fraction of RR)
  double respHz = 0.25;   // breathing rate
  double ampMod = 0.10;   // respiratory amplitude modulation depth
  bool irregular = false; // RR cycles 0.5x, 1.6x, 0.9x (every window of >= 4 intervals has jitter > 0.4)
  double dcIr = 120000, dcRed = 90000;
  double piIr = 0.010, piRed = 0.008;  // pulse amplitude as a fraction of DC (perfusion index)
  double noiseIr = 8, noiseRed = 12;   // white sensor noise, counts (std)
  double wander = 0.002;               // baseline wander amplitude, fraction of DC
  double wanderHz = 0.12;
  bool landing = true;                 // finger-landing ramp + pressure-settling transient
  double onAt = 0.5, offAt = 1e9, reOnAt = 1e9;  // finger placement / removal / re-placement (s)
  double pulseStopAt = 1e9;            // pulse vanishes (finger stays) at this time (s)
  double duration = 20;                // s
  uint32_t t0 = 1000;                  // timestamp of the first sample (ms)
  uint64_t seed = 1;
};

// one PPG beat, tau = seconds since beat onset; peak ~1.1 at 0.14 s
double shape(double tau) {
  if (tau < 0 || tau > 1.8) return 0;
  const double a = (tau - 0.14) / 0.055, b = (tau - 0.36) / 0.07;
  const double sys = std::exp(-a * a);
  const double dic = 0.30 * std::exp(-b * b);
  const double tail = 0.25 / (1.0 + std::exp(-(tau - 0.14) / 0.02)) * std::exp(-tau / 0.45);
  return sys + dic + tail;
}

struct Gen {
  Sim p;
  Rng rng;
  std::vector<double> bt, ba, bt2, ba2;  // beat onsets + amplitudes (second train: uncorrelated red)
  double ph1, ph2;

  static void train(Rng& rng, const Sim& p, double bpm, std::vector<double>& t, std::vector<double>& a) {
    const double rr0 = 60.0 / bpm;
    double x = -3.0 + rng.uni() * rr0;
    while (x < p.duration + 2.0) {
      t.push_back(x);
      a.push_back(1.0 + p.ampMod * std::sin(2 * kPi * p.respHz * x) + 0.04 * rng.gauss());
      double rr = rr0 * (1.0 + p.hrv * rng.gauss() + p.rsa * std::sin(2 * kPi * p.respHz * x + 1.0));
      if (p.irregular) rr *= t.size() % 3 == 0 ? 0.5 : t.size() % 3 == 1 ? 1.6 : 0.9;
      if (rr < 0.3 * rr0) rr = 0.3 * rr0;
      x += rr;
    }
  }

  explicit Gen(const Sim& s) : p(s), rng(s.seed) {
    train(rng, p, p.bpm, bt, ba);
    train(rng, p, p.bpm * 1.37 + 7, bt2, ba2);
    ph1 = 2 * kPi * rng.uni();
    ph2 = 2 * kPi * rng.uni();
  }

  static double pulse(const std::vector<double>& t, const std::vector<double>& a, double x) {
    double v = 0;
    for (size_t i = 0; i < t.size(); i++) {
      if (t[i] > x) break;
      if (x - t[i] < 1.8) v += a[i] * shape(x - t[i]);
    }
    return v;
  }

  bool fingerOn(double x) const { return (x >= p.onAt && x < p.offAt) || x >= p.reOnAt; }
  double placedAt(double x) const { return x >= p.reOnAt ? p.reOnAt : p.onAt; }

  static uint32_t clampAdc(double v) {
    if (v < 0) return 0;
    if (v > 262143) return 262143;
    return uint32_t(v + 0.5);
  }

  void sample(double x, uint32_t& ir, uint32_t& red) {
    if (!fingerOn(x) || p.kind == NOFINGER) {
      ir = clampAdc(1500 + 20 * rng.gauss());
      red = clampAdc(1200 + 20 * rng.gauss());
      return;
    }
    if (p.kind == CONSTANT) {
      ir = uint32_t(p.dcIr);
      red = uint32_t(p.dcRed);
      return;
    }
    double base = 1.0 + p.wander * (std::sin(2 * kPi * p.wanderHz * x + ph1) + 0.6 * std::sin(2 * kPi * 0.31 * x + ph2));
    const double tl = x - placedAt(x);
    if (p.landing) base *= 1.0 + 0.04 * std::exp(-tl / 0.5);
    const double f = p.bpm / 60.0;
    double pi = 0, pr = 0;
    switch (p.kind) {
      case PPG:
      case RED_DEAD:
      case RED_STUCK:
      case SATURATED:
        pi = pr = x < p.pulseStopAt ? pulse(bt, ba, x) : 0;
        break;
      case RED_UNCORR:
        pi = pulse(bt, ba, x);
        pr = pulse(bt2, ba2, x);
        break;
      case SINE:
        pi = pr = 0.5 * (1 + std::sin(2 * kPi * f * x));
        break;
      case SQUARE:
        pi = pr = std::sin(2 * kPi * f * x) >= 0 ? 1.0 : 0.0;
        break;
      default:
        break;
    }
    double vi = p.dcIr * base * (1 - p.piIr * pi) + p.noiseIr * rng.gauss();
    double vr = p.dcRed * base * (1 - p.piRed * pr) + p.noiseRed * rng.gauss();
    if (p.kind == RED_DEAD) vr = p.dcRed;
    if (p.kind == RED_STUCK) vr = p.dcRed - std::floor(2.0 * pr / 1.1 + 0.5);  // 0..2 LSB, in step with the pulse
    if (p.landing && tl < 0.03) {  // 30 ms ramp from ambient
      const double k = tl / 0.03;
      vi = 1500 + (vi - 1500) * k;
      vr = 1200 + (vr - 1200) * k;
    }
    ir = clampAdc(vi);
    red = clampAdc(vr);
  }
};

// drives a detector through a Sim; fn(x_seconds, t_ms, result) is called after every sample
template <class F>
void drive(const Sim& s, PulseDetector& d, F fn) {
  Gen g(s);
  const int n = int(s.duration * 100.0 + 0.5);
  for (int i = 0; i < n; i++) {
    const double x = i * 0.01;
    uint32_t ir = 0, red = 0;
    g.sample(x, ir, red);
    const uint32_t t = s.t0 + uint32_t(i) * 10u;
    const PulseResult& r = d.add(ir, red, t);
    fn(x, t, r);
  }
}

struct Stats {
  bool everPassed = false, everFinger = false;
  double firstPass = -1;       // seconds since placement at the first pass
  PulseResult atPass;
  uint8_t ev[12] = {0};
  int afterPass = 0, passedAfter = 0;  // samples after the first pass (finger on) / how many were passed
  int beatEvents = 0;
  float maxBpm = 0;
  bool evLeak = false;  // evidence() returned non-zero bytes while not passed
  PulseResult last;
};

Stats run(const Sim& s, const PulseConfig& cfg = PulseConfig()) {
  PulseDetector d(cfg);
  Stats st;
  Gen probe(s);
  int n = 0;
  drive(s, d, [&](double x, uint32_t, const PulseResult& r) {
    if (!r.passed && (n++ % 25) == 0) {
      uint8_t ev[12];
      d.evidence(ev);
      for (int i = 0; i < 12; i++)
        if (ev[i]) st.evLeak = true;
    }
    if (r.finger) st.everFinger = true;
    if (r.beatNow) st.beatEvents++;
    if (r.bpm > st.maxBpm) st.maxBpm = r.bpm;
    if (st.everPassed && probe.fingerOn(x)) {
      st.afterPass++;
      if (r.passed) st.passedAfter++;
    }
    if (r.passed && !st.everPassed) {
      st.everPassed = true;
      st.firstPass = x - probe.placedAt(x);
      st.atPass = r;
      d.evidence(st.ev);
    }
    st.last = r;
  });
  return st;
}

// true mean heart rate of the generated beats in [from, to] seconds
double true_bpm(const Sim& s, double from, double to) {
  Gen g(s);
  double first = 0, last = 0;
  int n = 0;
  for (size_t i = 0; i < g.bt.size(); i++) {
    if (g.bt[i] < from || g.bt[i] > to) continue;
    if (n == 0) first = g.bt[i];
    last = g.bt[i];
    n++;
  }
  return n >= 2 ? 60.0 * (n - 1) / (last - first) : 0;
}

uint32_t be(const uint8_t* p, int n) {
  uint32_t v = 0;
  for (int i = 0; i < n; i++) v = (v << 8) | p[i];
  return v;
}

bool evidence_matches(const uint8_t ev[12], const PulseResult& r) {
  bool ok = true;
  ok &= CHECK_EQ(int(ev[0]), 1);
  ok &= CHECK_EQ(int(ev[1]), int(std::floor(r.bpm + 0.5f)));
  ok &= CHECK_EQ(int(ev[2]), r.beats);
  ok &= CHECK_EQ(be(ev + 3, 3), r.irDC);
  ok &= CHECK_EQ(be(ev + 6, 3), r.redDC);
  int j = int(std::floor(r.jitter * 1000.0f + 0.5f));
  if (j > 255) j = 255;
  ok &= CHECK_EQ(int(ev[9]), j);
  ok &= CHECK_EQ(be(ev + 10, 2), r.elapsedMs / 10);
  return ok;
}

// A real pulse: must pass within maxS seconds of placement for every seed, report the right rate, stay passed.
void expect_pass(const char* name, Sim s, double maxS = 8.0, int seeds = 8) {
  CHECK_SECTION(name);
  double tMin = 1e9, tMax = 0, errMax = 0;
  for (int k = 1; k <= seeds; k++) {
    s.seed = uint64_t(k) * 1000 + uint64_t(s.bpm);
    const Stats st = run(s, PulseConfig());
    if (!CHECK(st.everPassed)) {
      std::printf("   seed %d never passed: beats=%d bpm=%.1f jitter=%.4f finger=%d\n", k, st.last.beats,
                  double(st.last.bpm), double(st.last.jitter), int(st.last.finger));
      continue;
    }
    if (st.firstPass < tMin) tMin = st.firstPass;
    if (st.firstPass > tMax) tMax = st.firstPass;
    if (!CHECK(st.firstPass <= maxS)) std::printf("   seed %d passed late: %.2f s\n", k, st.firstPass);
    CHECK(st.atPass.beats >= 5);
    CHECK(st.atPass.finger);
    const double x = s.onAt + st.firstPass;
    const double truth = true_bpm(s, std::max(x - 8.0, s.onAt + 0.5), x);
    const double err = std::fabs(double(st.atPass.bpm) - truth);
    if (err > errMax) errMax = err;
    if (!CHECK(err <= 0.08 * truth + 2.0))
      std::printf("   seed %d bpm %.1f vs true %.1f\n", k, double(st.atPass.bpm), truth);
    CHECK(st.atPass.jitter >= 0.005f && st.atPass.jitter <= 0.35f);
    CHECK(evidence_matches(st.ev, st.atPass));
    CHECK(!st.evLeak);
    // once passed it has to stay passed while the pulse continues (>= 90 % of the remaining samples)
    const double frac = st.afterPass ? double(st.passedAfter) / st.afterPass : 0;
    if (!CHECK(frac >= 0.90)) std::printf("   seed %d stayed passed only %.1f %%\n", k, 100 * frac);
    CHECK(st.last.passed);
  }
  std::printf("   pass time %.2f..%.2f s, max |bpm error| %.1f\n", tMin, tMax, errMax);
}

// Must never pass (any sample) for any seed.
void expect_fail(const char* name, Sim s, bool fingerExpected = true, int seeds = 6) {
  CHECK_SECTION(name);
  for (int k = 1; k <= seeds; k++) {
    s.seed = uint64_t(k) * 7919 + uint64_t(s.bpm);
    s.duration = 25;
    const Stats st = run(s, PulseConfig());
    if (!CHECK(!st.everPassed))
      std::printf("   seed %d PASSED at %.2f s: beats=%d bpm=%.1f jitter=%.4f\n", k, st.firstPass, st.atPass.beats,
                  double(st.atPass.bpm), double(st.atPass.jitter));
    CHECK_EQ(st.everFinger, fingerExpected);
    CHECK(!st.evLeak);  // evidence() stays all-zero while not passed
  }
}

// ----------------------------------------------------------------------------------------------------------------

void test_real_pulses() {
  Sim s;
  s.bpm = 60;
  expect_pass("clean 60 bpm", s);
  s.bpm = 120;
  expect_pass("clean 120 bpm", s);
  s.bpm = 45;
  expect_pass("clean 45 bpm", s);
  s.bpm = 170;
  expect_pass("clean 170 bpm", s);
  s.bpm = 42;
  expect_pass("clean 42 bpm (near the 40 bpm floor)", s, 8.5);
  s.bpm = 165;
  expect_pass("clean 165 bpm", s);

  Sim n;
  n.bpm = 72;
  n.noiseIr = 60;
  n.noiseRed = 80;
  n.wander = 0.03;  // 3600 counts of baseline wander: 3x the pulse amplitude
  expect_pass("noisy + baseline wander 72 bpm", n);

  Sim r;
  r.bpm = 80;
  r.ampMod = 0.30;
  r.rsa = 0.07;
  r.respHz = 0.3;
  r.wander = 0.01;
  r.wanderHz = 0.3;
  expect_pass("respiratory modulation 80 bpm (AM 30 %, RSA 7 %, resp baseline)", r);

  Sim lp;
  lp.bpm = 66;
  lp.piIr = 0.0025;
  lp.piRed = 0.002;
  expect_pass("low perfusion 0.25 % 66 bpm", lp);

  Sim lo;
  lo.bpm = 90;
  lo.dcIr = 62000;
  lo.dcRed = 50000;
  expect_pass("IR DC just above the finger threshold 90 bpm", lo);

  Sim nl;
  nl.bpm = 100;
  nl.landing = false;
  nl.hrv = 0.015;
  nl.rsa = 0.01;
  expect_pass("low HRV 100 bpm, no landing transient", nl);

  Sim w;
  w.bpm = 75;
  w.t0 = 0xFFFFFFFFu - 6000;  // millis() wraps 5.5 s after the finger lands
  expect_pass("timestamp wrap-around 75 bpm", w, 8.0, 4);
}

void test_rejections() {
  Sim s;
  s.kind = NOFINGER;
  expect_fail("no finger", s, false);

  s = Sim();
  s.kind = FLAT;
  expect_fail("finger, no pulse (flat + noise + wander)", s);

  s = Sim();
  s.kind = CONSTANT;
  expect_fail("perfectly constant signal", s);

  s = Sim();
  s.kind = SQUARE;
  s.bpm = 66;
  expect_fail("square-wave spoof 66 bpm", s);
  s.bpm = 100;
  s.noiseIr = 0;
  s.noiseRed = 0;
  expect_fail("square-wave spoof 100 bpm, noiseless", s);

  s = Sim();
  s.kind = SINE;
  s.bpm = 72;  // period is not a whole number of samples
  expect_fail("sine spoof 72 bpm, zero jitter", s);
  s.bpm = 60;
  s.noiseIr = 0;
  s.noiseRed = 0;
  expect_fail("sine spoof 60 bpm, zero jitter, noiseless", s);
  s.bpm = 150;
  s.noiseIr = 8;
  s.noiseRed = 12;
  expect_fail("sine spoof 150 bpm, zero jitter", s);

  s = Sim();
  s.bpm = 30;
  expect_fail("real-shaped pulse at 30 bpm (too slow)", s);

  s = Sim();
  s.bpm = 200;
  expect_fail("real-shaped pulse at 200 bpm (too fast)", s);

  s = Sim();
  s.kind = RED_UNCORR;
  s.bpm = 70;
  expect_fail("IR pulse with uncorrelated red", s);

  s = Sim();
  s.kind = RED_DEAD;
  s.bpm = 70;
  expect_fail("IR pulse with constant red channel", s);

  s = Sim();
  s.kind = RED_STUCK;  // correlated with IR, but the red channel only ever moves by 2 LSB
  s.bpm = 70;
  expect_fail("IR pulse with red stuck within 2 LSB", s);

  s = Sim();
  s.kind = SATURATED;
  s.bpm = 70;
  s.dcIr = 261000;  // pulse troughs fine, peaks of the wander/landing clip at full scale
  s.wander = 0.01;
  expect_fail("IR clipping at ADC full scale", s);

  s = Sim();
  s.irregular = true;
  s.bpm = 70;
  expect_fail("irregular rhythm 0.5x/1.6x/0.9x at 70 bpm (jitter > 0.35)", s);
  s.bpm = 50;
  expect_fail("irregular rhythm 0.5x/1.6x/0.9x at 50 bpm", s);
}

void test_200bpm_not_halved() {
  CHECK_SECTION("200 bpm is measured as ~200 (not halved into range)");
  for (int k = 1; k <= 6; k++) {
    Sim s;
    s.bpm = 200;
    s.seed = uint64_t(k) * 31;
    const Stats st = run(s);
    if (!CHECK(st.last.bpm > 180.0f)) std::printf("   seed %d bpm %.1f\n", k, double(st.last.bpm));
  }
}

void test_finger_removed() {
  CHECK_SECTION("finger removed mid-window after passing, then placed again");
  for (int k = 1; k <= 6; k++) {
    Sim s;
    s.bpm = 64;
    s.seed = uint64_t(k) * 101;
    s.offAt = 10.5;
    s.reOnAt = 12.5;
    s.duration = 23;
    PulseDetector d;
    bool passedBefore = false, badWhileOff = false, lateDrop = false;
    double rePass = -1;
    drive(s, d, [&](double x, uint32_t, const PulseResult& r) {
      if (x < s.offAt && r.passed) passedBefore = true;
      if (x >= s.offAt + 0.1 && x < s.reOnAt) {
        if (r.passed || r.finger || r.beats != 0 || r.bpm != 0 || r.elapsedMs != 0 || r.progress != 0) badWhileOff = true;
      }
      if (x >= s.offAt + 0.1 && x < s.offAt + 0.11 && r.passed) lateDrop = true;
      if (x >= s.reOnAt && r.passed && rePass < 0) {
        rePass = x - s.reOnAt;
        CHECK(r.elapsedMs <= uint32_t(rePass * 1000 + 50));  // elapsed restarted at re-placement
      }
    });
    CHECK(passedBefore);
    CHECK(!lateDrop);
    CHECK(!badWhileOff);
    if (!CHECK(rePass >= 3.5 && rePass <= 8.0)) std::printf("   seed %d re-pass after %.2f s\n", k, rePass);
  }

  CHECK_SECTION("finger removed before passing: beats do not carry over");
  for (int k = 1; k <= 6; k++) {
    Sim s;
    s.bpm = 90;
    s.seed = uint64_t(k) * 211;
    s.offAt = 4.0;
    s.reOnAt = 5.0;
    const Stats st = run(s);
    CHECK(st.everPassed);
    // placedAt() is the re-placement here; 5 fresh beats at 90 bpm need >= 2.7 s
    if (!CHECK(st.firstPass >= 2.7)) std::printf("   seed %d passed %.2f s after re-placement\n", k, st.firstPass);
  }
}

void test_pulse_stops() {
  CHECK_SECTION("pulse vanishes while the finger stays (pressed flat / dead finger)");
  for (int k = 1; k <= 6; k++) {
    Sim s;
    s.bpm = 70;
    s.seed = uint64_t(k) * 17;
    s.pulseStopAt = 12.0;
    PulseDetector d;
    bool passedBefore = false, passedLate = false, fingerLost = false;
    drive(s, d, [&](double x, uint32_t, const PulseResult& r) {
      if (x > 11.0 && x < 12.0 && r.passed) passedBefore = true;
      if (x > 12.0 + 3.0 && r.passed) passedLate = true;
      if (x > 1.0 && !r.finger) fingerLost = true;
    });
    CHECK(passedBefore);
    CHECK(!passedLate);
    CHECK(!fingerLost);
  }
}

void test_timestamps() {
  CHECK_SECTION("sample gap restarts the measurement; stale timestamps are dropped");
  Sim s;
  s.bpm = 75;
  s.seed = 5;
  s.duration = 40;
  Gen g(s);
  PulseDetector d;
  uint32_t t = 5000;
  bool passedA = false;
  for (int i = 0; i < 1100; i++) {  // 11 s
    uint32_t ir, red;
    g.sample(i * 0.01, ir, red);
    t = 5000 + uint32_t(i) * 10;
    if (d.add(ir, red, t).passed) passedA = true;
  }
  CHECK(passedA);
  CHECK(d.result().passed);
  // duplicate / backwards timestamps with garbage values are ignored
  const PulseResult before = d.result();
  d.add(0, 0, t);
  d.add(0, 0, t - 500);
  CHECK(d.result().finger);
  CHECK_EQ(d.result().beats, before.beats);
  CHECK_EQ(d.result().elapsedMs, before.elapsedMs);
  // 1 s of samples lost
  uint32_t ir, red;
  g.sample(12.1, ir, red);
  t += 1000;
  const PulseResult& r = d.add(ir, red, t);
  CHECK(r.finger);
  CHECK(!r.passed);
  CHECK_EQ(r.beats, 0);
  CHECK_EQ(r.elapsedMs, 0u);
  double rePass = -1;
  for (int i = 1; i < 1000; i++) {
    g.sample(12.1 + i * 0.01, ir, red);
    if (d.add(ir, red, t + uint32_t(i) * 10).passed && rePass < 0) rePass = i * 0.01;
  }
  if (!CHECK(rePass > 3.0 && rePass <= 8.0)) std::printf("   re-pass after gap %.2f s\n", rePass);

  CHECK_SECTION("reset()");
  d.reset();
  CHECK(!d.result().passed);
  CHECK(!d.result().finger);
  CHECK_EQ(d.result().beats, 0);
  uint8_t ev[12], zero[12] = {0};
  d.evidence(ev);
  CHECK_EQ_BYTES(ev, zero, 12);
}

void test_config_and_ui() {
  CHECK_SECTION("fingerIrMin from the config");
  {
    Sim s;
    s.bpm = 70;
    PulseConfig c;
    c.fingerIrMin = 150000;  // above the simulated 120k DC
    const Stats st = run(s, c);
    CHECK(!st.everFinger);
    CHECK(!st.everPassed);
    CHECK(st.last.irDC > 100000u && st.last.irDC < 140000u);  // without a finger irDC is the live level
  }
  CHECK_SECTION("minBeats / bpmMax from the config");
  {
    Sim s;
    s.bpm = 150;
    PulseConfig c;
    c.bpmMax = 140;
    CHECK(!run(s, c).everPassed);
    c = PulseConfig();
    c.minBeats = 8;
    s.bpm = 60;
    const Stats st = run(s, c);
    CHECK(st.everPassed);
    CHECK(st.atPass.beats >= 8);
    CHECK(st.firstPass >= 7.0);
  }
  CHECK_SECTION("heartbeat blink, progress, DC and elapsed");
  {
    Sim s;
    s.bpm = 60;
    s.duration = 20.5;  // finger on 0.5 .. 20.5 s
    s.seed = 77;
    PulseDetector d;
    int beats = 0;
    float lastProg = 0;
    bool progDown = false, progOver = false;
    drive(s, d, [&](double, uint32_t, const PulseResult& r) {
      if (r.beatNow) beats++;
      if (!r.passed && r.progress > 0.95f + 1e-6f) progOver = true;
      if (r.passed && r.progress != 1.0f) progOver = true;
      if (!r.passed && r.progress + 1e-6f < lastProg && lastProg < 0.95f) progDown = true;
      lastProg = r.progress;
    });
    const Gen g(s);
    int truth = 0;
    for (size_t i = 0; i < g.bt.size(); i++)
      if (g.bt[i] > 1.0 && g.bt[i] < 20.3) truth++;
    if (!CHECK(beats >= truth - 1 && beats <= truth + 1)) std::printf("   beatNow %d vs %d true beats\n", beats, truth);
    CHECK(!progOver);
    CHECK(!progDown);
    const PulseResult& r = d.result();
    CHECK(r.passed);
    CHECK(r.irDC > 115000u && r.irDC < 125000u);
    CHECK(r.redDC > 86000u && r.redDC < 94000u);
    CHECK(r.elapsedMs >= 19900u && r.elapsedMs <= 20000u);
    uint8_t ev[12];
    d.evidence(ev);
    CHECK(evidence_matches(ev, r));
    CHECK(be(ev + 10, 2) >= 1990u);
  }
}

}  // namespace

int main() {
  test_real_pulses();
  test_rejections();
  test_200bpm_not_halved();
  test_finger_removed();
  test_pulse_stops();
  test_timestamps();
  test_config_and_ui();
  return CHECK_SUMMARY();
}
