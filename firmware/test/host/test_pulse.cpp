// DEPS: pulse_algo
// Host tests for src/pulse_algo.cpp. Every input is a synthetic MAX30102-like IR/red stream at 100 Hz, generated
// here with a deterministic PRNG: a PPG beat train (systolic wave, dicrotic wave, diastolic tail) with heart-rate
// variability, respiratory sinus arrhythmia and amplitude modulation, baseline wander, sensor noise and a
// finger-landing transient, plus the spoofs / failure cases the pulse gate has to reject, including spoofs that
// switch shape or rate while the "finger" stays on (the emulator finding: a 66 bpm square wave followed by a 72 bpm
// sine passed, the mix of two perfect rhythms looking irregular enough).
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

enum Kind {
  PPG, SINE, SQUARE, FLAT, NOFINGER, CONSTANT, RED_UNCORR, RED_DEAD, RED_STUCK, SATURATED,
  PPG_PERFECT,  // the PPG beat shape, strictly periodic (one recorded beat, replayed)
  TRIANGLE
};

// A spoof segment: from `at` seconds after the finger placement on, shape `kind` at `bpm` (finger stays on).
struct Seg {
  double at;
  Kind kind;
  double bpm;
};

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
  // Shape / rate changes (SINE, SQUARE, FLAT, PPG_PERFECT, TRIANGLE) while the finger stays on; empty = kind / bpm.
  std::vector<Seg> segs;
  bool absPhase = true;  // spoof phase = 2 pi f x (as the emulator's synth: a switch jumps the phase); else continuous
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
  double phase = 0, lastX = -1;  // continuous spoof phase (Sim::absPhase = false)

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
    Seg now = {0, p.kind, p.bpm};
    for (size_t i = 0; i < p.segs.size(); i++)
      if (i == 0 || p.segs[i].at <= tl) now = p.segs[i];
    const double f = now.bpm / 60.0;
    phase = lastX < 0 ? 2 * kPi * f * x : phase + 2 * kPi * f * (x - lastX);
    lastX = x;
    const double ph = p.absPhase ? 2 * kPi * f * x : phase;
    double u = std::fmod(ph / (2 * kPi), 1.0);  // cycle position of a periodic spoof
    if (u < 0) u += 1;
    double pi = 0, pr = 0;
    switch (now.kind) {
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
        pi = pr = 0.5 * (1 + std::sin(ph));
        break;
      case SQUARE:
        pi = pr = std::sin(ph) >= 0 ? 1.0 : 0.0;
        break;
      case TRIANGLE:
        pi = pr = u < 0.5 ? 2 * u : 2 - 2 * u;
        break;
      case PPG_PERFECT:
        for (int j = 0; j < 6; j++) pi += shape((u + j) * 60.0 / now.bpm);
        pr = pi;
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

// A real pulse: must pass within maxS seconds of placement for every seed (for at least minPassed seeds when given:
// a weak signal whose beat-to-beat variability is close to the sensor's timing noise, see test_realistic_hrv), report
// the right rate and stay passed (>= minStay of the remaining samples).
void expect_pass(const char* name, Sim s, double maxS = 8.0, int seeds = 8, int minPassed = -1, double minStay = 0.90) {
  CHECK_SECTION(name);
  double tMin = 1e9, tMax = 0, errMax = 0;
  int passed = 0;
  for (int k = 1; k <= seeds; k++) {
    s.seed = uint64_t(k) * 1000 + uint64_t(s.bpm);
    const Stats st = run(s, PulseConfig());
    if (!st.everPassed) {
      if (minPassed < 0) CHECK(st.everPassed);
      std::printf("   seed %d never passed: beats=%d bpm=%.1f jitter=%.4f finger=%d\n", k, st.last.beats,
                  double(st.last.bpm), double(st.last.jitter), int(st.last.finger));
      continue;
    }
    passed++;
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
    // once passed it has to stay passed while the pulse continues (>= minStay of the remaining samples)
    const double frac = st.afterPass ? double(st.passedAfter) / st.afterPass : 0;
    if (!CHECK(frac >= minStay)) std::printf("   seed %d stayed passed only %.1f %%\n", k, 100 * frac);
    if (minStay >= 0.90) CHECK(st.last.passed);
  }
  if (minPassed >= 0 && !CHECK(passed >= minPassed)) std::printf("   only %d of %d seeds passed\n", passed, seeds);
  std::printf("   %d/%d passed, pass time %.2f..%.2f s, max |bpm error| %.1f\n", passed, seeds, tMin, tMax, errMax);
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
  expect_pass("clean 45 bpm", s, 11.0);  // slow rates: the cross-channel test needs a few more beats
  s.bpm = 170;
  expect_pass("clean 170 bpm", s);
  s.bpm = 42;
  expect_pass("clean 42 bpm (near the 40 bpm floor)", s, 11.0);
  s.bpm = 165;
  expect_pass("clean 165 bpm", s);

  Sim n;
  n.bpm = 72;
  n.noiseIr = 60;
  n.noiseRed = 80;
  n.wander = 0.03;  // 3600 counts of baseline wander: 3x the pulse amplitude
  expect_pass("noisy + baseline wander 72 bpm", n, 13.0);  // noise 60-80: timing noise close to the HRV

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
  expect_pass("low perfusion 0.25 % 66 bpm", lp, 10.5);

  Sim lo;
  lo.bpm = 90;
  lo.dcIr = 62000;
  lo.dcRed = 50000;
  expect_pass("IR DC just above the finger threshold 90 bpm", lo, 9.5);

  Sim nl;
  nl.bpm = 100;
  nl.landing = false;
  nl.hrv = 0.015;
  nl.rsa = 0.01;
  expect_pass("low HRV 100 bpm, no landing transient", nl, 9.5);

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

// ---- spoofs that change shape or rate while the finger stays on ---------------------------------------------------
// Each segment alone is perfectly periodic; the gate must not take the mix of two perfect rhythms (or the step
// between them) for heart-rate variability. Run as the emulator would: the phase jumps at a switch (2 pi f t), and
// also phase-continuous. Every run lasts at least 14 s past the last switch and must never pass, on any sample.

bool spoof_never_passes(const Sim& s, const char* what) {
  const Stats st = run(s, PulseConfig());
  CHECK(!st.evLeak);
  if (!st.everPassed) return true;
  std::printf("   %s seed %llu amp %.3f %s PASSED at %.2f s: beats=%d bpm=%.1f jitter=%.4f\n", what,
              (unsigned long long)s.seed, s.piIr, s.absPhase ? "phase-jump" : "continuous", st.firstPass,
              st.atPass.beats, double(st.atPass.bpm), double(st.atPass.jitter));
  return false;
}

Sim spoof_sim(const std::vector<Seg>& segs, double amp, bool absPhase, uint64_t seed) {
  Sim s;
  s.kind = segs[0].kind;
  s.bpm = segs[0].bpm;
  s.segs = segs;
  s.absPhase = absPhase;
  s.piIr = amp;
  s.piRed = 0.8 * amp;
  s.seed = seed;
  s.duration = s.onAt + segs.back().at + 14.0;
  if (s.duration < 26) s.duration = 26;
  return s;
}

// spoof k1 at b1, switched to k2 at b2 2..12 s after placement; amplitude 1 % (the emulator's default) and 2 %
void expect_switch_fails(const char* name, Kind k1, double b1, Kind k2, double b2) {
  CHECK_SECTION(name);
  const double switches[] = {2.0, 3.0, 4.0, 5.0, 6.5, 8.0, 10.0, 12.0};
  int runs = 0, passed = 0;
  for (double sw : switches)
    for (double amp : {0.01, 0.02})
      for (int ph = 0; ph < 2; ph++)
        for (int k = 1; k <= 3; k++) {
          const Sim s = spoof_sim({{0, k1, b1}, {sw, k2, b2}}, amp, ph == 0, uint64_t(k) * 7919 + uint64_t(sw * 10));
          runs++;
          char what[48];
          std::snprintf(what, sizeof what, "switch at %.1f s", sw);
          if (!CHECK(spoof_never_passes(s, what))) passed++;
        }
  std::printf("   %d runs, %d passed\n", runs, passed);
}

// two perfect rhythms alternating: every beat (segT = 0: intervals a, b, a, b, ...) or every segT seconds
void expect_alternation_fails(const char* name, Kind k, double b1, double b2, double segT) {
  CHECK_SECTION(name);
  int runs = 0, passed = 0;
  for (double amp : {0.01, 0.02})
    for (int ph = 0; ph < 2; ph++) {
      if (segT <= 0 && ph == 0) continue;  // beat-wise alternation: phase-continuous only (a jump would split beats)
      for (int n = 1; n <= 3; n++) {
        std::vector<Seg> segs;
        double x = 0;
        for (int i = 0; x < 30; i++) {
          const double b = (i & 1) ? b2 : b1;
          segs.push_back({x, k, b});
          x += segT > 0 ? segT : 60.0 / b;
        }
        Sim s = spoof_sim(segs, amp, ph == 0, uint64_t(n) * 104729 + uint64_t(b1));
        s.duration = 30;
        runs++;
        if (!CHECK(spoof_never_passes(s, name))) passed++;
      }
    }
  std::printf("   %d runs, %d passed\n", runs, passed);
}

void test_switched_spoofs() {
  // the emulator finding: 66 bpm square wave, then (finger kept on) a 72 bpm sine; before this fix it passed ~6.5 s
  // after the switch (jitter ~0.16) on 3 seeds
  CHECK_SECTION("emulator finding: square 66 bpm, then sine 72 bpm (finger kept on)");
  for (double sw : {5.0, 8.0, 10.0, 15.0})
    for (int k = 1; k <= 3; k++) {
      const Sim s = spoof_sim({{0, SQUARE, 66}, {sw, SINE, 72}}, 0.01, true, uint64_t(k));
      CHECK(spoof_never_passes(s, "square 66 -> sine 72"));
    }
  expect_switch_fails("square 66 -> sine 72", SQUARE, 66, SINE, 72);
  expect_switch_fails("sine 72 -> square 66", SINE, 72, SQUARE, 66);
  expect_switch_fails("flat (finger, no pulse) -> sine 72", FLAT, 72, SINE, 72);
  expect_switch_fails("flat -> perfect PPG shape 66", FLAT, 66, PPG_PERFECT, 66);
  expect_switch_fails("square 66 -> perfect PPG shape 72", SQUARE, 66, PPG_PERFECT, 72);
  expect_switch_fails("rate step: sine 60 -> 72", SINE, 60, SINE, 72);
  expect_switch_fails("rate step: sine 72 -> 60", SINE, 72, SINE, 60);
  expect_switch_fails("rate step: sine 66 -> 70", SINE, 66, SINE, 70);
  expect_switch_fails("rate step: sine 45 -> 50", SINE, 45, SINE, 50);
  expect_switch_fails("rate step: sine 150 -> 160", SINE, 150, SINE, 160);
  expect_switch_fails("rate step: perfect PPG shape 60 -> 75", PPG_PERFECT, 60, PPG_PERFECT, 75);
  expect_switch_fails("rate step: perfect PPG shape 120 -> 140", PPG_PERFECT, 120, PPG_PERFECT, 140);
  expect_switch_fails("triangle 60 -> sine 70", TRIANGLE, 60, SINE, 70);

  expect_alternation_fails("alternating every beat: sine 60 / 75 bpm", SINE, 60, 75, 0);
  expect_alternation_fails("alternating every beat: perfect PPG 66 / 72 bpm", PPG_PERFECT, 66, 72, 0);
  expect_alternation_fails("alternating every beat: sine 100 / 120 bpm", SINE, 100, 120, 0);
  expect_alternation_fails("alternating every beat: perfect PPG 140 / 160 bpm", PPG_PERFECT, 140, 160, 0);
  expect_alternation_fails("alternating every 6 s: sine 60 / 75 bpm", SINE, 60, 75, 6);
  expect_alternation_fails("alternating every 8 s: perfect PPG 66 / 72 bpm", PPG_PERFECT, 66, 72, 8);
  expect_alternation_fails("alternating every 8 s: sine 66 / 72 bpm", SINE, 66, 72, 8);
  expect_alternation_fails("alternating every 8 s: perfect PPG 140 / 160 bpm", PPG_PERFECT, 140, 160, 8);

  // perfectly periodic spoofs of other shapes (the rejection tests above cover sine and square)
  Sim s;
  s.kind = PPG_PERFECT;
  s.bpm = 60;
  expect_fail("perfect PPG shape 60 bpm (one recorded beat, replayed)", s);
  s.bpm = 120;
  expect_fail("perfect PPG shape 120 bpm", s);
  s.bpm = 175;
  expect_fail("perfect PPG shape 175 bpm", s);
  s = Sim();
  s.kind = TRIANGLE;
  s.bpm = 50;
  expect_fail("triangle 50 bpm (slow symmetric upstroke)", s);
  s.bpm = 150;
  expect_fail("triangle 150 bpm", s);
  s = Sim();
  s.kind = SINE;
  s.bpm = 45;
  s.wander = 0.01;  // slow sine + wander: timing too noisy to look regular, but the upstroke gives it away
  expect_fail("sine 45 bpm with 1 % baseline wander (slow symmetric upstroke)", s);
}

// ---- strictly periodic spoofs plus white sensor noise (firmware v1.2 review, high finding) ------------------------
// Additive noise shifts the beat timing points of a perfectly periodic source from beat to beat; up to v1.2 the gate
// read that jitter as heart-rate variability (a 66 bpm square wave at 1 % with noise 120 passed 10/10, a perfect PPG
// shape at noise 120 37/60, some sines and triangles even at the nominal noise 8). The cross-channel test rejects them:
// the noise is independent in the IR and red channels, a heart's variability is common to both.

Sim noisy_spoof(Kind k, double bpm, double amp, double noise, uint64_t seed) {
  Sim s;
  s.kind = k;
  s.bpm = bpm;
  s.piIr = amp;
  s.piRed = 0.8 * amp;
  s.noiseIr = noise;
  s.noiseRed = 1.5 * noise;
  s.duration = 25;
  s.seed = seed;
  return s;
}

const char* kind_name(Kind k) {
  return k == SINE ? "sine" : k == SQUARE ? "square" : k == TRIANGLE ? "triangle" : k == PPG_PERFECT ? "perfect PPG" : "?";
}

void test_noisy_periodic_spoofs() {
  // the review's reproductions, with its seeds
  CHECK_SECTION("review: periodic spoofs at the nominal noise 8 (sine 130 bpm, triangle 100 bpm, 0.5 %)");
  CHECK(spoof_never_passes(noisy_spoof(SINE, 130, 0.005, 8, 16072), "sine 130 noise 8"));
  CHECK(spoof_never_passes(noisy_spoof(TRIANGLE, 100, 0.005, 8, 8123), "triangle 100 noise 8"));
  CHECK_SECTION("review: square 66 bpm 1 % + noise 120 (the emulator-finding shape), 10 seeds");
  for (int k = 1; k <= 10; k++) CHECK(spoof_never_passes(noisy_spoof(SQUARE, 66, 0.01, 120, uint64_t(k) * 31 + 7), "square 66"));
  CHECK_SECTION("review: perfect PPG shape 1 % + noise 120 at 50-130 bpm, 10 seeds each");
  for (double bpm : {50.0, 66.0, 80.0, 100.0, 130.0})
    for (int k = 1; k <= 10; k++)
      CHECK(spoof_never_passes(noisy_spoof(PPG_PERFECT, bpm, 0.01, 120, uint64_t(k) * 31 + 7), "perfect PPG"));
  CHECK_SECTION("review: sine 100 / 130 bpm at 0.5-2 % + noise 120, 10 seeds each");
  for (double bpm : {100.0, 130.0})
    for (double amp : {0.005, 0.01, 0.02})
      for (int k = 1; k <= 10; k++)
        CHECK(spoof_never_passes(noisy_spoof(SINE, bpm, amp, 120, uint64_t(k) * 31 + 7), "sine"));

  // the sweep: every shape, 50-130 bpm, 0.5-4 %, noise 8-120 (0.007-0.1 % of the IR DC): must never pass
  const Kind kinds[] = {SINE, PPG_PERFECT, SQUARE, TRIANGLE};
  for (Kind k : kinds) {
    char name[96];
    std::snprintf(name, sizeof name, "%s spoof + white noise 8-120, 50-130 bpm, 0.5-4 %%: never passes", kind_name(k));
    CHECK_SECTION(name);
    int runs = 0, passed = 0;
    for (double noise : {8.0, 30.0, 60.0, 120.0})
      for (double bpm : {50.0, 66.0, 80.0, 100.0, 130.0})
        for (double amp : {0.005, 0.01, 0.02, 0.04})
          for (int seed = 1; seed <= 3; seed++) {
            runs++;
            const Sim s = noisy_spoof(k, bpm, amp, noise, uint64_t(seed) * 7919 + uint64_t(bpm) + uint64_t(noise * 13));
            if (!CHECK(spoof_never_passes(s, kind_name(k)))) passed++;
          }
    std::printf("   %d runs, %d passed\n", runs, passed);
  }
  // very noisy (noise 250 / 500 = 0.2 / 0.4 % of the IR DC, at or above the pulse itself for the weak amplitudes): the
  // cross-channel test's residual false-accept rate (per evaluation 0.1 % for Gaussian timing noise) shows up here;
  // at most 1 % of these runs may pass (measured: 0-1 of 480)
  CHECK_SECTION("all shapes + white noise 250 / 500: at most 1 % of runs pass");
  {
    int runs = 0, passed = 0;
    for (Kind k : kinds)
      for (double noise : {250.0, 500.0})
        for (double bpm : {50.0, 66.0, 80.0, 100.0, 130.0})
          for (double amp : {0.005, 0.01, 0.02, 0.04})
            for (int seed = 1; seed <= 3; seed++) {
              runs++;
              const Sim s = noisy_spoof(k, bpm, amp, noise, uint64_t(seed) * 7919 + uint64_t(bpm) + uint64_t(noise * 13));
              if (!spoof_never_passes(s, kind_name(k))) passed++;
            }
    std::printf("   %d runs, %d passed\n", runs, passed);
    CHECK(passed * 100 <= runs);
  }
  // a switched spoof with noise (the step and the noise together)
  CHECK_SECTION("square 66 -> sine 72 bpm switched at 5 / 8 s, 1 % + noise 60 / 120");
  for (double noise : {60.0, 120.0})
    for (double sw : {5.0, 8.0})
      for (int k = 1; k <= 3; k++) {
        Sim s = spoof_sim({{0, SQUARE, 66}, {sw, SINE, 72}}, 0.01, true, uint64_t(k) * 13 + uint64_t(noise));
        s.noiseIr = noise;
        s.noiseRed = 1.5 * noise;
        CHECK(spoof_never_passes(s, "square 66 -> sine 72 + noise"));
      }
}

// Realistic pulses: heart-rate variability that shrinks with the rate (random RR std / respiratory sinus arrhythmia
// from 3 % / 4 % at 45 bpm to 1.2 % / 0.5 % at 175 bpm), with weak, strong and noisy + wandering signals (8 seeds each).
// Since v1.2 the gate only credits beat-to-beat variability that the IR and red channels share (the cross-channel
// test; independent sensor noise is no heartbeat), so the time to pass grows as the variability approaches the timing
// noise of the weaker (red) channel:
//   - strong signals (2.5 %, noise 8): every seed within the usual 8 s, stays passed;
//   - weak (0.4 %, noise 20) or noisy + wandering (1 %, noise 40, 2 %) signals at rest (45-72 bpm): every seed within
//     15 s, stays passed >= 75 % of the time;
//   - the same at 100 bpm (RR 1.5 %): >= 6 of 8 seeds within 30 s;
//   - the same at 150-175 bpm with RR variability ~1 %: the variability is at the red channel's timing noise, exactly
//     what a periodic source plus sensor noise looks like - not required to pass (docs/FIRMWARE.md, known limitations);
//     reported only.
void test_realistic_hrv() {
  struct R {
    double bpm, hrv, rsa;
  };
  const R rates[] = {{45, 0.03, 0.04},    {60, 0.025, 0.03},   {72, 0.02, 0.03},
                     {100, 0.015, 0.015}, {150, 0.012, 0.006}, {175, 0.012, 0.005}};
  struct V {
    const char* name;
    double amp, noise, wander;
  };
  const V vars[] = {{"weak 0.4 %, noise 20, wander 0.5 %", 0.004, 20, 0.005},
                    {"strong 2.5 %, noise 8, wander 0.2 %", 0.025, 8, 0.002},
                    {"1 %, noise 40, wander 2 %", 0.01, 40, 0.02}};
  for (const R& r : rates)
    for (const V& v : vars) {
      Sim s;
      s.bpm = r.bpm;
      s.hrv = r.hrv;
      s.rsa = r.rsa;
      s.piIr = v.amp;
      s.piRed = 0.8 * v.amp;
      s.noiseIr = v.noise;
      s.noiseRed = 1.5 * v.noise;
      s.wander = v.wander;
      char name[112];
      std::snprintf(name, sizeof name, "realistic HRV %.0f bpm (RR %.1f %% + RSA %.1f %%), %s", r.bpm, 100 * r.hrv,
                    100 * r.rsa, v.name);
      if (v.amp >= 0.02) {
        expect_pass(name, s);
      } else if (r.bpm <= 72) {
        expect_pass(name, s, 15.0, 8, -1, 0.75);
      } else {
        s.duration = 30;
        if (r.bpm <= 100)
          expect_pass(name, s, 30.0, 8, 6, 0.75);
        else
          expect_pass(name, s, 30.0, 8, 0, 0.0);
      }
    }
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
  test_switched_spoofs();
  test_noisy_periodic_spoofs();
  test_realistic_hrv();
  test_200bpm_not_halved();
  test_finger_removed();
  test_pulse_stops();
  test_timestamps();
  test_config_and_ui();
  return CHECK_SUMMARY();
}
