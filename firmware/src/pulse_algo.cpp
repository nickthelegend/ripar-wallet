// Live-pulse detection from MAX30102 IR/red samples (pure logic, host-testable, C++14).
//
// Input contract: one add() per sensor sample at ~100 Hz, t_ms = the sample's time on a sample clock (advance
// ~10 ms per sample, e.g. t0 + 10 * n). Samples whose t_ms does not increase are dropped; a gap > 250 ms restarts
// the measurement.
//
// Pipeline per sample (the filters are designed for 100 Hz):
//   1. Finger detection: fast EMA (~30 ms) of raw IR > fingerIrMin. Losing the finger (or a gap) ends the
//      measurement and clears everything (beats, sums, window stats).
//   2. DC removal (slow EMA, tau 1 s), inversion (more blood = less reflected light), then a band-pass:
//      2nd-order Butterworth high-pass 0.5 Hz + 2nd-order Butterworth low-pass 4 Hz (RBJ biquads).
//   3. Beat candidates from the slope-sum function (Zong et al. 2003): s[k] = sum of positive first differences
//      of the band-passed IR over the last 130 ms (the systolic upstroke; slow wander barely contributes).
//      Adaptive threshold = max(floor, 0.5 * decaying envelope of s), hysteresis (s must drop below the
//      threshold between beats), refractory max(250 ms, 0.45 * median interval). Nothing is detected during the
//      first 500 ms of contact.
//   4. A candidate is committed once s has stopped rising (150 ms) and the band-passed signal has passed its top.
//      Beat time (fiducial) = where the upstroke crosses the level halfway between its foot and its top, from a
//      least-squares line through the samples around the crossing: sub-sample accurate and, to first order,
//      insensitive to a sloping baseline. It gives bpm and jitter.
//      The spoof statistics use two more precise fiducials that do not depend on the foot (see commitBeat):
//      S = steepest point of the upstroke, U = upstroke midpoint between its onset and its top, each with its
//      timing error predicted from the measured sensor noise (running median of |second difference| of raw IR,
//      propagated through the band-pass). The cross-channel test uses a fourth, C = the slope centroid of the upstroke,
//      found by the same procedure on IR and on red in one wide window around the beat.
//   5. Beats older than windowMs drop out. bpm = 60000 / median interval, jitter = std / mean of intervals. The
//      spoof statistics keep a longer history (kHistMs, at most kHist beats).
//   6. passed = beats >= minBeats && bpm in [bpmMin, bpmMax] && jitter <= 0.35 && last beat recent
//            && not too regular (spoof: a signal generator, or one switched between perfect rhythms or shapes;
//               judged once 4 post-landing beats span 3 s (4 s above 80 bpm) - see updateStats / spoof_score):
//                 - robust successive differences of the beat intervals (lag 1 and lag 2) above a fixed floor and
//                   above 1.5x what the predicted timing noise alone would produce,
//                 - no more repeated interval values than random heart-rate variability produces,
//                 - cross-channel (v1.2 review): the successive interval differences of the IR and the red C
//                   fiducials must share their variability - a = (dI + dR) / 2 well above b = (dI - dR) / 2. Sensor
//                   noise moves each channel's beats independently, a heart moves both; without a heart a and b are
//                   identically distributed, so the timing noise is measured, not predicted (see cross_score);
//               once passed, the bar to keep the pulse is lower than the bar to establish it; a pulse that
//               starts after a pause (no beat for 3 s) is judged afresh, like a new landing
//            && no channel flat/constant && no ADC saturation
//            && at most 1/4 of the beats edge-like (square wave: the whole rise in one sample, also judged against
//               the sensor noise) or slow-rising
//               (sine, triangle: the upstroke takes >= 320 ms and >= 30 % of the interval; a PPG rises in 0.1-0.25 s)
//            && Pearson(band-passed red, band-passed IR) > 0.5 over the post-landing part of the window.
//
// Limits: the spoof statistics tell a heart from a naive generator (fixed rhythms and shapes, switched or not, with or
// without sensor noise), not from a source that replays a PPG with random beat-to-beat variability common to both
// channels (random timing, or common-mode amplitude noise from the source itself), nor from one that drives IR and red
// with independent timing. The cross-channel test is a significance test: per evaluation a periodic source plus
// Gaussian timing noise passes it with probability ~0.1 %, and very noisy periodic sources (noise at or above the pulse
// amplitude) still pass now and then (docs/FIRMWARE.md). A real pulse whose beat-to-beat variability is close to the
// red channel's timing noise (weak signal, high rate, low HRV) passes late or not at all - it looks exactly like a
// periodic source plus noise.
#include "pulse_algo.h"

#include <cmath>
#include <cstring>

namespace ripar {


namespace {

constexpr float kFs = 100.0f;          // nominal sample rate the filters are designed for
constexpr float kHpHz = 0.5f;          // band-pass low edge
constexpr float kLpHz = 4.0f;          // band-pass high edge
constexpr float kDcTauS = 1.0f;        // slow DC EMA
constexpr float kFastTauS = 0.03f;     // finger-detection EMA
constexpr float kEnvTauS = 2.5f;       // slope-sum envelope decay
constexpr float kThrFrac = 0.5f;       // threshold = kThrFrac * envelope
constexpr float kRiseRel = 0.0003f;    // minimum upstroke (band-passed counts) as a fraction of IR DC (0.03 %)
constexpr float kRiseAbs = 15.0f;      // ... and in absolute counts
constexpr uint32_t kSettleMs = 500;    // no beats while the finger settles on the pad
constexpr uint32_t kRefrMinMs = 250;   // hard refractory: 240 bpm can still be *measured* (and then rejected)
constexpr float kRefrFrac = 0.45f;     // adaptive refractory = kRefrFrac * median interval (blocks dicrotic waves)
constexpr uint32_t kSlopeWin = 13;     // slope-sum window, samples (130 ms)
constexpr uint32_t kHold = 15;         // samples the slope-sum must stay below its maximum before committing
constexpr uint32_t kTopHold = 4;       // ... and samples the band-passed signal must stay below its top
constexpr uint32_t kMaxWait = 60;      // commit at the latest this many samples after the slope-sum maximum
constexpr uint32_t kFootBack = 100;    // samples searched back from the top for the foot (not past the last top)
constexpr uint32_t kGapResetMs = 250;  // timestamp gap that restarts the measurement
constexpr float kJitterMax = 0.35f;    // above: not a rhythm (noise, motion, missed/extra beats)
constexpr float kCorrMin = 0.5f;       // red and IR pulses must move together
constexpr float kEdgeFrac = 0.6f;      // one sample carrying >= this share of an upstroke's rise => edge-like beat
constexpr float kEdgeFracN = 0.5f;     // noise-aware edge test: largest fall less kEdgeNoiseK x the fall noise ...
constexpr float kEdgeNoiseK = 2.5f;    // ... >= kEdgeFracN x (sum of falls less the noise's share) => edge-like beat
constexpr uint32_t kEdgeWin = 18;      // samples before the slope-sum maximum examined by the edge test
constexpr uint32_t kRegStartMs = 2000; // spoof statistics (regularity, correlation) ignore the landing phase
constexpr int kMinPost = 4;            // post-landing beats (3 intervals) the spoof statistics need at least
constexpr uint32_t kFlatSpan = 4;      // raw span (counts) at or below which a channel counts as constant
constexpr uint32_t kAdcMax = 0x3FFFF;  // MAX30102 18-bit full scale (saturation)
constexpr uint32_t kMinCorrSamples = 100;
constexpr uint32_t kTicksPerMs = 10;   // internal beat-time resolution: 0.1 ms
constexpr int kMaxBeats = 32;          // == size of beatT_
constexpr uint32_t kRegSpanMs = 3000;      // time the post-landing beats of the spoof statistics must span ...
constexpr uint32_t kRegSpanFastMs = 4000;  // ... or this long once the median interval is below kFastMs (80 bpm)
constexpr float kFastMs = 750.0f;
constexpr uint32_t kHistMs = 16000;        // beat history kept for the spoof statistics (bpm keeps windowMs)
constexpr float kEpsMag = 0.001f;          // successive differences below this fraction of the mean interval ...
constexpr float kEpsMagMs = 1.5f;          // ... or below this many ms (whichever is larger): too regular
constexpr float kNoiseK = 1.5f;            // ... or below kNoiseK x what the measured sensor noise alone produces
constexpr float kNoiseKLive = 1.1f;        // once passed in this session: the bar to keep a pulse (to establish: above)
constexpr float kFixedLive = 0.75f;        // ... and the fixed thresholds scaled by this
constexpr float kNoiseMaxLevel = 0.008f;   // noise test only while the predicted timing noise is below this fraction
constexpr float kEpsRep = 0.0015f;         // two intervals within this fraction of the mean interval "repeat"
constexpr float kRepQ = 0.12f;             // upper bound of the repeat probability of an interval pair of a heart
constexpr float kRepZ = 2.0f;              // repeats beyond kRepQ * pairs + kRepZ standard deviations: too regular
constexpr uint32_t kSlowRiseMs = 320;      // an upstroke rising for >= this ...
constexpr float kSlowRiseFrac = 0.30f;     // ... and >= this fraction of the interval is no PPG (sine, triangle)
constexpr uint32_t kRestartGapMs = 3000;   // no beat for this long (and 2.5 median intervals) ...
constexpr uint32_t kFirstBeatLateMs = 4000;  // ... or the first beat this late after placement: the pulse (re)started
constexpr uint32_t kRestartSettleMs = 1500;  // spoof statistics then start over, skipping the first beats' transient
constexpr float kOnsetFrac = 0.2f;         // upstroke onset: where the slope falls below this fraction of its maximum
constexpr float kNoiseKU = 1.22f;          // U timing error per unit of (band-passed noise / slope at the crossing)
constexpr uint32_t kRingN = 128;           // == PulseDetector::kRing (ring helpers outside the class)
// Cross-channel test (cross_score): which beats, which fiducial, how strict
constexpr float kCrossWin = 0.45f;         // fiducial window: this x the median interval before the detector's top ...
constexpr uint32_t kCrossWinDef = 40;      // ... (samples) before a median interval is known
constexpr uint32_t kCrossWinMax = 70;      // ... at most (samples)
constexpr float kCenFrac = 0.5f;           // slope centroid: weight = rise above this fraction of the steepest step
constexpr float kCrossSlope = 0.6f;        // only beats whose steepest step reaches this x the median one ...
constexpr float kCrossIv = 0.25f;          // ... and whose intervals lie within this fraction of the median interval
constexpr float kCrossLive = 0.6f;         // once passed in this session: the bar to keep a pulse (x the bar to establish)
constexpr float kCrossFloorTk = 1.0f;      // noise floor of the IR / red difference (ticks = 0.1 ms: fiducial rounding)

struct Bq {
  float b0, b1, b2, a1, a2;
};

// RBJ cookbook biquad, Q = 1/sqrt(2) (Butterworth)
Bq make_bq(bool highpass, float fc) {
  const double pi = 3.14159265358979323846;
  const double w0 = 2.0 * pi * double(fc) / double(kFs);
  const double cw = std::cos(w0);
  const double alpha = std::sin(w0) / (2.0 * 0.70710678118654752);
  const double a0 = 1.0 + alpha;
  Bq q;
  if (highpass) {
    q.b0 = float((1.0 + cw) / 2.0 / a0);
    q.b1 = float(-(1.0 + cw) / a0);
  } else {
    q.b0 = float((1.0 - cw) / 2.0 / a0);
    q.b1 = float((1.0 - cw) / a0);
  }
  q.b2 = q.b0;
  q.a1 = float(-2.0 * cw / a0);
  q.a2 = float((1.0 - alpha) / a0);
  return q;
}

struct Consts {
  Bq hp, lp;
  float dcA, fastA, envDecay;
  float gainY;   // std of the band-passed signal per unit of white input noise
  float gainAC;  // std of (g[k+1] - g[k-1]), g = first difference of the band-passed signal, per unit input noise
};

// White-noise gain of the band-pass followed by the FIR fir[0..nf-1] (from the impulse response, double precision).
double noise_gain(const Bq& hp, const Bq& lp, const double* fir, int nf) {
  enum { kN = 512 };
  double hbuf[kN];
  double z[4] = {0, 0, 0, 0};
  for (int i = 0; i < kN; i++) {
    const double x = i == 0 ? 1.0 : 0.0;
    double y = hp.b0 * x + z[0];
    z[0] = hp.b1 * x - hp.a1 * y + z[1];
    z[1] = hp.b2 * x - hp.a2 * y;
    const double u = y;
    y = lp.b0 * u + z[2];
    z[2] = lp.b1 * u - lp.a1 * y + z[3];
    z[3] = lp.b2 * u - lp.a2 * y;
    hbuf[i] = y;
  }
  double ss = 0;
  for (int i = 0; i < kN + nf; i++) {
    double v = 0;
    for (int j = 0; j < nf; j++)
      if (i - j >= 0 && i - j < kN) v += fir[j] * hbuf[i - j];
    ss += v * v;
  }
  return std::sqrt(ss);
}

Consts make_consts() {
  Consts k;
  k.hp = make_bq(true, kHpHz);
  k.lp = make_bq(false, kLpHz);
  k.dcA = float(1.0 - std::exp(-1.0 / (double(kFs) * double(kDcTauS))));
  k.fastA = float(1.0 - std::exp(-1.0 / (double(kFs) * double(kFastTauS))));
  k.envDecay = float(std::exp(-1.0 / (double(kFs) * double(kEnvTauS))));
  const double one[1] = {1.0}, ac[4] = {1.0, -1.0, -1.0, 1.0};  // y[k+1] - y[k] - y[k-1] + y[k-2]
  k.gainY = float(noise_gain(k.hp, k.lp, one, 1));
  k.gainAC = float(noise_gain(k.hp, k.lp, ac, 4));
  return k;
}

const Consts& K() {
  static const Consts k = make_consts();
  return k;
}

// transposed direct form II
inline float biquad(const Bq& q, float* z, float x) {
  const float y = q.b0 * x + z[0];
  z[0] = q.b1 * x - q.a1 * y + z[1];
  z[1] = q.b2 * x - q.a2 * y;
  return y;
}

inline float fmaxf_(float a, float b) { return a > b ? a : b; }
inline float fminf_(float a, float b) { return a < b ? a : b; }

inline uint32_t to_u32(double v) {
  if (!(v > 0)) return 0;
  if (v >= 4294967295.0) return 0xFFFFFFFFu;
  return uint32_t(v + 0.5);
}

inline uint8_t clamp8(float v) {
  if (!(v > 0)) return 0;
  if (v >= 255.0f) return 255;
  return uint8_t(std::floor(v + 0.5f));
}

inline void put_be(uint8_t* p, uint32_t v, int n) {
  for (int i = n - 1; i >= 0; i--) {
    p[i] = uint8_t(v & 0xFF);
    v >>= 8;
  }
}

// k-th smallest of v[0..n-1] (insertion sort, n <= kMaxBeats); v is reordered
float kth(float* v, int n, int k) {
  for (int i = 1; i < n; i++) {
    const float x = v[i];
    int j = i - 1;
    while (j >= 0 && v[j] > x) {
      v[j + 1] = v[j];
      j--;
    }
    v[j + 1] = x;
  }
  return v[k < 0 ? 0 : (k >= n ? n - 1 : k)];
}

// Which order statistic of nd absolute differences estimates the beat-to-beat variability: robust against up to 3
// contaminated differences (an abrupt rate / shape / phase step contaminates 2 or 3) and against up to half of them.
int robust_index(int nd) {
  if (nd <= 2) return nd - 1;  // 2 differences: both must vary (only reachable at slow rates, see kRegSpanMs)
  if (nd <= 5) return 1;
  const int a = (nd - 1) / 2, b = nd - 4;
  return a < b ? a : b;
}

// q-quantile of |N(0, 1)| (sqrt(2) erfinv(q), series; accurate to < 2 % for q <= 0.75)
float half_normal_quantile(float q) {
  const double x = double(q), x2 = x * x, pi = 3.14159265358979323846;
  return float(1.4142135623730951 * 0.886226925452758 * x * (1.0 + pi * x2 / 12.0 + 7.0 * pi * pi * x2 * x2 / 480.0));
}

// Spoof score of one beat-time series t[0..n-1] (ticks) with the predicted white-noise timing error sig[0..n-1]
// (ticks) of each beat; >= 1 = beat-to-beat variability like a heart's, < 1 = too regular. Three tests:
//   lag 1 / lag 2: a robust order statistic of |I[k+1] - I[k]| and |I[k+2] - I[k]| (zero for a constant or a strictly
//     alternating rhythm) must reach kEpsMag of the mean interval and kNoiseK times what the timing noise predicted
//     from the measured sensor noise gives for that order statistic;
//   repeats: the number of interval pairs equal within kEpsRep must stay within what random variability gives
//     (a source switching between a few perfect rhythms repeats its intervals, however often it switches).
struct SpoofScore {
  float fixed = 0;  // fixed-threshold and repeat tests
  float noise = 0;  // noise-aware magnitude test
  float level = 0;  // predicted timing noise (median lag-1, relative to the mean interval)
};

SpoofScore spoof_score(const uint32_t* t, const float* sig, int n, bool live) {
  const float kn = live ? kNoiseKLive : kNoiseK;
  const float kf = live ? kFixedLive : 1.0f;
  SpoofScore out;
  const int m = n - 1;
  if (m < 3) return out;
  double iv[kMaxBeats];
  double sum = 0;
  for (int i = 0; i < m; i++) {
    iv[i] = double(int32_t(t[i + 1] - t[i]));
    sum += iv[i];
  }
  const double mean = sum / m;
  if (!(mean > 0)) return out;
  float score = 1e9f, nscore = 1e9f;
  float d[kMaxBeats], e[kMaxBeats];
  const float fixedThr = kf * fmaxf_(kEpsMag * float(mean), kEpsMagMs * float(kTicksPerMs));
  for (int lag = 1; lag <= 2; lag++) {
    const int nd = m - lag;
    if (nd < 2) break;
    for (int i = 0; i < nd; i++) {
      d[i] = float(std::fabs(iv[i + lag] - iv[i]));
      const float a = sig[i], b = sig[i + 1], c = sig[i + 2], x = lag == 2 ? sig[i + 3] : 0.0f;
      e[i] = lag == 1 ? std::sqrt(a * a + 4.0f * b * b + c * c) : std::sqrt(a * a + b * b + c * c + x * x);
    }
    const int k = robust_index(nd);
    const float stat = kth(d, nd, k);
    const float emed = kth(e, nd, nd / 2);
    if (lag == 1) out.level = float(double(emed) / mean);
    const float noise = emed * half_normal_quantile((float(k) + 0.5f) / float(nd));
    score = fminf_(score, stat / fixedThr);
    nscore = fminf_(nscore, noise > 0 ? stat / (kn * noise) : 1e9f);
  }
  int rep = 0;
  const double tol = double(kEpsRep) * mean;
  for (int i = 0; i < m; i++)
    for (int j = i + 1; j < m; j++) rep += int(std::fabs(iv[i] - iv[j]) < tol);
  const double pairs = 0.5 * double(m) * double(m - 1);
  const double q = double(kRepQ);
  int thr = int(std::ceil(q * pairs + double(kRepZ) * std::sqrt(q * (1.0 - q) * pairs)));
  if (thr < 2) thr = 2;
  out.fixed = fminf_(score, float(thr) / float(rep + 1));
  out.noise = nscore;
  return out;
}

// Steepest-point (S) and upstroke-midpoint (U) fiducials of one upstroke (see PulseDetector::commitBeat) of the
// band-passed ring y (timestamps ts), foot < top, lo = the start of the foot search. noiseRaw = white input noise
// (counts, std) for the predicted timing errors. s is always set (sOk: its parabolic interpolation was defined);
// u only when uOk (a least-squares line through the midpoint crossing was defined).
struct UpFids {
  uint32_t s = 0, u = 0;
  float sigS = 1e6f, sigU = 1e6f;
  uint32_t onset = 0;
  bool sOk = false, uOk = false;
};

UpFids upstroke_fids(const float* y, const uint32_t* ts, uint32_t lo, uint32_t foot, uint32_t top, float noiseRaw) {
  const Consts& kc = K();
  UpFids f;
  uint32_t km = foot + 1;
  float gm = y[km % kRingN] - y[(km - 1) % kRingN];
  for (uint32_t i = foot + 2; i <= top; i++) {
    const float g = y[i % kRingN] - y[(i - 1) % kRingN];
    if (g > gm) {
      gm = g;
      km = i;
    }
  }
  double off = 0, dn = 0;
  if (km >= lo + 2) {
    const double ga = double(y[(km - 1) % kRingN]) - double(y[(km - 2) % kRingN]);
    const double gc = double(y[(km + 1) % kRingN]) - double(y[km % kRingN]);
    dn = ga - 2.0 * double(gm) + gc;
    if (dn < 0) off = 0.5 * (ga - gc) / dn;
    if (off < -0.5) off = -0.5;
    if (off > 0.5) off = 0.5;
  }
  const uint32_t tKa = ts[(km - 1) % kRingN], tKb = ts[km % kRingN];
  const double stepTk = double(int32_t(tKb - tKa));
  f.s = tKa + uint32_t(int32_t(std::floor((0.5 + off) * stepTk + 0.5)));
  f.sOk = dn < 0;
  if (f.sOk) f.sigS = float(0.5 * double(kc.gainAC) * double(noiseRaw) / -dn * stepTk);
  uint32_t on = km;
  while (on > foot + 1 && y[(on - 1) % kRingN] - y[(on - 2) % kRingN] >= kOnsetFrac * gm) on--;
  f.onset = on - 1;
  const float lv = 0.5f * (y[f.onset % kRingN] + y[top % kRingN]);
  uint32_t c2 = top;
  while (c2 > f.onset && y[c2 % kRingN] >= lv) c2--;
  const uint32_t b0 = c2 >= f.onset + 2 ? c2 - 2 : f.onset;
  const uint32_t b1 = c2 + 3 <= top ? c2 + 3 : top;
  const uint32_t tR = ts[c2 % kRingN];
  double n2 = 0, tsum = 0, ys = 0, tts = 0, tys = 0;
  for (uint32_t i = b0; i <= b1; i++) {
    const double tt = double(int32_t(ts[i % kRingN] - tR)), yy = y[i % kRingN];
    n2 += 1;
    tsum += tt;
    ys += yy;
    tts += tt * tt;
    tys += tt * yy;
  }
  const double dd = n2 * tts - tsum * tsum;
  const double sl = dd > 0 ? (n2 * tys - tsum * ys) / dd : 0;
  if (n2 >= 3 && sl > 0) {
    double tu = (double(lv) - (ys - sl * tsum) / n2) / sl;
    const double lo2 = double(int32_t(ts[b0 % kRingN] - tR)), hi2 = double(int32_t(ts[b1 % kRingN] - tR));
    if (tu < lo2) tu = lo2;
    if (tu > hi2) tu = hi2;
    f.u = tR + uint32_t(int32_t(std::floor(tu + 0.5)));
    f.sigU = float(double(kNoiseKU) * double(kc.gainY) * double(noiseRaw) / sl);
    f.uOk = true;
  }
  return f;
}

// Cross-channel fiducial of one channel of a beat: in the window [wlo, whi] of the band-passed ring y (timestamps ts)
// the top = its highest sample, the foot = the lowest sample before it, and C = the slope centroid of the upstroke
// foot..top: the mean time of its sample steps, each weighted by how far its rise exceeds kCenFrac of the steepest
// step. The flat foot and top (where noise dominates) carry no weight and no threshold decision can flip from one
// sample to the next, so C moves smoothly with the noise. *steep = the steepest step. false: no upstroke.
bool centroid_fid(const float* y, const uint32_t* ts, uint32_t wlo, uint32_t whi, uint32_t& out, float* steep) {
  if (whi < wlo + 2) return false;
  uint32_t top = wlo;
  for (uint32_t i = wlo + 1; i <= whi; i++)
    if (y[i % kRingN] > y[top % kRingN]) top = i;
  uint32_t foot = top;
  for (uint32_t i = wlo; i < top; i++)
    if (y[i % kRingN] < y[foot % kRingN]) foot = i;
  if (top < foot + 2) return false;
  float gm = 0;
  for (uint32_t i = foot + 1; i <= top; i++) {
    const float g = y[i % kRingN] - y[(i - 1) % kRingN];
    if (g > gm) gm = g;
  }
  if (!(gm > 0)) return false;
  const uint32_t tRef = ts[top % kRingN];
  double sw = 0, stw = 0;
  for (uint32_t i = foot + 1; i <= top; i++) {
    const double g = double(y[i % kRingN]) - double(y[(i - 1) % kRingN]) - double(kCenFrac) * double(gm);
    if (!(g > 0)) continue;
    const double tm = 0.5 * (double(int32_t(ts[i % kRingN] - tRef)) + double(int32_t(ts[(i - 1) % kRingN] - tRef)));
    sw += g;
    stw += g * tm;
  }
  if (!(sw > 0)) return false;
  out = tRef + uint32_t(int32_t(std::floor(stw / sw + 0.5)));
  if (steep) *steep = gm;
  return true;
}

// Cross-channel test: IR beat times tI[0..n-1] and red beat times tR[0..n-1] (ticks, the slope centroids of the same
// beats), ok[i] = both found, steep[i] = the IR beat's steepest step. Sensor noise moves the IR and the red fiducial of
// a beat independently; a heart moves both by the same amount. With dI, dR = the successive interval differences
// (second differences of the beat times) of the two channels, a = (dI + dR) / 2 carries the heart's variability plus
// noise and b = (dI - dR) / 2 the noise alone; without a heart (any periodic source, whatever its shape, amplitude and
// noise) a and b are identically distributed. So this measures the timing noise instead of predicting it.
// Only clean beat triples count: both fiducials found, every steepest step >= kCrossSlope x the median one and both
// intervals within kCrossIv of the median interval. A detection that noise made on a weak feature of a periodic source
// (an extra beat on a filter recovery, a split upstroke) lands on the same deterministic feature in both channels and
// would otherwise look like a common irregularity; a heart's beats are all strong and evenly spaced at rest.
// Score = sqrt(mean of the nd - trim smallest a^2 / mean of all b^2) / kCrossK[nd], trim = (nd + 1) / 3 (a common step
// - rate / shape / phase switch - contaminates 2-3 values). kCrossK[nd] = the 99.9 % quantile of that ratio for nd
// pure-noise second differences with equal noise in both channels (Monte Carlo, 3e6 draws per nd; a noisier red channel
// only lowers it); once passed the bar is kCrossLive x that. >= 1 = variability common to both channels, like a heart's.
constexpr int kCrossMaxNd = 22;  // == kHist - 2
const float kCrossK[kCrossMaxNd + 1] = {1e9f, 1e9f, 26.6f, 12.1f, 8.3f,  5.35f, 4.6f,  4.1f,  3.26f, 3.04f, 2.88f, 2.45f,
                                        2.38f, 2.3f, 2.05f, 2.02f, 1.98f, 1.8f,  1.79f, 1.76f, 1.64f, 1.62f, 1.61f};

float cross_score(const uint32_t* tI, const uint32_t* tR, const uint8_t* ok, const float* steep, int n, bool live) {
  if (n < 4) return 0;
  float tmp[kCrossMaxNd + 2];
  for (int i = 0; i < n; i++) tmp[i] = steep[i];
  const float gMin = kCrossSlope * kth(tmp, n, n / 2);
  for (int i = 0; i + 1 < n; i++) tmp[i] = float(int32_t(tI[i + 1] - tI[i]));
  const float im = kth(tmp, n - 1, (n - 1) / 2);
  const float ivLo = (1.0f - kCrossIv) * im, ivHi = (1.0f + kCrossIv) * im;
  float a2[kCrossMaxNd];
  double sb = 0;
  int nd = 0;
  for (int i = 0; i + 2 < n && nd < kCrossMaxNd; i++) {
    if (!(ok[i] && ok[i + 1] && ok[i + 2])) continue;
    if (steep[i] < gMin || steep[i + 1] < gMin || steep[i + 2] < gMin) continue;
    const float i1 = float(int32_t(tI[i + 1] - tI[i])), i2 = float(int32_t(tI[i + 2] - tI[i + 1]));
    if (i1 < ivLo || i1 > ivHi || i2 < ivLo || i2 > ivHi) continue;
    const double dI = double(int32_t(tI[i + 2] - tI[i + 1])) - double(int32_t(tI[i + 1] - tI[i]));
    const double dR = double(int32_t(tR[i + 2] - tR[i + 1])) - double(int32_t(tR[i + 1] - tR[i]));
    a2[nd++] = float(0.25 * (dI + dR) * (dI + dR));
    sb += 0.25 * (dI - dR) * (dI - dR);
  }
  if (nd < 2) return 0;
  const int trim = (nd + 1) / 3;
  kth(a2, nd, 0);  // sorts a2 ascending
  double sa = 0;
  for (int i = 0; i < nd - trim; i++) sa += double(a2[i]);
  sa /= double(nd - trim);
  sb /= double(nd);
  const double floorB = double(kCrossFloorTk) * double(kCrossFloorTk);
  if (sb < floorB) sb = floorB;
  return float(std::sqrt(sa / sb)) / (kCrossK[nd] * (live ? kCrossLive : 1.0f));
}

}  // namespace

PulseDetector::PulseDetector(const PulseConfig& c) : c_(c) { reset(); }

void PulseDetector::reset() {
  haveT_ = false;
  haveFast_ = false;
  lastT_ = 0;
  fastIr_ = fastRed_ = 0;
  clearSession();
}

void PulseDetector::clearSession() {
  r_ = PulseResult();
  dcIr_ = dcRed_ = lp_ = prev_ = prev2_ = thr_ = 0;
  fingerSince_ = lastBeat_ = 0;
  std::memset(beatT_, 0, sizeof(beatT_));
  nBeats_ = 0;
  sumIr_ = sumRed_ = 0;
  nSamples_ = 0;
  haveFinger_ = false;
  inPk_ = false;
  armed_ = false;  // the first beat must start after the settle period, not mid-upstroke
  haveBeat_ = false;
  std::memset(zIr_, 0, sizeof(zIr_));
  std::memset(zRed_, 0, sizeof(zRed_));
  std::memset(ringY_, 0, sizeof(ringY_));
  std::memset(ringYr_, 0, sizeof(ringYr_));
  std::memset(ringT_, 0, sizeof(ringT_));
  std::memset(ringRaw_, 0, sizeof(ringRaw_));
  pkIdx_ = topIdx_ = lastTopIdx_ = 0;
  medMs_ = 0;
  regular_ = 0;
  postBeats_ = 0;
  edgeMask_ = 0;
  slowMask_ = 0;
  std::memset(histU_, 0, sizeof(histU_));
  std::memset(histS_, 0, sizeof(histS_));
  std::memset(sigU_, 0, sizeof(sigU_));
  std::memset(sigS_, 0, sizeof(sigS_));
  std::memset(histC_, 0, sizeof(histC_));
  std::memset(histCr_, 0, sizeof(histCr_));
  std::memset(okC_, 0, sizeof(okC_));
  std::memset(steepH_, 0, sizeof(steepH_));
  nHist_ = 0;
  noiseMed_ = 0;
  regStartTk_ = 0;
  restarted_ = false;
  regProgress_ = 0;
  live_ = false;
  std::memset(bk_, 0, sizeof(bk_));
  bucketMs_ = c_.windowMs / kBuckets;
  if (bucketMs_ == 0) bucketMs_ = 1;
}

void PulseDetector::beginSession(uint32_t ir, uint32_t red, uint32_t t_ms) {
  clearSession();
  haveFinger_ = true;
  fingerSince_ = t_ms;
  regStartTk_ = (t_ms + kRegStartMs) * kTicksPerMs;
  dcIr_ = float(ir);
  dcRed_ = float(red);
  r_.finger = true;
}

const PulseResult& PulseDetector::add(uint32_t ir, uint32_t red, uint32_t t_ms) {
  r_.beatNow = false;
  if (haveT_) {
    const uint32_t dt = t_ms - lastT_;
    if (dt == 0 || dt >= 0x80000000u) return r_;  // timestamp not increasing: drop the sample
    if (dt > kGapResetMs && haveFinger_) clearSession();  // samples were lost: restart the measurement
  }
  haveT_ = true;
  lastT_ = t_ms;

  const Consts& k = K();
  if (!haveFast_) {
    fastIr_ = float(ir);
    fastRed_ = float(red);
    haveFast_ = true;
  } else {
    fastIr_ += k.fastA * (float(ir) - fastIr_);
    fastRed_ += k.fastA * (float(red) - fastRed_);
  }

  if (!(fastIr_ > float(c_.fingerIrMin))) {
    if (haveFinger_ || r_.finger) clearSession();
    r_.irDC = to_u32(fastIr_);
    r_.redDC = to_u32(fastRed_);
    return r_;
  }
  if (!haveFinger_) beginSession(ir, red, t_ms);

  const uint32_t el = t_ms - fingerSince_;
  r_.finger = true;
  r_.elapsedMs = el;
  sumIr_ += ir;
  sumRed_ += red;
  nSamples_++;
  r_.irDC = to_u32(sumIr_ / nSamples_);
  r_.redDC = to_u32(sumRed_ / nSamples_);

  // DC removal + inversion + band-pass
  dcIr_ += k.dcA * (float(ir) - dcIr_);
  dcRed_ += k.dcA * (float(red) - dcRed_);
  const float yi = biquad(k.lp, zIr_ + 2, biquad(k.hp, zIr_, dcIr_ - float(ir)));
  const float yr = biquad(k.lp, zRed_ + 2, biquad(k.hp, zRed_, dcRed_ - float(red)));

  const uint32_t idx = nSamples_ - 1;  // sample index within this measurement
  const uint32_t tk = t_ms * kTicksPerMs;
  ringY_[idx % kRing] = yi;
  ringYr_[idx % kRing] = yr;
  ringT_[idx % kRing] = tk;
  ringRaw_[idx % kRing] = ir;
  if (idx >= 2) {  // sensor noise: running median of |second difference| of raw IR (pulse and wander barely move it)
    const int32_t e2 = int32_t(ir) - 2 * int32_t(ringRaw_[(idx - 1) % kRing]) + int32_t(ringRaw_[(idx - 2) % kRing]);
    const float a = float(e2 < 0 ? -e2 : e2);
    if (!(noiseMed_ > 0)) noiseMed_ = a > 1.0f ? a : 1.0f;
    else noiseMed_ += (a > noiseMed_ ? noiseMed_ : -noiseMed_) * (1.0f / 32.0f);
    if (noiseMed_ < 0.05f) noiseMed_ = 0.05f;  // a noiseless (synthetic) signal: stay well clear of denormals
  }

  const bool settled = el >= kSettleMs && idx > 2 * kSlopeWin;
  if (settled) {
    if (el >= kRegStartMs) accumulate(el, ir, red, yi, yr);
    // slope-sum: positive rises of the band-passed IR over the last kSlopeWin samples
    float s = 0;
    for (uint32_t i = 0; i < kSlopeWin; i++) {
      const float d = ringY_[(idx - i) % kRing] - ringY_[(idx - i - 1) % kRing];
      if (d > 0) s += d;
    }
    detect(idx, tk, s);
  }
  pruneBeats(tk);

  // ---- pass decision ----
  bool ok = settled && c_.minBeats > 0 && nBeats_ >= c_.minBeats && r_.bpm >= c_.bpmMin && r_.bpm <= c_.bpmMax &&
            (!c_.strict || regular_ >= 1.0f) && r_.jitter <= kJitterMax;
  if (ok) {
    // the pulse must still be there: last beat no older than 2.5 median intervals (and never > 2 slowest beats)
    float limitMs = 2.5f * medMs_;
    if (c_.bpmMin > 0) limitMs = fminf_(limitMs, 2.0f * 60000.0f / c_.bpmMin);
    const float ageMs = float(tk - lastBeat_) / float(kTicksPerMs);
    ok = ageMs <= limitMs;
  }
  r_.regular = regular_;
  r_.windowOk = windowOk(el);
  if (ok) ok = r_.windowOk;
  r_.passed = ok;
  if (ok) live_ = true;

  // progress: both "minBeats in the window" and the post-landing evidence (kMinPost beats over kRegSpanMs) count
  if (ok) {
    r_.progress = 1.0f;
  } else if (!settled || c_.minBeats <= 0) {
    r_.progress = 0.0f;
  } else {
    const float p1 = float(nBeats_ < c_.minBeats ? nBeats_ : c_.minBeats) / float(c_.minBeats);
    const float p2 = regProgress_;
    r_.progress = fminf_(fminf_(p1, 0.5f + 0.5f * p2), 0.95f);
  }
  return r_;
}

void PulseDetector::detect(uint32_t idx, uint32_t tk, float s) {
  const Consts& k = K();
  if (!haveBeat_ && lastTopIdx_ == 0) lastTopIdx_ = idx;  // first settled sample bounds the first foot search
  lp_ = fmaxf_(s, lp_ * k.envDecay);
  const float minRise = fmaxf_(kRiseAbs, kRiseRel * dcIr_);
  thr_ = fmaxf_(minRise, kThrFrac * lp_);

  if (inPk_) {
    if (s > prev2_) {
      prev2_ = s;
      pkIdx_ = idx;
    }
    if (ringY_[idx % kRing] > ringY_[topIdx_ % kRing]) topIdx_ = idx;
    const uint32_t sincePk = idx - pkIdx_;
    if ((sincePk >= kHold && idx - topIdx_ >= kTopHold) || sincePk >= kMaxWait) {
      inPk_ = false;
      armed_ = false;
      commitBeat(pkIdx_, topIdx_, idx);
    }
  }
  if (!inPk_) {
    if (!armed_) {
      if (s < thr_) armed_ = true;  // hysteresis: the slope-sum must fall below threshold between beats
    } else if (s > thr_) {
      bool refrOk = true;
      if (haveBeat_) {
        float refrMs = float(kRefrMinMs);
        if (medMs_ > 0 && nBeats_ >= 3) refrMs = fmaxf_(refrMs, kRefrFrac * medMs_);
        refrOk = float(tk - lastBeat_) >= refrMs * float(kTicksPerMs);
      }
      if (refrOk) {
        inPk_ = true;
        prev2_ = s;
        pkIdx_ = idx;
        topIdx_ = idx;
      }
    }
  }
}

// pk = slope-sum maximum, top = band-passed maximum after the candidate started, idx = current sample.
void PulseDetector::commitBeat(uint32_t pk, uint32_t top, uint32_t idx) {
  if (top >= idx) return;  // still rising: drift, not a beat
  // foot search range: within the ring, after the previous beat's top (or the settle point), <= kFootBack back
  uint32_t lo = idx + 1 > uint32_t(kRing) ? idx + 1 - uint32_t(kRing) : 0;
  if (lastTopIdx_ + 1 > lo) lo = lastTopIdx_ + 1;
  if (top > kFootBack && top - kFootBack > lo) lo = top - kFootBack;
  if (top <= lo + 1) return;

  // foot = lowest point before the top
  uint32_t foot = top;
  for (uint32_t i = lo; i < top; i++)
    if (ringY_[i % kRing] < ringY_[foot % kRing]) foot = i;
  const float yFoot = ringY_[foot % kRing], yTop = ringY_[top % kRing];
  const float prom = yTop - yFoot;
  if (!(prom >= fmaxf_(kRiseAbs, kRiseRel * dcIr_)) || foot >= top) return;

  // last sample below the half level on the way up to the top: the crossing lies in (c, c+1]
  const float level = yFoot + 0.5f * prom;
  uint32_t c = top;
  while (c > foot && ringY_[c % kRing] >= level) c--;
  // least-squares line through up to 6 samples around the crossing (c-2 .. c+3, clipped to the upstroke)
  const uint32_t a0 = c >= foot + 2 ? c - 2 : foot;
  const uint32_t a1 = c + 3 <= top ? c + 3 : top;
  const uint32_t tRef = ringT_[c % kRing];
  double sn = 0, st = 0, sy = 0, stt = 0, sty = 0;
  for (uint32_t i = a0; i <= a1; i++) {
    const double t = double(int32_t(ringT_[i % kRing] - tRef));
    const double y = ringY_[i % kRing];
    sn += 1;
    st += t;
    sy += y;
    stt += t * t;
    sty += t * y;
  }
  const double t0 = double(int32_t(ringT_[a0 % kRing] - tRef)), t1 = double(int32_t(ringT_[a1 % kRing] - tRef));
  double tc;
  const double den = sn * stt - st * st;
  const double slope = den > 0 ? (sn * sty - st * sy) / den : 0;
  if (sn >= 3 && slope > 0) {
    tc = (double(level) - (sy - slope * st) / sn) / slope;
  } else {  // two-point interpolation
    const float y0 = ringY_[c % kRing], y1 = ringY_[(c + 1) % kRing];
    const double dt = double(int32_t(ringT_[(c + 1) % kRing] - tRef));
    tc = y1 > y0 ? dt * double(level - y0) / double(y1 - y0) : 0;
  }
  if (tc < t0) tc = t0;
  if (tc > t1) tc = t1;
  const uint32_t fid = tRef + uint32_t(int32_t(std::floor(tc + 0.5)));

  if (haveBeat_) {
    const int32_t since = int32_t(fid - lastBeat_);
    if (since < int32_t(kRefrMinMs * kTicksPerMs)) return;  // same upstroke / too close to the last beat
  }

  // Two more fiducials for the spoof statistics (bpm keeps using fid). Neither depends on the foot, which on a slow or
  // wandering signal can lie anywhere in the diastole:
  //  S = steepest point of the upstroke: maximum first difference, parabolic sub-sample peak. Immune to baseline
  //      offset and slope (so also to the landing transient); precise on a sharp (PPG-like) upstroke.
  //  U = upstroke midpoint: where the upstroke crosses the level halfway between its onset (the slope has fallen to
  //      kOnsetFrac of its maximum) and its top, least-squares line as for fid. Precise on smooth upstrokes too.
  // Each comes with its timing error predicted from the measured sensor noise (white noise through the band-pass).
  static_assert(uint32_t(kRing) == kRingN, "kRingN must equal kRing");
  const float noiseRaw = noiseMed_ / 1.6524f;  // median |N(0, 6 s^2)| = 0.6745 * sqrt(6) * s
  const UpFids fi = upstroke_fids(ringY_, ringT_, lo, foot, top, noiseRaw);
  const uint32_t fidS = fi.s, fidU = fi.uOk ? fi.u : fid, onset = fi.onset;
  const float sigS = fi.sigS, sigU = fi.sigU;
  // Cross-channel fiducials (see cross_score): the same procedure on IR and red, each channel finding its own
  // upstroke in one wide window around this beat (up to kCrossWin x the median interval before the top, and up to
  // now). Neither depends on where this channel's noise put the detector's foot and top, so a detection that locked
  // onto noise does not drag both channels' fiducials along.
  uint32_t cIr = 0, cRed = 0;
  float steepC = 0;
  bool okC = false;
  {
    uint32_t w = medMs_ > 0 ? uint32_t(kCrossWin * medMs_ / 10.0f) : kCrossWinDef;
    if (w > kCrossWinMax) w = kCrossWinMax;
    const uint32_t ringLo = idx + 1 > uint32_t(kRing) ? idx + 1 - uint32_t(kRing) : 0;
    uint32_t wlo = top > w ? top - w : 0;
    if (wlo < ringLo) wlo = ringLo;
    okC = centroid_fid(ringY_, ringT_, wlo, idx, cIr, &steepC) && centroid_fid(ringYr_, ringT_, wlo, idx, cRed, nullptr);
  }
  // Slow symmetric upstroke (sine, triangle): a PPG rises in ~100-250 ms whatever the rate.
  const uint32_t riseTk = ringT_[top % kRing] - ringT_[onset % kRing];
  const bool slow = haveBeat_ && riseTk >= kSlowRiseMs * kTicksPerMs &&
                    float(riseTk) >= kSlowRiseFrac * float(fid - lastBeat_);
  // A pulse that (re)starts after a pause (a flat stretch, lost beats, a spoof switched on late) comes with the same
  // filter transient as a landing: the spoof statistics start over and skip its first beats.
  {
    float gapLimit = float(kRestartGapMs);
    if (2.5f * medMs_ > gapLimit) gapLimit = 2.5f * medMs_;
    const bool late = haveBeat_ ? float(fid - lastBeat_) > gapLimit * float(kTicksPerMs)
                                : fid - fingerSince_ * kTicksPerMs > kFirstBeatLateMs * kTicksPerMs;
    if (late) {
      nHist_ = 0;
      regStartTk_ = fid + kRestartSettleMs * kTicksPerMs;
      restarted_ = true;
    }
  }
  if (nHist_ >= kHist) {
    std::memmove(histU_, histU_ + 1, sizeof(histU_[0]) * (kHist - 1));
    std::memmove(histS_, histS_ + 1, sizeof(histS_[0]) * (kHist - 1));
    std::memmove(sigU_, sigU_ + 1, sizeof(sigU_[0]) * (kHist - 1));
    std::memmove(sigS_, sigS_ + 1, sizeof(sigS_[0]) * (kHist - 1));
    std::memmove(histC_, histC_ + 1, sizeof(histC_[0]) * (kHist - 1));
    std::memmove(histCr_, histCr_ + 1, sizeof(histCr_[0]) * (kHist - 1));
    std::memmove(okC_, okC_ + 1, sizeof(okC_[0]) * (kHist - 1));
    std::memmove(steepH_, steepH_ + 1, sizeof(steepH_[0]) * (kHist - 1));
    nHist_ = kHist - 1;
  }
  histU_[nHist_] = fidU;
  histS_[nHist_] = fidS;
  sigU_[nHist_] = sigU;
  sigS_[nHist_] = sigS;
  histC_[nHist_] = cIr;
  histCr_[nHist_] = cRed;
  okC_[nHist_] = okC ? 1 : 0;
  steepH_[nHist_] = steepC;
  nHist_++;

  // Edge test: a real upstroke takes >= ~60 ms, so no single 10 ms sample carries most of it (typically 15-30 %).
  // A square wave (LED blinking into the sensor) puts ~100 % of the rise into one sample. Measured on raw IR
  // (upstroke = IR falling) over the kEdgeWin samples up to the slope-sum maximum; noise only adds to the sum.
  uint32_t step = 0;
  double rise = 0;
  const uint32_t e0 = pk > lo + kEdgeWin ? pk - kEdgeWin : lo + 1;
  for (uint32_t i = e0; i <= pk; i++) {
    const uint32_t u = ringRaw_[i % kRing], v = ringRaw_[(i - 1) % kRing];
    const uint32_t d = v > u ? v - u : 0;
    rise += d;
    if (d > step) step = d;
  }
  // With sensor noise the sum also collects the noise's falls and a square wave no longer looks edge-like, so the test
  // also runs noise-aware: the largest fall less kEdgeNoiseK standard deviations of the fall noise (what noise alone
  // reaches) against the sum less what the noise's falls add to it on average (sigma / sqrt(pi) per sample).
  const double sigFall = 1.4142135623730951 * double(noiseRaw);
  const double riseN = rise - double(pk - e0 + 1) * 0.5641895835 * double(noiseRaw);
  const double stepN = double(step) - double(kEdgeNoiseK) * sigFall;
  const bool edge = (rise > 0 && double(step) >= double(kEdgeFrac) * rise) ||
                    (riseN > 0 && stepN >= double(kEdgeFracN) * riseN);

  if (nBeats_ >= kMaxBeats) {
    std::memmove(beatT_, beatT_ + 1, sizeof(uint32_t) * (kMaxBeats - 1));
    edgeMask_ >>= 1;
    slowMask_ >>= 1;
    nBeats_ = kMaxBeats - 1;
  }
  if (edge) edgeMask_ |= 1u << nBeats_;
  else edgeMask_ &= ~(1u << nBeats_);
  if (slow) slowMask_ |= 1u << nBeats_;
  else slowMask_ &= ~(1u << nBeats_);
  beatT_[nBeats_++] = fid;
  lastBeat_ = fid;
  lastTopIdx_ = top;
  haveBeat_ = true;
  r_.beatNow = true;
  updateStats();
}

void PulseDetector::pruneBeats(uint32_t tk) {
  const uint32_t win = c_.windowMs * kTicksPerMs;
  int drop = 0;
  while (drop < nBeats_ && tk - beatT_[drop] > win && tk - beatT_[drop] < 0x80000000u) drop++;
  const uint32_t hwin = kHistMs * kTicksPerMs;
  int hdrop = 0;
  while (hdrop < nHist_ && tk - histU_[hdrop] > hwin && tk - histU_[hdrop] < 0x80000000u) hdrop++;
  if (drop == 0 && hdrop == 0) return;
  if (hdrop > 0) {
    const size_t keep = size_t(nHist_ - hdrop);
    std::memmove(histU_, histU_ + hdrop, sizeof(histU_[0]) * keep);
    std::memmove(histS_, histS_ + hdrop, sizeof(histS_[0]) * keep);
    std::memmove(sigU_, sigU_ + hdrop, sizeof(sigU_[0]) * keep);
    std::memmove(sigS_, sigS_ + hdrop, sizeof(sigS_[0]) * keep);
    std::memmove(histC_, histC_ + hdrop, sizeof(histC_[0]) * keep);
    std::memmove(histCr_, histCr_ + hdrop, sizeof(histCr_[0]) * keep);
    std::memmove(okC_, okC_ + hdrop, sizeof(okC_[0]) * keep);
    std::memmove(steepH_, steepH_ + hdrop, sizeof(steepH_[0]) * keep);
    nHist_ -= hdrop;
  }
  if (drop > 0) {
    std::memmove(beatT_, beatT_ + drop, sizeof(uint32_t) * size_t(nBeats_ - drop));
    edgeMask_ = drop >= 32 ? 0 : edgeMask_ >> drop;
    slowMask_ = drop >= 32 ? 0 : slowMask_ >> drop;
    nBeats_ -= drop;
  }
  updateStats();
}

void PulseDetector::updateStats() {
  r_.beats = nBeats_;
  regular_ = 0;
  // beats after the landing phase (the finger-landing transient is in-band for the first ~2 s)
  int first = 0;
  while (first < nHist_ && int32_t(histU_[first] - regStartTk_) < 0) first++;
  postBeats_ = nHist_ - first;
  {
    const float span = postBeats_ > 0 ? float(histU_[nHist_ - 1] - histU_[first]) / float(kRegSpanMs * kTicksPerMs) : 0;
    const float pb = float(postBeats_) / float(kMinPost);
    regProgress_ = fminf_(fminf_(span, 1.0f), fminf_(pb, 1.0f));
  }
  if (nBeats_ < 2) {
    r_.bpm = 0;
    r_.jitter = 0;
    medMs_ = 0;
    return;
  }
  const int n = nBeats_ - 1;
  float iv[kMaxBeats];
  double sum = 0;
  for (int i = 0; i < n; i++) {
    iv[i] = float(beatT_[i + 1] - beatT_[i]) / float(kTicksPerMs);
    sum += double(iv[i]);
  }
  const double mean = sum / n;
  double var = 0;
  for (int i = 0; i < n; i++) var += (double(iv[i]) - mean) * (double(iv[i]) - mean);
  var /= n;
  // median (insertion sort, n <= 31)
  for (int i = 1; i < n; i++) {
    const float v = iv[i];
    int j = i - 1;
    while (j >= 0 && iv[j] > v) {
      iv[j + 1] = iv[j];
      j--;
    }
    iv[j + 1] = v;
  }
  medMs_ = (n & 1) ? iv[n / 2] : 0.5f * (iv[n / 2 - 1] + iv[n / 2]);
  r_.bpm = medMs_ > 0 ? 60000.0f / medMs_ : 0;
  r_.jitter = (n >= 2 && mean > 0) ? float(std::sqrt(var) / mean) : 0;

  // "Too regular" (spoof) statistics, over the beat history (up to kHistMs, not just windowMs): U over the
  // post-landing beats (the landing transient shifts it), S over all beats (it is immune to it). Judged once kMinPost
  // post-landing beats span kRegSpanMs (kRegSpanFastMs at high rates, where it costs few seconds and early windows
  // would otherwise hold little more than one rate step). A source that is perfectly periodic in segments (square
  // then sine, a rate step, two rhythms alternating) fails whatever the mix: the statistics are robust order
  // statistics of successive differences (a step contaminates only 2-3 of them), and repeated interval values are
  // counted, rather than the overall spread that the mix of two perfect rhythms inflates.
  // The fixed-threshold and repeat tests run on both fiducials. The noise test runs on S (the precise fiducial of a
  // PPG-like upstroke) and also on U when U is predicted to be the more precise one (a smooth, sine-like upstroke),
  // each only while its predicted timing noise is below kNoiseMaxLevel: beyond that the prediction overshoots (the
  // sub-sample offsets saturate) and a real pulse's variability is no longer distinguishable from noise anyway.
  const uint32_t needSpan = (medMs_ > 0 && medMs_ < kFastMs ? kRegSpanFastMs : kRegSpanMs) * kTicksPerMs;
  if (postBeats_ >= kMinPost && histU_[nHist_ - 1] - histU_[first] >= needSpan) {
    const SpoofScore su = spoof_score(histU_ + first, sigU_ + first, postBeats_, live_);
    const SpoofScore ss = restarted_ ? spoof_score(histS_ + first, sigS_ + first, postBeats_, live_)
                                      : spoof_score(histS_, sigS_, nHist_, live_);
    float noise = 1e9f;
    if (ss.level < kNoiseMaxLevel) noise = ss.noise;
    if (su.level < ss.level && su.level < kNoiseMaxLevel) noise = fminf_(noise, su.noise);
    regular_ = fminf_(fminf_(su.fixed, ss.fixed), noise);
    const float cc = cross_score(histC_ + first, histCr_ + first, okC_ + first, steepH_ + first, postBeats_, live_);
    regular_ = fminf_(regular_, cc);
  }
}

void PulseDetector::accumulate(uint32_t el, uint32_t ir, uint32_t red, float yi, float yr) {
  const uint32_t id = el / bucketMs_;
  Bucket& b = bk_[id % kBuckets];
  if (b.n == 0 || b.id != id) {
    std::memset(&b, 0, sizeof(b));
    b.id = id;
    b.irMin = b.redMin = 0xFFFFFFFFu;
  }
  b.n++;
  if (ir >= kAdcMax || red >= kAdcMax) b.sat++;
  if (ir < b.irMin) b.irMin = ir;
  if (ir > b.irMax) b.irMax = ir;
  if (red < b.redMin) b.redMin = red;
  if (red > b.redMax) b.redMax = red;
  b.sx += yi;
  b.sy += yr;
  b.sxx += yi * yi;
  b.syy += yr * yr;
  b.sxy += yi * yr;
}

// Window-level spoof / quality checks over the last kBuckets sub-windows (post-landing samples only).
bool PulseDetector::windowOk(uint32_t el) const {
  const uint32_t cur = el / bucketMs_;
  double n = 0, sx = 0, sy = 0, sxx = 0, syy = 0, sxy = 0;
  uint32_t irMin = 0xFFFFFFFFu, irMax = 0, redMin = 0xFFFFFFFFu, redMax = 0, sat = 0;
  for (int i = 0; i < kBuckets; i++) {
    const Bucket& b = bk_[i];
    if (b.n == 0 || b.id > cur || cur - b.id >= uint32_t(kBuckets)) continue;
    n += b.n;
    sat += b.sat;
    sx += double(b.sx);
    sy += double(b.sy);
    sxx += double(b.sxx);
    syy += double(b.syy);
    sxy += double(b.sxy);
    if (b.irMin < irMin) irMin = b.irMin;
    if (b.irMax > irMax) irMax = b.irMax;
    if (b.redMin < redMin) redMin = b.redMin;
    if (b.redMax > redMax) redMax = b.redMax;
  }
  if (n < kMinCorrSamples) return false;
  if (sat > 0) return false;                                                     // ADC clipped: shape unusable
  if (irMax - irMin <= kFlatSpan || redMax - redMin <= kFlatSpan) return false;  // a channel is constant
  // edge-like (square wave, motion artifacts) or slow symmetric (sine, triangle) upstrokes in over 1/4 of the beats
  if (c_.strict) {
    int odd = 0;
    for (int i = 0; i < nBeats_; i++) odd += int(((edgeMask_ | slowMask_) >> i) & 1u);
    if (odd * 4 > nBeats_) return false;
  }
  const double vx = n * sxx - sx * sx, vy = n * syy - sy * sy;
  if (!(vx > 0) || !(vy > 0)) return false;
  const double corr = (n * sxy - sx * sy) / std::sqrt(vx * vy);
  return corr > double(kCorrMin);
}

void PulseDetector::evidence(uint8_t out12[12]) const {
  std::memset(out12, 0, 12);
  if (!r_.passed) return;  // no evidence for an unverified pulse
  out12[0] = 1;
  out12[1] = clamp8(r_.bpm);
  out12[2] = uint8_t(r_.beats > 255 ? 255 : (r_.beats < 0 ? 0 : r_.beats));
  put_be(out12 + 3, r_.irDC > 0xFFFFFFu ? 0xFFFFFFu : r_.irDC, 3);
  put_be(out12 + 6, r_.redDC > 0xFFFFFFu ? 0xFFFFFFu : r_.redDC, 3);
  out12[9] = clamp8(r_.jitter * 1000.0f);
  const uint32_t d = r_.elapsedMs / 10;
  put_be(out12 + 10, d > 0xFFFFu ? 0xFFFFu : d, 2);
}

}  // namespace ripar
