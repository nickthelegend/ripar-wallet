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
//      insensitive to a sloping baseline.
//   5. Beats older than windowMs drop out. bpm = 60000 / median interval, jitter = std / mean of intervals.
//   6. passed = beats >= minBeats && bpm in [bpmMin, bpmMax] && jitter <= 0.35 && last beat recent
//            && regularity >= 0.005 (spoof: a signal generator is too regular; computed only over beats after
//               the first 2 s of contact, whose landing transient distorts beat times - see updateStats)
//            && no channel flat/constant && no ADC saturation
//            && fewer than 1/4 of the beats edge-like (square wave: the whole rise in one sample)
//            && Pearson(band-passed red, band-passed IR) > 0.5 over the post-landing part of the window.
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
constexpr float kJitterMin = 0.005f;   // below: too regular to be a heart (signal generator)
constexpr float kJitterMax = 0.35f;    // above: not a rhythm (noise, motion, missed/extra beats)
constexpr float kCorrMin = 0.5f;       // red and IR pulses must move together
constexpr float kEdgeFrac = 0.6f;      // one sample carrying >= this share of an upstroke's rise => edge-like beat
constexpr uint32_t kEdgeWin = 18;      // samples before the slope-sum maximum examined by the edge test
constexpr uint32_t kRegStartMs = 2000; // spoof statistics (regularity, correlation) ignore the landing phase
constexpr int kMinPost = 4;            // post-landing beats (3 intervals) needed for the regularity statistic
constexpr uint32_t kFlatSpan = 4;      // raw span (counts) at or below which a channel counts as constant
constexpr uint32_t kAdcMax = 0x3FFFF;  // MAX30102 18-bit full scale (saturation)
constexpr uint32_t kMinCorrSamples = 100;
constexpr uint32_t kTicksPerMs = 10;   // internal beat-time resolution: 0.1 ms
constexpr int kMaxBeats = 32;          // == size of beatT_

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
};

const Consts& K() {
  static const Consts k = {make_bq(true, kHpHz), make_bq(false, kLpHz),
                           float(1.0 - std::exp(-1.0 / (double(kFs) * double(kDcTauS)))),
                           float(1.0 - std::exp(-1.0 / (double(kFs) * double(kFastTauS)))),
                           float(std::exp(-1.0 / (double(kFs) * double(kEnvTauS))))};
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
  std::memset(ringT_, 0, sizeof(ringT_));
  std::memset(ringRaw_, 0, sizeof(ringRaw_));
  pkIdx_ = topIdx_ = lastTopIdx_ = 0;
  medMs_ = 0;
  regular_ = 0;
  postBeats_ = 0;
  edgeMask_ = 0;
  std::memset(bk_, 0, sizeof(bk_));
  bucketMs_ = c_.windowMs / kBuckets;
  if (bucketMs_ == 0) bucketMs_ = 1;
}

void PulseDetector::beginSession(uint32_t ir, uint32_t red, uint32_t t_ms) {
  clearSession();
  haveFinger_ = true;
  fingerSince_ = t_ms;
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
  ringT_[idx % kRing] = tk;
  ringRaw_[idx % kRing] = ir;

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
            regular_ >= kJitterMin && r_.jitter <= kJitterMax;
  if (ok) {
    // the pulse must still be there: last beat no older than 2.5 median intervals (and never > 2 slowest beats)
    float limitMs = 2.5f * medMs_;
    if (c_.bpmMin > 0) limitMs = fminf_(limitMs, 2.0f * 60000.0f / c_.bpmMin);
    const float ageMs = float(tk - lastBeat_) / float(kTicksPerMs);
    ok = ageMs <= limitMs;
  }
  if (ok) ok = windowOk(el);
  r_.passed = ok;

  // progress: both "minBeats in the window" and "kMinPost post-landing beats" must be reached
  if (ok) {
    r_.progress = 1.0f;
  } else if (!settled || c_.minBeats <= 0) {
    r_.progress = 0.0f;
  } else {
    const float p1 = float(nBeats_ < c_.minBeats ? nBeats_ : c_.minBeats) / float(c_.minBeats);
    const float p2 = float(postBeats_ < kMinPost ? postBeats_ : kMinPost) / float(kMinPost);
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
  const bool edge = rise > 0 && double(step) >= double(kEdgeFrac) * rise;

  if (nBeats_ >= kMaxBeats) {
    std::memmove(beatT_, beatT_ + 1, sizeof(uint32_t) * (kMaxBeats - 1));
    edgeMask_ >>= 1;
    nBeats_ = kMaxBeats - 1;
  }
  if (edge) edgeMask_ |= 1u << nBeats_;
  else edgeMask_ &= ~(1u << nBeats_);
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
  if (drop == 0) return;
  std::memmove(beatT_, beatT_ + drop, sizeof(uint32_t) * size_t(nBeats_ - drop));
  edgeMask_ = drop >= 32 ? 0 : edgeMask_ >> drop;
  nBeats_ -= drop;
  updateStats();
}

void PulseDetector::updateStats() {
  r_.beats = nBeats_;
  regular_ = 0;
  // beats after the landing phase (the finger-landing transient is in-band for the first ~2 s)
  const uint32_t regStart = (fingerSince_ + kRegStartMs) * kTicksPerMs;
  int first = 0;
  while (first < nBeats_ && int32_t(beatT_[first] - regStart) < 0) first++;
  postBeats_ = nBeats_ - first;
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

  // "Too regular" statistic (spoof check). The landing transient shifts the early beat times of even a perfectly
  // periodic source, so only post-landing beats are used. Of those, the smaller of std/mean and the
  // successive-difference estimate sqrt(mean(dI^2)/2)/mean is taken, so a smooth drift of the beat times does not
  // count as heart-rate variability. Needs kMinPost - 1 such intervals, else 0 (= not passed yet).
  const int m = nBeats_ - 1 - first;  // intervals among post-landing beats
  if (m >= kMinPost - 1) {
    double s1 = 0, s2 = 0, sd = 0;
    for (int i = first; i < nBeats_ - 1; i++) {
      const double v = double(beatT_[i + 1] - beatT_[i]);
      s1 += v;
      s2 += v * v;
      if (i + 2 < nBeats_) {
        const double dd = double(beatT_[i + 2] - beatT_[i + 1]) - v;
        sd += dd * dd;
      }
    }
    const double mu = s1 / m;
    double v2 = s2 / m - mu * mu;
    if (v2 < 0) v2 = 0;
    const double a = std::sqrt(v2) / mu, b = std::sqrt(sd / (2.0 * (m - 1))) / mu;
    regular_ = float(a < b ? a : b);
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
  // edge-like upstrokes (square-wave spoof, motion artifacts) in more than a quarter of the beats
  int edges = 0;
  for (int i = 0; i < nBeats_; i++) edges += int((edgeMask_ >> i) & 1u);
  if (edges * 4 > nBeats_) return false;
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
