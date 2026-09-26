// Live-pulse detection from MAX30102 IR/red samples (pure logic, host-testable).
#pragma once
#include <cstdint>

namespace ripar {

struct PulseResult {
  bool finger = false;     // IR DC above threshold
  bool passed = false;     // >= minBeats in window, bpm in range, finger still present
  int beats = 0;           // beats counted in the current window
  float bpm = 0;           // from median beat interval
  float jitter = 0;        // std(interval)/mean(interval)
  uint32_t irDC = 0, redDC = 0;
  float progress = 0;      // 0..1 toward passing (for the UI)
  bool beatNow = false;    // true on the sample where a beat was detected (UI heartbeat blink)
  uint32_t elapsedMs = 0;  // since finger placed
};

struct PulseConfig {
  uint32_t fingerIrMin = 50000;
  int minBeats = 5;
  uint32_t windowMs = 8000;
  float bpmMin = 40, bpmMax = 180;
};

class PulseDetector {
 public:
  explicit PulseDetector(const PulseConfig& c = PulseConfig());
  void reset();
  // feed one sample (100 Hz nominal); t_ms monotonically increasing
  const PulseResult& add(uint32_t ir, uint32_t red, uint32_t t_ms);
  const PulseResult& result() const { return r_; }
  // 12-byte evidence (docs/PROTOCOL.md §5); valid once passed
  void evidence(uint8_t out12[12]) const;

 private:
  PulseConfig c_;
  PulseResult r_;
  // DC tracking + band-pass + peak detection state (implementation-defined)
  // dcIr_/dcRed_: slow DC EMA; lp_: decaying envelope of the slope-sum signal; thr_: detection threshold;
  // prev2_: slope-sum value at the pending candidate. Beat times (beatT_, lastBeat_) are in 0.1 ms ticks
  // (t_ms * 10, wrapping, only ever compared by unsigned difference).
  float dcIr_ = 0, dcRed_ = 0, lp_ = 0, prev_ = 0, prev2_ = 0, thr_ = 0;
  uint32_t fingerSince_ = 0, lastBeat_ = 0, lastT_ = 0;
  uint32_t beatT_[32];
  int nBeats_ = 0;
  double sumIr_ = 0, sumRed_ = 0;
  uint32_t nSamples_ = 0;
  bool haveFinger_ = false;

  enum { kRing = 128, kBuckets = 16 };
  struct Bucket {  // per-sub-window stats for the red/IR correlation + flat/saturation checks
    uint32_t id, n, sat;
    uint32_t irMin, irMax, redMin, redMax;
    float sx, sy, sxx, syy, sxy;
  };
  bool haveT_ = false, haveFast_ = false, inPk_ = false, armed_ = true, haveBeat_ = false;
  float fastIr_ = 0, fastRed_ = 0;  // fast EMA of raw IR/red (finger detection)
  float zIr_[4], zRed_[4];          // biquad states: high-pass [0..1], low-pass [2..3]
  float ringY_[kRing];              // band-passed IR history
  uint32_t ringT_[kRing];           // sample timestamps (ticks)
  uint32_t ringRaw_[kRing];         // raw IR history (edge test)
  uint32_t pkIdx_ = 0, topIdx_ = 0, lastTopIdx_ = 0, bucketMs_ = 500;
  float medMs_ = 0;                 // median beat interval in the window (ms)
  float regular_ = 0;               // "too regular" statistic over the post-landing beats (see updateStats)
  int postBeats_ = 0;               // beats in the window that landed after the landing phase
  uint32_t edgeMask_ = 0;           // bit i set: beat beatT_[i] had an edge-like (single-sample) upstroke
  Bucket bk_[kBuckets];

  void clearSession();
  void beginSession(uint32_t ir, uint32_t red, uint32_t t_ms);
  void detect(uint32_t idx, uint32_t tk, float s);
  void commitBeat(uint32_t pk, uint32_t top, uint32_t idx);
  void pruneBeats(uint32_t tk);
  void updateStats();
  void accumulate(uint32_t el, uint32_t ir, uint32_t red, float yi, float yr);
  bool windowOk(uint32_t el) const;
};

}  // namespace ripar
