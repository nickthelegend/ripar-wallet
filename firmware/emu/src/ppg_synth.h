// Synthetic MAX30102 IR / red samples (100 Hz) for the emulated pulse sensor. The waveform model is the one the
// firmware's pulse tests use (test/host/test_pulse.cpp Gen): a PPG beat train (systolic wave, dicrotic wave,
// diastolic tail) with heart-rate variability, respiratory sinus arrhythmia and amplitude modulation, baseline
// wander, white sensor noise and a finger-landing transient, here generated as a stream in emulated time. The real
// PulseDetector (src/pulse_algo.cpp) judges it exactly as it judges the sensor on the device; nothing in the pulse
// gate is bypassed. JS controls finger on/off, bpm, amplitude (perfusion index) and noise; `shape` also offers the
// spoofs the detector must reject (sine, square, flat).
#pragma once
#include <cstdint>
#include <vector>

namespace ripar {
namespace emu {

struct PpgParams {
  enum Shape : uint8_t { Ppg, Sine, Square, Flat };
  bool on = false;          // finger on the sensor
  double bpm = 72;          // heart rate
  double amplitude = 0.01;  // pulse amplitude as a fraction of the IR DC level (perfusion index); red = 0.8x
  double noise = 8;         // white sensor noise, counts (std) on IR; red = 1.5x
  double hrv = 0.03;        // random beat-to-beat variation (std, fraction of the RR interval)
  Shape shape = Ppg;
};

class PpgSynth {
 public:
  void seed(uint64_t s);
  // New parameters at emulated time nowMs; a finger that was off and is now on "lands" at nowMs.
  void set(const PpgParams& p, uint32_t nowMs);
  const PpgParams& params() const { return p_; }
  // One sensor sample taken at emulated time tMs (18-bit ADC counts).
  void sample(uint32_t tMs, uint32_t& ir, uint32_t& red);

 private:
  struct Rng {
    uint64_t s = 1;
    uint64_t next();
    double uni();
    double gauss();
  };
  Rng rng_;
  PpgParams p_;
  double placedAt_ = 0;  // s
  double lastX_ = 0;     // time of the previous sample, s (unwrapped)
  uint32_t lastT_ = 0;
  bool haveT_ = false;
  std::vector<double> bt_, ba_;  // beat onsets (s) and amplitudes, covering [x - 2 s, x + 0.5 s]
  double nextBeat_ = 0;
  double ph1_ = 0, ph2_ = 0;
  void restart_train(double x);
  void extend(double x);
  double unwrap(uint32_t tMs);
};

}  // namespace emu
}  // namespace ripar
