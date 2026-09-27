// Synthetic PPG stream (ppg_synth.h). Waveform constants from test/host/test_pulse.cpp (Sim / Gen / shape()).
#include "ppg_synth.h"

#include <cmath>

namespace ripar {
namespace emu {

namespace {

const double kPi = 3.14159265358979323846;
const double kDcIr = 120000, kDcRed = 90000;  // Sim::dcIr / dcRed
const double kRsa = 0.03, kRespHz = 0.25, kAmpMod = 0.10;
const double kWander = 0.002, kWanderHz = 0.12;

// test_pulse.cpp shape(): one PPG beat, tau = seconds since beat onset; peak ~1.1 at 0.14 s
double shape(double tau) {
  if (tau < 0 || tau > 1.8) return 0;
  const double a = (tau - 0.14) / 0.055, b = (tau - 0.36) / 0.07;
  const double sys = std::exp(-a * a);
  const double dic = 0.30 * std::exp(-b * b);
  const double tail = 0.25 / (1.0 + std::exp(-(tau - 0.14) / 0.02)) * std::exp(-tau / 0.45);
  return sys + dic + tail;
}

uint32_t clamp_adc(double v) {
  if (v < 0) return 0;
  if (v > 262143) return 262143;
  return uint32_t(v + 0.5);
}

}  // namespace

uint64_t PpgSynth::Rng::next() {  // splitmix64 (test_pulse.cpp Rng)
  uint64_t z = (s += 0x9E3779B97F4A7C15ull);
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}
double PpgSynth::Rng::uni() { return double(next() >> 11) * (1.0 / 9007199254740992.0); }
double PpgSynth::Rng::gauss() {
  double u1 = uni();
  if (u1 < 1e-300) u1 = 1e-300;
  const double u2 = uni();
  return std::sqrt(-2.0 * std::log(u1)) * std::cos(2.0 * kPi * u2);
}

void PpgSynth::seed(uint64_t s) {
  rng_.s = s * 0x9E3779B97F4A7C15ull + 12345;
  ph1_ = 2 * kPi * rng_.uni();
  ph2_ = 2 * kPi * rng_.uni();
}

double PpgSynth::unwrap(uint32_t tMs) {  // emulated millis() wraps like the device's; the model needs a line
  if (!haveT_) {
    haveT_ = true;
    lastT_ = tMs;
    lastX_ = double(tMs) / 1000.0;
    return lastX_;
  }
  const int32_t d = int32_t(tMs - lastT_);
  lastT_ = tMs;
  lastX_ += double(d) / 1000.0;
  return lastX_;
}

void PpgSynth::set(const PpgParams& p, uint32_t nowMs) {
  const bool landed = p.on && !p_.on;
  p_ = p;
  if (!(p_.bpm > 1)) p_.bpm = 1;
  if (p_.bpm > 400) p_.bpm = 400;
  if (!(p_.amplitude >= 0)) p_.amplitude = 0;
  if (p_.amplitude > 0.2) p_.amplitude = 0.2;
  if (!(p_.noise >= 0)) p_.noise = 0;
  if (p_.noise > 5000) p_.noise = 5000;
  if (!(p_.hrv >= 0)) p_.hrv = 0;
  if (p_.hrv > 0.5) p_.hrv = 0.5;
  const double x = unwrap(nowMs);
  if (landed) {
    placedAt_ = x;
    restart_train(x);
  }
}

// test_pulse.cpp Gen::train(), started 3 s before the finger landed so beats are already under way
void PpgSynth::restart_train(double x) {
  bt_.clear();
  ba_.clear();
  nextBeat_ = x - 3.0 + rng_.uni() * (60.0 / p_.bpm);
  extend(x);
}

void PpgSynth::extend(double x) {
  while (nextBeat_ < x + 0.5) {
    bt_.push_back(nextBeat_);
    ba_.push_back(1.0 + kAmpMod * std::sin(2 * kPi * kRespHz * nextBeat_) + 0.04 * rng_.gauss());
    const double rr0 = 60.0 / p_.bpm;
    double rr = rr0 * (1.0 + p_.hrv * rng_.gauss() + kRsa * std::sin(2 * kPi * kRespHz * nextBeat_ + 1.0));
    if (rr < 0.3 * rr0) rr = 0.3 * rr0;
    nextBeat_ += rr;
  }
  size_t drop = 0;  // beats that no longer contribute (shape() is 0 after 1.8 s)
  while (drop < bt_.size() && bt_[drop] < x - 2.0) drop++;
  if (drop) {
    bt_.erase(bt_.begin(), bt_.begin() + long(drop));
    ba_.erase(ba_.begin(), ba_.begin() + long(drop));
  }
}

// test_pulse.cpp Gen::sample()
void PpgSynth::sample(uint32_t tMs, uint32_t& ir, uint32_t& red) {
  const double x = unwrap(tMs);
  if (!p_.on) {
    ir = clamp_adc(1500 + 20 * rng_.gauss());
    red = clamp_adc(1200 + 20 * rng_.gauss());
    return;
  }
  extend(x);
  double base = 1.0 + kWander * (std::sin(2 * kPi * kWanderHz * x + ph1_) + 0.6 * std::sin(2 * kPi * 0.31 * x + ph2_));
  const double tl = x - placedAt_;
  base *= 1.0 + 0.04 * std::exp(-tl / 0.5);  // pressure-settling transient
  const double f = p_.bpm / 60.0;
  double pi = 0;
  switch (p_.shape) {
    case PpgParams::Ppg:
      for (size_t i = 0; i < bt_.size(); i++) {
        if (bt_[i] > x) break;
        if (x - bt_[i] < 1.8) pi += ba_[i] * shape(x - bt_[i]);
      }
      break;
    case PpgParams::Sine:
      pi = 0.5 * (1 + std::sin(2 * kPi * f * x));
      break;
    case PpgParams::Square:
      pi = std::sin(2 * kPi * f * x) >= 0 ? 1.0 : 0.0;
      break;
    default:
      break;
  }
  const double piIr = p_.amplitude, piRed = 0.8 * p_.amplitude;
  double vi = kDcIr * base * (1 - piIr * pi) + p_.noise * rng_.gauss();
  double vr = kDcRed * base * (1 - piRed * pi) + 1.5 * p_.noise * rng_.gauss();
  if (tl < 0.03) {  // 30 ms ramp from ambient
    const double k = tl < 0 ? 0 : tl / 0.03;
    vi = 1500 + (vi - 1500) * k;
    vr = 1200 + (vr - 1200) * k;
  }
  ir = clamp_adc(vi);
  red = clamp_adc(vr);
}

}  // namespace emu
}  // namespace ripar
