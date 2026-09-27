// C API of the emulator (exported to JavaScript by build.sh). JSON strings in and out; input JSON is parsed with the
// firmware's strict parser (json_strict.h). Every returned `const char*` stays valid until the next API call.
//
//   int         emu_new(opts)            -> handle (> 0), or 0 (emu_last_error() says why)
//   void        emu_delete(h)
//   const char* emu_last_error()
//   const char* emu_state(h)             -> state JSON (emu_state.cpp)
//   int         emu_key(h, down)         BOOT key level (1 = pressed) at the current emulated time
//   int         emu_tick(h, ms)          advance emulated time; returns the new millis()
//   const char* emu_scan(h, text)        one QR (a UR, single part or one multipart part) -> scan status JSON
//   const char* emu_finger(h, json)      {on, bpm, amplitude, noise, hrv, shape} -> the finger now in use
//   const char* emu_control(h, json)     {addEntropy: hex, injectTrng: hex (test mode), nvsFail: bool, battery: n,
//                                         pulseFault: "none" | "stall" | "unplug", appStallMs: n}
//   const char* emu_context(h)           -> context JSON (RAM context + the stored NVS blob)
//   const char* emu_nvs(h)               -> {seed, context}: the emulated NVS, for the companion to persist
//
// opts: {entropy: hex (>= 32 bytes, required unless test), seed?: hex32, context?: hex, test?: true | {seed?: hex32,
//        trngSeed?: hex, ppgSeed?: n, selftestFault?: bool}, clockMs?: n, battery?: n,
//        hardware?: {camera?: bool, pulseSensor?: bool}}
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <string>

#include "emu_core.h"
#include "json_out.h"
#include "json_strict.h"

#ifdef __EMSCRIPTEN__
#include <emscripten/emscripten.h>
#else
#define EMSCRIPTEN_KEEPALIVE
#endif

using ripar::Bytes;
using ripar::JsonVal;
using namespace ripar::emu;

namespace {

std::map<int, std::unique_ptr<Device>> g_devices;
int g_next = 1;
std::string g_out, g_err;

const char* out(const std::string& s) {
  g_out = s;
  return g_out.c_str();
}

const char* error_json(const std::string& why) {
  JsonOut j;
  j.obj().kv("error", why).end_obj();
  return out(j.text());
}

Device* dev(int h) {
  auto it = g_devices.find(h);
  return it == g_devices.end() ? nullptr : it->second.get();
}

bool parse(const char* text, JsonVal& v, std::string& err) {
  if (!text) text = "{}";
  if (!ripar::json_parse_strict(reinterpret_cast<const uint8_t*>(text), std::strlen(text), v, &err)) return false;
  if (v.type != JsonVal::Object) {
    err = "expected a JSON object";
    return false;
  }
  return true;
}

bool hex_field(const JsonVal& o, const char* k, Bytes& b, std::string& err, bool& present) {
  present = false;
  const JsonVal* v = o.get(k);
  if (!v || v->type == JsonVal::Null) return true;
  if (v->type != JsonVal::String || !ripar::from_hex(v->str, b)) {
    err = std::string(k) + ": expected a hex string";
    return false;
  }
  present = true;
  return true;
}

bool num_field(const JsonVal& o, const char* k, double& d) {
  const JsonVal* v = o.get(k);
  if (!v || v->type != JsonVal::Number) return false;
  d = std::strtod(v->str.c_str(), nullptr);
  return true;
}

bool bool_field(const JsonVal& o, const char* k, bool& b) {
  const JsonVal* v = o.get(k);
  if (!v || v->type != JsonVal::Bool) return false;
  b = v->boolean;
  return true;
}

}  // namespace

extern "C" {

EMSCRIPTEN_KEEPALIVE const char* emu_last_error() { return g_err.c_str(); }

EMSCRIPTEN_KEEPALIVE int emu_new(const char* optsJson) {
  g_err.clear();
  JsonVal o;
  std::string err;
  if (!parse(optsJson, o, err)) {
    g_err = "options: " + err;
    return 0;
  }
  Options opt;
  bool present = false;
  if (!hex_field(o, "entropy", opt.entropy, err, present)) {
    g_err = err;
    return 0;
  }
  Bytes seed;
  if (!hex_field(o, "seed", seed, err, present)) {
    g_err = err;
    return 0;
  }
  if (present) {
    if (seed.size() != 32) {
      g_err = "seed: expected 32 bytes";
      return 0;
    }
    opt.haveSeed = true;
    std::memcpy(opt.seed, seed.data(), 32);
  }
  if (!hex_field(o, "context", opt.context, err, opt.haveContext)) {
    g_err = err;
    return 0;
  }
  const JsonVal* t = o.get("test");
  if (t && t->type == JsonVal::Bool) {
    opt.test = t->boolean;
  } else if (t && t->type == JsonVal::Object) {
    opt.test = true;
    Bytes ts;
    if (!hex_field(*t, "seed", ts, err, present)) {
      g_err = "test." + err;
      return 0;
    }
    if (present) {
      if (ts.size() != 32 || opt.haveSeed) {
        g_err = "test.seed: 32 bytes, and not together with seed";
        return 0;
      }
      opt.haveSeed = true;
      std::memcpy(opt.seed, ts.data(), 32);
    }
    if (!hex_field(*t, "trngSeed", opt.trngSeed, err, present)) {
      g_err = "test." + err;
      return 0;
    }
    double d = 0;
    if (num_field(*t, "ppgSeed", d)) opt.ppgSeed = uint64_t(d);
    bool b = false;
    if (bool_field(*t, "selftestFault", b)) opt.selftestFault = b;
  } else if (t && t->type != JsonVal::Null) {
    g_err = "test: expected an object or a boolean";
    return 0;
  }
  if (!opt.test && opt.entropy.size() < 32) {
    g_err = "entropy: at least 32 bytes from crypto.getRandomValues() are required";
    return 0;
  }
  double d = 0;
  if (num_field(o, "clockMs", d)) opt.clockMs = uint32_t(d);
  if (num_field(o, "battery", d)) opt.battery = int(d);
  const JsonVal* hw = o.get("hardware");
  if (hw && hw->type == JsonVal::Object) {
    bool b = true;
    if (bool_field(*hw, "camera", b)) opt.camera = b;
    if (bool_field(*hw, "pulseSensor", b)) opt.pulseSensor = b;
  }
  const int h = g_next++;
  g_devices[h].reset(new Device(opt));
  return h;
}

EMSCRIPTEN_KEEPALIVE void emu_delete(int h) { g_devices.erase(h); }

EMSCRIPTEN_KEEPALIVE const char* emu_state(int h) {
  Device* d = dev(h);
  return d ? out(d->state_json()) : error_json("no such emulator");
}

EMSCRIPTEN_KEEPALIVE int emu_key(int h, int down) {
  Device* d = dev(h);
  if (!d) return -1;
  d->key(down != 0);
  return 0;
}

EMSCRIPTEN_KEEPALIVE int emu_tick(int h, int ms) {
  Device* d = dev(h);
  if (!d) return -1;
  if (ms > 0) d->tick(uint32_t(ms));
  return int(d->now() & 0x7FFFFFFF);
}

EMSCRIPTEN_KEEPALIVE const char* emu_scan(int h, const char* text) {
  Device* d = dev(h);
  if (!d) return error_json("no such emulator");
  const ScanStatus s = d->scan(text ? std::string(text) : std::string());
  JsonOut j;
  j.obj().kv("result", s.result).kv("progress", s.progress).kv("received", s.received).kv("seqLen", s.seqLen);
  j.kv("hint", s.hint).kv("screen", s.screen).end_obj();
  return out(j.text());
}

EMSCRIPTEN_KEEPALIVE const char* emu_finger(int h, const char* json) {
  Device* d = dev(h);
  if (!d) return error_json("no such emulator");
  JsonVal o;
  std::string err;
  if (!parse(json, o, err)) return error_json("finger: " + err);
  PpgParams p = d->finger_params();
  bool b = false;
  double v = 0;
  if (bool_field(o, "on", b)) p.on = b;
  if (num_field(o, "bpm", v)) p.bpm = v;
  if (num_field(o, "amplitude", v)) p.amplitude = v;
  if (num_field(o, "noise", v)) p.noise = v;
  if (num_field(o, "hrv", v)) p.hrv = v;
  const JsonVal* sh = o.get("shape");
  if (sh && sh->type == JsonVal::String) {
    if (sh->str == "ppg")
      p.shape = PpgParams::Ppg;
    else if (sh->str == "sine")
      p.shape = PpgParams::Sine;
    else if (sh->str == "square")
      p.shape = PpgParams::Square;
    else if (sh->str == "flat")
      p.shape = PpgParams::Flat;
    else
      return error_json("finger: shape must be ppg | sine | square | flat");
  }
  d->finger(p);
  const PpgParams& q = d->finger_params();
  static const char* const kShapes[] = {"ppg", "sine", "square", "flat"};
  JsonOut j;
  j.obj().kv("on", q.on).kv("bpm", q.bpm).kv("amplitude", q.amplitude).kv("noise", q.noise).kv("hrv", q.hrv);
  j.kv("shape", kShapes[int(q.shape) & 3]).end_obj();
  return out(j.text());
}

EMSCRIPTEN_KEEPALIVE const char* emu_control(int h, const char* json) {
  Device* d = dev(h);
  if (!d) return error_json("no such emulator");
  JsonVal o;
  std::string err;
  if (!parse(json, o, err)) return error_json("control: " + err);
  Bytes b;
  bool present = false;
  if (!hex_field(o, "addEntropy", b, err, present)) return error_json(err);
  if (present) d->add_entropy(b);
  if (!hex_field(o, "injectTrng", b, err, present)) return error_json(err);
  if (present) {
    if (!d->test_mode()) return error_json("injectTrng: test mode only");
    d->inject_trng(b);
  }
  bool f = false;
  if (bool_field(o, "nvsFail", f)) d->set_nvs_fail(f);
  double v = 0;
  if (num_field(o, "battery", v)) d->set_battery(int(v));
  const JsonVal* pf = o.get("pulseFault");
  if (pf && pf->type != JsonVal::Null) {
    if (pf->type != JsonVal::String) return error_json("pulseFault: none | stall | unplug");
    if (pf->str == "none")
      d->set_pulse_fault(EmuPulse::Fault::None);
    else if (pf->str == "stall")
      d->set_pulse_fault(EmuPulse::Fault::Stall);
    else if (pf->str == "unplug")
      d->set_pulse_fault(EmuPulse::Fault::Unplug);
    else
      return error_json("pulseFault: none | stall | unplug");
  }
  if (num_field(o, "appStallMs", v)) {
    if (!(v >= 0 && v <= 600000)) return error_json("appStallMs: 0 .. 600000");
    d->stall_app(uint32_t(v));
  }
  return out("{}");
}

EMSCRIPTEN_KEEPALIVE const char* emu_context(int h) {
  Device* d = dev(h);
  return d ? out(d->context_json()) : error_json("no such emulator");
}

EMSCRIPTEN_KEEPALIVE const char* emu_nvs(int h) {
  Device* d = dev(h);
  return d ? out(d->nvs_json()) : error_json("no such emulator");
}

}  // extern "C"
