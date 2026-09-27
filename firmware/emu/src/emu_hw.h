// The emulated hardware under the flows.cpp driver: one class per device-only module, each mirroring the behaviour
// that module has on the ESP32-S3 (the files named below) in emulated time. Nothing here decides anything a
// portable module (fsm, policy, respond, pulse_algo, ...) decides on the device.
//
//   EmuIo     io.cpp      BOOT key: 5 ms timer, 30 ms debounce, Short < 1 s / Long2s at 2 s / Hold5s at 5 s, the
//                         8-event queue with the 1 s event age limit, io_flush(swallowHeld); buzzer (counted);
//                         battery (a fixed, settable percentage)
//   EmuPulse  pulse.cpp   MAX30102 at 100 Hz into a 32-sample FIFO (rollover, OVF counter, the full-FIFO read quirk),
//                         drained by pulse_update() into the real PulseDetector with the +10 ms sample clock and the
//                         post-stall re-sync; samples from PpgSynth. Fault injection: I2C bus stall, hot unplug
//   EmuCam    qrscan.cpp  the camera + quirc handoff: one payload slot, an identical payload re-delivered at most
//                         once per 1000 ms (deliver() / kRepeatMs), the latest text submitted while the camera runs
//   EmuStore  store.cpp   NVS "ctx": the context_serialize() blob, written then read back and compared; the JS side
//                         persists the blob (a settable fault makes every write fail, to show Save semantics)
//   EmuTrng   keys.cpp    trng_fill(): HMAC-DRBG (SHA-256) seeded from the JS entropy pool; test mode: seeded from
//                         a fixed / given value, and injected bytes are returned first
//   EmuKeys   keys.cpp    seed, K1 / P1 derivation (crypto.cpp), sign + verify (+ recover) + wipe, the self-test
#pragma once
#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>

#include "context.h"
#include "fsm.h"
#include "ppg_synth.h"
#include "pulse_algo.h"
#include "util.h"

namespace ripar {
namespace emu {

// ------------------------------------------------------------------------------------------------ io.cpp
class EmuIo {
 public:
  void init(uint32_t now);                       // io_init(): a press already down at start is ignored until release
  void set_raw(bool down) { raw_ = down; }       // the physical key (JS keyDown / keyUp)
  bool raw() const { return raw_; }
  void timer_tick(uint32_t now);                 // key_tick(), every 5 ms
  Key poll_key_state(uint32_t now, bool& down);  // io_poll_key_state()
  void flush(bool swallowHeld);                  // io_flush()
  bool key_down() const { return stable_; }      // io_key_down()

  // buzzer: the device plays tones; the emulator counts them (the companion may play them)
  struct Buzz {
    uint32_t ok = 0, err = 0, beat = 0;
    const char* last = "";
    uint32_t lastAt = 0;
  };
  void buzz_ok(uint32_t now) { note(buzz_.ok, "ok", now); }
  void buzz_err(uint32_t now) { note(buzz_.err, "err", now); }
  void buzz_beat(uint32_t now) { note(buzz_.beat, "beat", now); }
  const Buzz& buzz() const { return buzz_; }

  int battery = 87;  // battery_percent() (-1 = unknown)

 private:
  static const int kQueueLen = 8;
  struct Ev {
    Key key;
    uint32_t t;
  };
  bool raw_ = false, rawLast_ = false, stable_ = false, armed_ = false, sentLong_ = false, sentHold_ = false;
  uint32_t rawSince_ = 0, downSince_ = 0;
  Ev q_[kQueueLen];
  int qHead_ = 0, qCount_ = 0;
  Buzz buzz_;
  void push(Key k, uint32_t now);
  Key pop(uint32_t now);
  void note(uint32_t& n, const char* what, uint32_t now) {
    n++;
    buzz_.last = what;
    buzz_.lastAt = now;
  }
};

// ------------------------------------------------------------------------------------------------ pulse.cpp
class EmuPulse {
 public:
  // Fault injection (the companion's control({pulseFault})): what can happen to the sensor after power-on.
  //   Stall : the I2C bus fails (every register read / write NACKs): pulse_update() reads 0 samples while the
  //           MAX30102 keeps sampling into its FIFO (rollover, OVF counter); clearing it lets the next read get the
  //           full FIFO with the lost-sample count (the pulse.cpp overflow / re-sync path)
  //   Unplug: the sensor loses power: FIFO and registers are gone, nothing is sampled or read; when it is plugged
  //           back (fault cleared) it is in its power-on reset state and samples nothing until pulse_start()
  enum class Fault : uint8_t { None, Stall, Unplug };

  PpgSynth synth;
  bool init(bool present);                   // pulse_init(): present unless the companion unplugged it
  void start(uint32_t now);                  // pulse_start()
  void stop();                               // pulse_stop()
  void sensor_tick(uint32_t now);            // the sensor takes its 100 Hz samples (FIFO, rollover)
  const PulseResult& update(uint32_t now);   // pulse_update()
  void evidence(uint8_t ev12[12]) const { det_.evidence(ev12); }  // pulse_evidence()
  bool running() const { return running_; }  // pulse.cpp g_running (the driver measures)

  void set_fault(Fault f);
  Fault fault() const { return fault_; }
  // introspection (state().pulse.sensor): the chip samples, FIFO fill level, OVF counter, the last read
  bool sampling() const { return sampling_; }
  int fifo_level() const { return int(fifo_.size()); }
  uint32_t ovf() const { return ovf_; }
  int last_read() const { return lastRead_; }
  uint32_t last_lost() const { return lastLost_; }
  uint32_t reads() const { return reads_; }

 private:
  static const int kFifoDepth = 32;
  static const uint32_t kSampleMs = 10, kStaleMs = 250;
  bool present_ = false, running_ = false, sampling_ = false;
  Fault fault_ = Fault::None;
  PulseDetector det_;
  PulseResult out_;
  uint32_t clock_ = 0, startMs_ = 0, lastSampleMs_ = 0, nextSampleAt_ = 0;
  std::deque<uint64_t> fifo_;  // ir << 32 | red (at most kFifoDepth: the chip's FIFO)
  uint32_t ovf_ = 0;           // OVF_COUNTER (saturates at 31; reset when a sample is popped)
  int lastRead_ = 0;           // samples the last pulse_update() read (while measuring)
  uint32_t lastLost_ = 0, reads_ = 0;
};

// ------------------------------------------------------------------------------------------------ qrscan.cpp
class EmuCam {
 public:
  // what became of one decoded QR (qrscan.cpp deliver())
  enum class Submit : uint8_t {
    Off,        // camera not running (not on SCAN / no camera): nothing is decoded
    Empty,      // an empty payload: deliver() ignores it
    Repeat,     // the payload delivered last, again within kRepeatMs: not handed to the app again
    Delivered,  // in the handoff slot (replacing a payload the app has not polled yet)
  };
  static const uint32_t kRepeatMs = 1000;  // qrscan.cpp kRepeatMs

  bool init(bool present) {  // qrscan_init(): the "camera" is the companion's scan() call
    present_ = present;
    return present;
  }
  bool present() const { return present_; }
  void start() {  // qrscan_start(): nothing starts without a camera; the repeat filter restarts
    running_ = present_;
    pending_.clear();
    has_ = false;
    lastDelivered_.clear();
  }
  void stop() {  // qrscan_stop(): the slot is emptied (the repeat filter is kept until the next start)
    running_ = false;
    pending_.clear();
    has_ = false;
  }
  bool running() const { return running_; }
  bool has_pending() const { return has_; }
  Submit submit(const std::string& text, uint32_t now);  // the decode task decoded `text` at `now`
  bool poll(std::string& payload);                        // qrscan_poll(): the slot, if filled since the last poll

 private:
  bool present_ = true, running_ = false, has_ = false;
  std::string pending_;
  std::string lastDelivered_;  // g_lastDelivered / g_lastDeliveredMs
  uint32_t lastDeliveredMs_ = 0;
};

// ------------------------------------------------------------------------------------------------ store.cpp
class EmuStore {
 public:
  void preload(const Bytes& blob) { blob_ = blob; }  // the NVS content the JS side persisted
  bool load_context(Context& c) const;               // store_load_context()
  bool has_context() const { return !blob_.empty(); }  // store_has_context()
  bool save_context(const Context& c);               // store_save_context()
  const Bytes& blob() const { return blob_; }
  uint32_t saves() const { return saves_; }          // successful writes (the JS side persists after each)
  bool failWrites = false;                           // fault injection: every write fails (NVS error)

 private:
  Bytes blob_;
  uint32_t saves_ = 0;
};

// ------------------------------------------------------------------------------------------------ trng
class EmuTrng {
 public:
  void instantiate(const uint8_t* seed, size_t n);  // HMAC-DRBG instantiate
  void reseed(const uint8_t* p, size_t n);          // more entropy from JS (crypto.getRandomValues)
  void inject(const Bytes& b) { injected_.insert(injected_.end(), b.begin(), b.end()); }  // test mode
  size_t injected() const { return injected_.size(); }
  void fill(uint8_t* p, size_t n);                  // trng_fill()

 private:
  uint8_t k_[32] = {0}, v_[32] = {0};
  std::deque<uint8_t> injected_;
  void update(const uint8_t* p, size_t n);
};

// ------------------------------------------------------------------------------------------------ keys.cpp
class EmuKeys {
 public:
  ~EmuKeys() { wipe_all(); }
  bool have_seed() const { return haveSeed_; }  // keys_have_seed()
  bool store_seed(const uint8_t seed[32]);      // the emulated NVS seed (restore / test mode)
  bool create(const Bytes& pool);               // keys_create(): seed = sha256(pool); refuses to overwrite
  bool init();                                  // keys_init(): derive from the seed, cache public data
  Addr k1_address() const { return have_ ? k1addr_ : Addr(); }
  void p1_pubkey(uint8_t xy64[64]) const;
  bool k1_sign(const B32& digest, uint8_t rsv65[65]);  // derive, sign, low-s, verify, recover, wipe
  bool p1_sign(const B32& digest, uint8_t rs64[64]);   // derive, sign, low-s, verify, wipe
  bool p1_sign_der(const B32& digest, Bytes& der);
  // keys_selftest(): published vectors + the independent Python reference vectors (test/host/crypto_vectors.h) in
  // place of the device's mbedTLS cross-check; the device keys when present. `fault` corrupts one expected value
  // (demonstrates the SELFTEST FAIL path).
  bool selftest(std::string& report, bool fault);
  const uint8_t* seed() const { return haveSeed_ ? seed_ : nullptr; }  // emulated NVS export
  void wipe_all();

 private:
  bool haveSeed_ = false, have_ = false;
  uint8_t seed_[32] = {0};
  Addr k1addr_;
  uint8_t k1pub_[64] = {0}, p1pub_[64] = {0};
  bool derive_one(bool k1, uint8_t priv[32]) const;
};

}  // namespace emu
}  // namespace ripar
