// Emulated hardware (emu_hw.h). Each block names the device file whose behaviour it reproduces.
#include "emu_hw.h"

#include <cstdio>
#include <cstring>

#include "crypto.h"
#include "hashes.h"

// Independent Python reference values (tools/ref_crypto.py gen) used by the host tests; the emulator's self-test
// uses them where the device cross-checks with mbedTLS.
#include "crypto_vectors.h"

namespace ripar {
namespace emu {

namespace {

void wipe(void* p, size_t n) {
  volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
  while (n--) *v++ = 0;
}

}  // namespace

// ================================================================================================= io.cpp
namespace {
constexpr uint32_t kDebounceMs = 30;
constexpr uint32_t kShortMaxMs = 1000;
constexpr uint32_t kLongMs = 2000;
constexpr uint32_t kHoldMs = 5000;
constexpr uint32_t kEventMaxAgeMs = 1000;
}  // namespace

// io_init()
void EmuIo::init(uint32_t now) {
  const bool down = raw_;
  rawLast_ = down;
  stable_ = down;
  rawSince_ = now;
  downSince_ = now;
  armed_ = !down;  // ignore a press that is already down (strapping pin / stuck key)
  qHead_ = qCount_ = 0;
}

// push_locked()
void EmuIo::push(Key k, uint32_t now) {
  if (qCount_ < kQueueLen) {
    q_[(qHead_ + qCount_) % kQueueLen] = Ev{k, now};
    qCount_++;
  }
}

// key_tick(): debounced state + events, one 5 ms timer tick
void EmuIo::timer_tick(uint32_t now) {
  const bool raw = raw_;
  if (raw != rawLast_) {
    rawLast_ = raw;
    rawSince_ = now;
  }
  if (raw != stable_ && (now - rawSince_) >= kDebounceMs) {
    stable_ = raw;
    if (raw) {  // press
      downSince_ = rawSince_;
      sentLong_ = sentHold_ = false;
    } else {  // release
      const uint32_t held = rawSince_ - downSince_;
      if (armed_ && !sentLong_ && held < kShortMaxMs) push(Key::Short, now);
      armed_ = true;
    }
  }
  if (stable_ && armed_) {
    const uint32_t held = now - downSince_;
    if (!sentLong_ && held >= kLongMs) {
      sentLong_ = true;
      push(Key::Long2s, now);
    }
    if (!sentHold_ && held >= kHoldMs) {
      sentHold_ = true;
      push(Key::Hold5s, now);
    }
  }
}

// pop_locked(): the first event that is not older than kEventMaxAgeMs
Key EmuIo::pop(uint32_t now) {
  while (qCount_ > 0) {
    const Ev e = q_[qHead_];
    qHead_ = (qHead_ + 1) % kQueueLen;
    qCount_--;
    if (now - e.t <= kEventMaxAgeMs) return e.key;
  }
  return Key::None;
}

// io_poll_key_state()
Key EmuIo::poll_key_state(uint32_t now, bool& down) {
  const Key k = pop(now);
  down = stable_;
  return k;
}

// io_flush()
void EmuIo::flush(bool swallowHeld) {
  qHead_ = 0;
  qCount_ = 0;
  if (swallowHeld && stable_) armed_ = false;  // the rest of this press produces no event; re-armed on release
}

// ================================================================================================= pulse.cpp
bool EmuPulse::init(bool present) {  // pulse_init(): probe, reset, park in shutdown
  present_ = present;
  running_ = false;
  sampling_ = false;
  return present;
}

// pulse_start(): configure while shut down, clear the FIFO, SHDN = 0. The register writes fail while the I2C bus is
// faulted or the sensor is unplugged: then g_running stays false (pulse_update() reports nothing, SIGN never arms).
void EmuPulse::start(uint32_t now) {
  det_.reset();
  out_ = PulseResult();
  clock_ = 0;
  startMs_ = now;
  lastRead_ = 0;
  lastLost_ = 0;
  if (!present_) return;
  const bool ok = fault_ == Fault::None;
  if (ok) {
    fifo_.clear();
    ovf_ = 0;
    sampling_ = true;
    nextSampleAt_ = now + kSampleMs;  // SHDN = 0: the first sample is ready one period later
  }
  running_ = ok;
  lastSampleMs_ = now;
}

// pulse_stop(): fail closed; pulse_evidence() still returns the finished measurement's evidence. LEDs off + shutdown
// (writes that fail during an I2C fault: the chip then keeps sampling, which nobody reads).
void EmuPulse::stop() {
  running_ = false;
  out_ = PulseResult();
  if (!present_) return;
  if (fault_ == Fault::None) sampling_ = false;
}

void EmuPulse::set_fault(Fault f) {
  if (f == fault_) return;
  if (f == Fault::Unplug) {  // power lost: FIFO, pointers and configuration are gone
    sampling_ = false;
    fifo_.clear();
    ovf_ = 0;
  }
  // plugged back in (Unplug -> None / Stall): power-on reset state (MODE = 0), no sampling until pulse_start()
  fault_ = f;
}

// the MAX30102 itself: a sample every 10 ms while in SpO2 mode, 32-sample FIFO with rollover (OVF counter)
void EmuPulse::sensor_tick(uint32_t now) {
  if (!sampling_) return;
  while (int32_t(now - nextSampleAt_) >= 0) {
    uint32_t ir = 0, red = 0;
    synth.sample(nextSampleAt_, ir, red);
    if (fifo_.size() >= size_t(kFifoDepth)) {  // FIFO_ROLLOVER_EN: the oldest sample is overwritten
      fifo_.pop_front();
      if (ovf_ < 31) ovf_++;
    }
    fifo_.push_back((uint64_t(ir & 0x3FFFF) << 32) | (red & 0x3FFFF));
    nextSampleAt_ += kSampleMs;
  }
}

// pulse_update(): fifo_read() (WR / OVF / RD pointers, then the samples) into PulseDetector on the sample clock
const PulseResult& EmuPulse::update(uint32_t now) {
  out_.beatNow = false;
  if (!running_) return out_;
  reads_++;
  int n = 0;
  uint32_t lost = 0;
  if (fault_ == Fault::None) {
    // (WR - RD) & 0x1F: a FIFO holding exactly 32 unread samples with OVF = 0 reads as 0 (pulse.cpp fifo_read)
    n = int(fifo_.size()) & 0x1F;
    if (n == 0 && ovf_ != 0) n = kFifoDepth;  // full FIFO with rollover
    lost = ovf_ & 0x1F;
  }  // else: the I2C transfer fails -> 0 samples (OVF is not read, so not reset)
  lastRead_ = n;
  lastLost_ = n > 0 ? lost : 0;
  if (n <= 0) {
    if (now - lastSampleMs_ > kStaleMs) {  // no samples: "thumb still on the pad" can no longer be checked
      out_.passed = false;
      out_.finger = false;
    }
    return out_;
  }
  ovf_ = 0;  // popping a sample resets OVF_COUNTER
  lastSampleMs_ = now;
  clock_ += lost * kSampleMs;
  // re-sync after a stall longer than the FIFO: the newest sample was taken ~now
  const uint32_t rel = now - startMs_;
  const uint32_t firstEst = rel > uint32_t(n - 1) * kSampleMs ? rel - uint32_t(n - 1) * kSampleMs : 0;
  if (firstEst > clock_ + kSampleMs + 200) clock_ = firstEst - kSampleMs;
  bool beat = false;
  for (int i = 0; i < n; i++) {
    const uint64_t s = fifo_.front();
    fifo_.pop_front();
    clock_ += kSampleMs;
    beat = det_.add(uint32_t(s >> 32), uint32_t(s & 0xFFFFFFFFu), clock_).beatNow || beat;
  }
  out_ = det_.result();
  out_.beatNow = beat;
  return out_;
}

// ================================================================================================= qrscan.cpp
// deliver(): the decode task hands a payload to the app thread; an identical payload at most once per kRepeatMs
EmuCam::Submit EmuCam::submit(const std::string& text, uint32_t now) {
  if (!running_) return Submit::Off;  // camera powered down: nothing is decoded
  if (text.empty()) return Submit::Empty;
  const bool same = text == lastDelivered_;
  if (same && now - lastDeliveredMs_ < kRepeatMs) return Submit::Repeat;
  pending_ = text;
  has_ = true;
  lastDelivered_ = text;
  lastDeliveredMs_ = now;
  return Submit::Delivered;
}

bool EmuCam::poll(std::string& payload) {
  if (!has_) return false;
  payload.swap(pending_);
  pending_.clear();
  has_ = false;
  return true;
}

// ================================================================================================= store.cpp
bool EmuStore::load_context(Context& c) const {  // store_load_context()
  if (blob_.size() != CONTEXT_BLOB_SIZE) return false;
  return context_deserialize(blob_.data(), blob_.size(), c);
}

bool EmuStore::save_context(const Context& c) {  // store_save_context(): write, read back, compare
  if (failWrites) return false;
  uint8_t buf[CONTEXT_BLOB_SIZE];
  context_serialize(c, buf);
  blob_.assign(buf, buf + CONTEXT_BLOB_SIZE);
  Context check;
  if (!load_context(check)) return false;
  uint8_t again[CONTEXT_BLOB_SIZE];
  context_serialize(check, again);
  if (std::memcmp(again, buf, CONTEXT_BLOB_SIZE) != 0) return false;
  saves_++;
  return true;
}

// ================================================================================================= trng
// HMAC_DRBG (NIST SP 800-90A) with HMAC-SHA256 from crypto.cpp, no prediction resistance / personalisation.
void EmuTrng::update(const uint8_t* p, size_t n) {
  Bytes m;
  for (int round = 0; round < 2; round++) {
    m.assign(v_, v_ + 32);
    m.push_back(uint8_t(round));
    if (p && n) m.insert(m.end(), p, p + n);
    hmac_sha256(k_, 32, m.data(), m.size(), k_);
    hmac_sha256(k_, 32, v_, 32, v_);
    if (!p || !n) break;
  }
  if (!m.empty()) wipe(m.data(), m.size());
}

void EmuTrng::instantiate(const uint8_t* seed, size_t n) {
  std::memset(k_, 0x00, 32);
  std::memset(v_, 0x01, 32);
  injected_.clear();
  update(seed, n);
}

void EmuTrng::reseed(const uint8_t* p, size_t n) { update(p, n); }

void EmuTrng::fill(uint8_t* p, size_t n) {
  if (!p || !n) return;
  size_t i = 0;
  while (i < n && !injected_.empty()) {  // test mode: injected bytes first
    p[i++] = injected_.front();
    injected_.pop_front();
  }
  while (i < n) {
    hmac_sha256(k_, 32, v_, 32, v_);
    const size_t k = (n - i) < 32 ? (n - i) : 32;
    std::memcpy(p + i, v_, k);
    i += k;
  }
  update(nullptr, 0);
}

// ================================================================================================= keys.cpp
bool EmuKeys::store_seed(const uint8_t seed[32]) {
  std::memcpy(seed_, seed, 32);
  haveSeed_ = true;
  have_ = false;
  return true;
}

// keys_create(): refuses to overwrite a seed; seed = sha256(entropy pool); a seed without valid keys is not kept
bool EmuKeys::create(const Bytes& pool) {
  if (haveSeed_) return false;
  uint8_t seed[32], k1[32], p1[32];
  sha256(pool.data(), pool.size(), seed);
  const bool ok = derive_path(Curve::Secp256k1, seed, 32, PATH_K1, 5, k1) && derive_path(Curve::P256, seed, 32, PATH_P1, 2, p1);
  wipe(k1, sizeof k1);
  wipe(p1, sizeof p1);
  if (ok) store_seed(seed);
  wipe(seed, sizeof seed);
  return ok && init();
}

// load_public()
bool EmuKeys::init() {
  have_ = false;
  if (!haveSeed_) return false;
  uint8_t k1[32], p1[32];
  bool ok = derive_path(Curve::Secp256k1, seed_, 32, PATH_K1, 5, k1) && derive_path(Curve::P256, seed_, 32, PATH_P1, 2, p1);
  ok = ok && ec_pubkey(Curve::Secp256k1, k1, k1pub_) && ec_pubkey(Curve::P256, p1, p1pub_);
  wipe(k1, sizeof k1);
  wipe(p1, sizeof p1);
  if (ok) {
    k1addr_ = eth_address(k1pub_);
  } else {
    k1addr_ = Addr();
    wipe(k1pub_, 64);
    wipe(p1pub_, 64);
  }
  have_ = ok;
  return ok;
}

void EmuKeys::p1_pubkey(uint8_t xy64[64]) const {
  if (have_)
    std::memcpy(xy64, p1pub_, 64);
  else
    std::memset(xy64, 0, 64);
}

bool EmuKeys::derive_one(bool k1, uint8_t priv[32]) const {  // derive_one()
  if (!haveSeed_) return false;
  const bool ok = k1 ? derive_path(Curve::Secp256k1, seed_, 32, PATH_K1, 5, priv)
                     : derive_path(Curve::P256, seed_, 32, PATH_P1, 2, priv);
  if (!ok) wipe(priv, 32);
  return ok;
}

namespace {
// s <= n/2 (keys.cpp is_low_s)
bool is_low_s(Curve c, const uint8_t rs[64]) {
  static const uint8_t kHalfK1[32] = {0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                      0xff, 0xff, 0xff, 0xff, 0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4,
                                      0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0};
  static const uint8_t kHalfP256[32] = {0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff, 0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b,
                                        0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8};
  return std::memcmp(rs + 32, c == Curve::P256 ? kHalfP256 : kHalfK1, 32) <= 0;
}
}  // namespace

// k1_sign()
bool EmuKeys::k1_sign(const B32& digest, uint8_t rsv65[65]) {
  if (!have_) return false;
  uint8_t priv[32], rs[64], rec[64];
  int recid = -1;
  bool ok = derive_one(true, priv) && ecdsa_sign(Curve::Secp256k1, priv, digest.v, rs, &recid);
  wipe(priv, sizeof priv);
  ok = ok && (recid == 0 || recid == 1) && is_low_s(Curve::Secp256k1, rs) &&
       ecdsa_verify(Curve::Secp256k1, k1pub_, digest.v, rs) &&
       ecdsa_recover(Curve::Secp256k1, digest.v, rs, recid, rec) && std::memcmp(rec, k1pub_, 64) == 0;
  if (ok) {
    std::memcpy(rsv65, rs, 64);
    rsv65[64] = uint8_t(27 + recid);
  }
  wipe(rs, sizeof rs);
  return ok;
}

// p1_sign()
bool EmuKeys::p1_sign(const B32& digest, uint8_t rs64[64]) {
  if (!have_) return false;
  uint8_t priv[32], rs[64];
  int recid = -1;
  bool ok = derive_one(false, priv) && ecdsa_sign(Curve::P256, priv, digest.v, rs, &recid);
  wipe(priv, sizeof priv);
  ok = ok && is_low_s(Curve::P256, rs) && ecdsa_verify(Curve::P256, p1pub_, digest.v, rs);
  if (ok) std::memcpy(rs64, rs, 64);
  wipe(rs, sizeof rs);
  return ok;
}

bool EmuKeys::p1_sign_der(const B32& digest, Bytes& der) {  // p1_sign_der()
  uint8_t rs[64], out[72];
  if (!p1_sign(digest, rs)) return false;
  const size_t n = ecdsa_der(rs, out);
  wipe(rs, sizeof rs);
  if (n == 0 || n > sizeof out) return false;
  der.assign(out, out + n);
  return true;
}

void EmuKeys::wipe_all() {  // keys_wipe() (RAM)
  wipe(seed_, sizeof seed_);
  wipe(k1pub_, sizeof k1pub_);
  wipe(p1pub_, sizeof p1pub_);
  k1addr_ = Addr();
  haveSeed_ = have_ = false;
}

// ------------------------------------------------------------------------------------------------ self-test
namespace {

bool unhex(const char* s, uint8_t* out, size_t n) {
  Bytes b;
  if (!from_hex(s, b) || b.size() != n) return false;
  std::memcpy(out, b.data(), n);
  return true;
}

struct Report {
  std::string& out;
  int fails = 0;
  void check(const char* name, bool ok) {
    out += ok ? "PASS " : "FAIL ";
    out += name;
    out += '\n';
    if (!ok) fails++;
  }
};

void sha256_str(const char* s, uint8_t out[32]) { sha256(reinterpret_cast<const uint8_t*>(s), std::strlen(s), out); }

Curve curve_of(int c) { return c == 1 ? Curve::P256 : Curve::Secp256k1; }

// keys.cpp check_vector() without the mbedTLS legs
void check_vector(Report& R, const char* tag, Curve c, const char* privHex, const char* msg, const char* pubHex,
                  const char* rsHex, int expRecid, bool fault) {
  uint8_t d[32], dig[32], pub[64], expPub[64], rs[64], expRs[64], der[72], rec[64];
  char name[96];
  const bool vecOk = unhex(privHex, d, 32) && unhex(pubHex, expPub, 64) && unhex(rsHex, expRs, 64);
  if (fault) expRs[63] ^= 1;
  sha256_str(msg, dig);
  std::snprintf(name, sizeof name, "%s vector parse", tag);
  R.check(name, vecOk);
  const bool pubOk = ec_pubkey(c, d, pub);
  std::snprintf(name, sizeof name, "%s ec_pubkey == vector", tag);
  R.check(name, pubOk && std::memcmp(pub, expPub, 64) == 0);
  int recid = -1;
  const bool sigOk = ecdsa_sign(c, d, dig, rs, &recid);
  std::snprintf(name, sizeof name, "%s ecdsa_sign == RFC6979 vector (low-s)", tag);
  R.check(name, sigOk && std::memcmp(rs, expRs, 64) == 0);
  std::snprintf(name, sizeof name, "%s low-s", tag);
  R.check(name, sigOk && is_low_s(c, rs));
  std::snprintf(name, sizeof name, "%s recid == %d", tag, expRecid);
  R.check(name, sigOk && recid == expRecid);
  std::snprintf(name, sizeof name, "%s ecdsa_verify", tag);
  R.check(name, sigOk && ecdsa_verify(c, pub, dig, rs));
  std::snprintf(name, sizeof name, "%s ecdsa_recover", tag);
  R.check(name, sigOk && ecdsa_recover(c, dig, rs, recid, rec) && std::memcmp(rec, pub, 64) == 0);
  const size_t dn = sigOk ? ecdsa_der(rs, der) : 0;
  std::snprintf(name, sizeof name, "%s ecdsa_der", tag);
  R.check(name, dn >= 8 && dn <= 72 && der[0] == 0x30 && der[1] == dn - 2);
  uint8_t bad[32];
  std::memcpy(bad, dig, 32);
  bad[31] ^= 1;
  std::snprintf(name, sizeof name, "%s verify rejects a modified digest", tag);
  R.check(name, sigOk && !ecdsa_verify(c, pub, bad, rs));
  wipe(d, sizeof d);
}

}  // namespace

bool EmuKeys::selftest(std::string& report, bool fault) {
  report.clear();
  Report R{report};

  // --- hash primitives: published values + the Python reference (sha512 / HMAC over block-boundary lengths)
  {
    uint8_t a[64];
    bool ok = true;
    sha256(reinterpret_cast<const uint8_t*>("abc"), 3, a);
    ok = ok && to_hex(a, 32, false) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    sha256(nullptr, 0, a);
    ok = ok && to_hex(a, 32, false) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    R.check("sha256 == FIPS 180-2 vectors", ok);
    keccak256(nullptr, 0, a);
    R.check("keccak256('') == c5d24601...", to_hex(a, 32, false) ==
                                               "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    ok = true;
    for (const HashVec& v : HASH_VECS) {
      Bytes key(v.klen), msg(v.mlen);
      for (size_t i = 0; i < key.size(); i++) key[i] = uint8_t(i * 13 + 7);
      for (size_t i = 0; i < msg.size(); i++) msg[i] = uint8_t(i * 7 + 3);
      uint8_t o32[32], o64[64];
      sha512(msg.data(), msg.size(), o64);
      ok = ok && to_hex(o64, 64, false) == v.sha512;
      hmac_sha256(key.data(), key.size(), msg.data(), msg.size(), o32);
      ok = ok && to_hex(o32, 32, false) == v.hmac_sha256;
      hmac_sha512(key.data(), key.size(), msg.data(), msg.size(), o64);
      ok = ok && to_hex(o64, 64, false) == v.hmac_sha512;
    }
    R.check("sha512 / hmac_sha256 / hmac_sha512 == Python reference (17 lengths)", ok);
  }

  // --- the device's published ECDSA vectors (keys.cpp keys_selftest)
  check_vector(R, "P-256", Curve::P256, "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721", "sample",
               "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
               "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
               "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
               "0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9",
               1, fault);
  check_vector(R, "secp256k1", Curve::Secp256k1, "0000000000000000000000000000000000000000000000000000000000000001",
               "Satoshi Nakamoto",
               "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
               "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
               "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8"
               "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5",
               1, false);

  // --- ECDSA vs the Python reference (a spread of the host-test vectors: both curves, edge digests)
  {
    bool ok = true;
    int n = 0;
    const size_t total = sizeof(ECDSA_VECS) / sizeof(ECDSA_VECS[0]);
    for (size_t i = 0; i < total; i += 6) {
      const EcdsaVec& v = ECDSA_VECS[i];
      const Curve c = curve_of(v.curve);
      uint8_t d[32], dig[32], pub[64], rs[64], der[72];
      int recid = -1;
      ok = ok && unhex(v.priv, d, 32) && unhex(v.digest, dig, 32) && ec_pubkey(c, d, pub) &&
           to_hex(pub, 64, false) == v.pub && ecdsa_sign(c, d, dig, rs, &recid) && to_hex(rs, 64, false) == v.rs &&
           recid == v.recid && ecdsa_verify(c, pub, dig, rs);
      const size_t dn = ok ? ecdsa_der(rs, der) : 0;
      ok = ok && to_hex(der, dn, false) == v.der;
      if (ok && c == Curve::Secp256k1) ok = to_hex(eth_address(pub).v, 20, false) == v.addr;
      wipe(d, sizeof d);
      n++;
    }
    char name[96];
    std::snprintf(name, sizeof name, "ECDSA sign / recid / verify / DER / address == Python reference (%d vectors)", n);
    R.check(name, ok);
    ok = true;
    for (const DerVec& v : DER_VECS) {
      uint8_t rs[64], der[72];
      ok = ok && unhex(v.rs, rs, 64);
      const size_t dn = ok ? ecdsa_der(rs, der) : 0;
      ok = ok && to_hex(der, dn, false) == v.der;
    }
    R.check("strict DER == Python reference", ok);
  }

  // --- BIP-32 TV1 / SLIP-10 nist256p1 TV1: seed 000102..0f, m/0'/1/2'/2/1000000000
  {
    uint8_t seed16[16], priv[32], exp[32];
    for (int i = 0; i < 16; i++) seed16[i] = uint8_t(i);
    const uint32_t path[5] = {0 + H, 1, 2 + H, 2, 1000000000u};
    bool ok = derive_path(Curve::Secp256k1, seed16, 16, path, 5, priv) &&
              unhex("471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8", exp, 32) &&
              std::memcmp(priv, exp, 32) == 0;
    R.check("BIP-32 TV1 m/0'/1/2'/2/1000000000", ok);
    ok = derive_path(Curve::P256, seed16, 16, path, 5, priv) &&
         unhex("21c4f269ef0a5fd1badf47eeacebeeaa3de22eb8e5b0adcd0f27dd99d34d0119", exp, 32) &&
         std::memcmp(priv, exp, 32) == 0;
    R.check("SLIP-10 P-256 TV1 m/0'/1/2'/2/1000000000", ok);
    wipe(priv, sizeof priv);
  }

  // --- device paths from a fixed seed 00..1f (keys.cpp values) and from the demo seed (Python reference)
  {
    uint8_t seed[32], k1[32], p1[32], exp[32], pub[64], expPub[64];
    for (int i = 0; i < 32; i++) seed[i] = uint8_t(i);
    bool ok = derive_path(Curve::Secp256k1, seed, 32, PATH_K1, 5, k1) && derive_path(Curve::P256, seed, 32, PATH_P1, 2, p1);
    R.check("K1 m/44'/60'/0'/0/0 priv", ok && unhex("11407d418c91c6314e009de5a478110ba7e23714289fe8a87941f5773cc38778", exp, 32) &&
                                            std::memcmp(k1, exp, 32) == 0);
    R.check("P1 m/7951'/0' priv", ok && unhex("8c0cf2e758737962f9688403bfc25ef5d52ed648bd34a78e821251080e27edf2", exp, 32) &&
                                      std::memcmp(p1, exp, 32) == 0);
    Addr want;
    R.check("K1 address 0x919538116b4F25f1CE01429fd9Ed7964556bf565",
            ok && ec_pubkey(Curve::Secp256k1, k1, pub) && unhex("919538116b4f25f1ce01429fd9ed7964556bf565", want.v, 20) &&
                eth_address(pub) == want);
    R.check("P1 pubkey", ok && ec_pubkey(Curve::P256, p1, pub) &&
                             unhex("d9b5652338847e00105256b6f6019a19995559d424e93b1d7dad8f0d26dd8835"
                                   "eb352cc0a5b3febc42e2dcf8888c1840aa82c237810c3ee86aa4fbe5f7633f7f",
                                   expPub, 64) &&
                             std::memcmp(pub, expPub, 64) == 0);
    ok = unhex(DEMO_SEED, seed, 32) && derive_path(Curve::Secp256k1, seed, 32, PATH_K1, 5, k1) &&
         to_hex(k1, 32, false) == DEMO_K1_PRIV && ec_pubkey(Curve::Secp256k1, k1, pub) &&
         to_hex(eth_address(pub).v, 20, false) == DEMO_K1_ADDR && derive_path(Curve::P256, seed, 32, PATH_P1, 2, p1) &&
         to_hex(p1, 32, false) == DEMO_P1_PRIV && ec_pubkey(Curve::P256, p1, pub) && to_hex(pub, 64, false) == DEMO_P1_PUB;
    R.check("demo seed K1 / P1 == Python reference", ok);
    bool dv = true;
    for (const DeriveVec& v : DERIVE_VECS) {
      Bytes sd;
      uint32_t path[6];
      for (int i = 0; i < 6; i++) path[i] = v.path[i];
      uint8_t priv[32];
      dv = dv && from_hex(v.seed, sd) && derive_path(curve_of(v.curve), sd.data(), sd.size(), path, size_t(v.depth), priv) &&
           to_hex(priv, 32, false) == v.priv;
      wipe(priv, sizeof priv);
    }
    R.check("derivation == Python reference (random seeds / paths, both curves)", dv);
    wipe(seed, sizeof seed);
    wipe(k1, sizeof k1);
    wipe(p1, sizeof p1);
  }

  // --- the device keys, if provisioned (keys.cpp: sign + independent verify)
  if (have_) {
    B32 dig;
    sha256_str("ripar-device-selftest", dig.v);
    uint8_t rsv[65], rs[64], rec[64];
    Bytes der;
    R.check("device K1 sign + verify + recover",
            k1_sign(dig, rsv) && ecdsa_verify(Curve::Secp256k1, k1pub_, dig.v, rsv) &&
                ecdsa_recover(Curve::Secp256k1, dig.v, rsv, rsv[64] - 27, rec) && std::memcmp(rec, k1pub_, 64) == 0);
    R.check("device P1 sign + verify", p1_sign(dig, rs) && ecdsa_verify(Curve::P256, p1pub_, dig.v, rs));
    R.check("device P1 DER", p1_sign_der(dig, der) && der.size() >= 8 && der[0] == 0x30 && der[1] == der.size() - 2);
  } else {
    report += "SKIP device keys (no seed)\n";
  }

  char line[96];
  std::snprintf(line, sizeof line, "%s (%d failed)\n", R.fails ? "SELFTEST FAIL" : "SELFTEST PASS", R.fails);
  report += line;
  return R.fails == 0;
}

}  // namespace emu
}  // namespace ripar
