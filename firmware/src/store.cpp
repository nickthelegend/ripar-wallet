// NVS (Preferences namespace "ripar"): the pinned device context (include/context.h), stored as the versioned,
// CRC-protected blob of context_serialize() under key "ctx". The byte layout lives in src/context.cpp (host-tested
// by test/host/test_policy.cpp). A blob of another size / version / CRC (e.g. layout v1 from older firmware) is not
// loaded: the device then counts as unpaired and must be paired again.
//
// Only flows.cpp calls store_save_context(), and only with a Context produced by the policy.h context_after_*()
// helpers after a user-confirmed pairing / a signature the device itself made.
#include <Preferences.h>

#include <cstring>

#include "device.h"

namespace ripar {
namespace {

constexpr const char* kNs = "ripar";
constexpr const char* kKey = "ctx";

}  // namespace

bool store_load_context(Context& c) {
  Preferences prefs;
  if (!prefs.begin(kNs, true)) return false;
  uint8_t buf[CONTEXT_BLOB_SIZE];
  const size_t len = prefs.getBytesLength(kKey);
  const bool got = len == CONTEXT_BLOB_SIZE && prefs.getBytes(kKey, buf, CONTEXT_BLOB_SIZE) == CONTEXT_BLOB_SIZE;
  prefs.end();
  if (!got) return false;
  return context_deserialize(buf, CONTEXT_BLOB_SIZE, c);
}

bool store_has_context() {
  Preferences prefs;
  if (!prefs.begin(kNs, true)) return false;  // no namespace yet: nothing was ever stored
  const size_t len = prefs.getBytesLength(kKey);
  prefs.end();
  return len > 0;
}

bool store_save_context(const Context& c) {
  uint8_t buf[CONTEXT_BLOB_SIZE];
  context_serialize(c, buf);
  Preferences prefs;
  if (!prefs.begin(kNs, false)) return false;
  const bool ok = prefs.putBytes(kKey, buf, CONTEXT_BLOB_SIZE) == CONTEXT_BLOB_SIZE;
  prefs.end();
  if (!ok) return false;
  Context check;  // read back: a torn / failed write must not be reported as saved
  if (!store_load_context(check)) return false;
  uint8_t again[CONTEXT_BLOB_SIZE];
  context_serialize(check, again);
  return std::memcmp(again, buf, CONTEXT_BLOB_SIZE) == 0;
}

}  // namespace ripar
