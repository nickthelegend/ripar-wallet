// Minimal CBOR (RFC 8949) encoder + bounded DOM decoder for the Ripar protocol. Host + device.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "util.h"

namespace ripar {

class CborWriter {
 public:
  void uint(uint64_t v);
  void nint(uint64_t v);  // encodes -1 - v
  void bytes(const uint8_t* p, size_t n);
  void bytes(const Bytes& b) { bytes(b.data(), b.size()); }
  void text(const std::string& s);
  void array(size_t n);
  void map(size_t n);
  void tag(uint64_t t);
  void boolean(bool b);
  void null();
  const Bytes& out() const { return out_; }
  Bytes take() { return std::move(out_); }

 private:
  void head(uint8_t major, uint64_t v);
  Bytes out_;
};

struct CborVal {
  enum Type : uint8_t { UInt, NInt, Bytes_, Text, Array, Map, Tag, Bool, Null, Undefined, Float } type = Null;
  uint64_t u = 0;              // UInt/NInt value, Tag number, Bool 0/1
  Bytes b;                     // Bytes_ and Text payload
  std::vector<CborVal> items;  // Array: elements. Map: k0,v0,k1,v1,... Tag: [content]
  std::string str() const { return std::string(b.begin(), b.end()); }
};

// Decodes exactly one item spanning the whole buffer. Limits: depth <= 8, <= 256 items per container,
// no indefinite lengths. Returns false (with err) on any violation or trailing bytes.
bool cbor_decode(const uint8_t* p, size_t n, CborVal& out, std::string* err = nullptr);
inline bool cbor_decode(const Bytes& b, CborVal& out, std::string* err = nullptr) {
  return cbor_decode(b.data(), b.size(), out, err);
}

// Map lookup by unsigned-integer key; nullptr if absent or not a map. Duplicate keys are rejected by the decoder.
const CborVal* cbor_get(const CborVal& map, uint64_t key);

}  // namespace ripar
