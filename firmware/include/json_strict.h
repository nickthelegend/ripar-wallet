// Strict JSON (RFC 8259) DOM parser for the Privy request view (docs/PROTOCOL.md §4 ripar-privy-req).
// Host (g++ -std=c++14) + device.
//
// The device signs sha256 of the exact JSON bytes it displays, so the parser refuses everything that a
// different JSON implementation could read differently from us:
//   - duplicate object member names (compared after escape decoding, so "a" and "a" collide)
//   - anything after the single top-level value except JSON whitespace (space, tab, CR, LF)
//   - invalid UTF-8 (overlongs, surrogates, > U+10FFFF), raw control characters inside strings,
//     lone / mis-ordered UTF-16 surrogate escapes, and the escape \u0000
//   - nesting deeper than 16 containers (the top-level object or array is depth 1)
//   - more than 2048 values in total, or more than 16384 input bytes
//   - non-RFC syntax: single quotes, trailing commas, comments, NaN/Infinity, leading zeros / "+" / ".5" / "1."
// Numbers are kept as their literal text (no float conversion).
#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ripar {

struct JsonVal {
  enum Type : uint8_t { Null, Bool, Number, String, Array, Object } type = Null;
  bool boolean = false;
  std::string str;                // String: decoded UTF-8 (escapes resolved). Number: the literal as written.
  std::vector<std::string> keys;  // Object: member names (decoded), in document order
  std::vector<JsonVal> items;     // Array: elements. Object: member values (items[i] belongs to keys[i]).
  // Object member by exact (decoded) name; nullptr when absent or when this is not an object.
  const JsonVal* get(const char* key) const;
};

const unsigned JSON_MAX_DEPTH = 16;
const size_t JSON_MAX_VALUES = 2048;
const size_t JSON_MAX_BYTES = 16384;

// Parses exactly one JSON value spanning the whole buffer (surrounding JSON whitespace allowed).
// On failure returns false, sets *err (if given) and leaves `out` unchanged.
bool json_parse_strict(const uint8_t* p, size_t n, JsonVal& out, std::string* err = nullptr);

}  // namespace ripar
