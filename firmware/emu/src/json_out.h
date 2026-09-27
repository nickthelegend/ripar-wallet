// Minimal JSON writer for the emulator's C API (output only; input is parsed with the firmware's json_strict.h).
// Strings are written as printable ASCII: other bytes become '?' (the device's own display rule, ui.cpp sanitize()),
// control characters are escaped.
#pragma once
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace ripar {
namespace emu {

class JsonOut {
 public:
  JsonOut& obj() {
    sep();
    s_ += '{';
    first_.push_back(true);
    return *this;
  }
  JsonOut& end_obj() {
    s_ += '}';
    first_.pop_back();
    return *this;
  }
  JsonOut& arr() {
    sep();
    s_ += '[';
    first_.push_back(true);
    return *this;
  }
  JsonOut& end_arr() {
    s_ += ']';
    first_.pop_back();
    return *this;
  }
  JsonOut& key(const char* k) {
    sep();
    quote(k);
    s_ += ':';
    afterKey_ = true;
    return *this;
  }
  JsonOut& str(const std::string& v) {
    sep();
    quote(v);
    return *this;
  }
  JsonOut& str(const char* v) { return str(std::string(v ? v : "")); }
  JsonOut& num(double v) {
    sep();
    if (!std::isfinite(v)) {
      s_ += "null";
      return *this;
    }
    char b[40];
    std::snprintf(b, sizeof b, "%.10g", v);
    s_ += b;
    return *this;
  }
  JsonOut& num(int64_t v) {
    sep();
    char b[32];
    std::snprintf(b, sizeof b, "%lld", static_cast<long long>(v));
    s_ += b;
    return *this;
  }
  JsonOut& num(int v) { return num(int64_t(v)); }
  JsonOut& num(uint32_t v) { return num(int64_t(v)); }
  JsonOut& u64s(uint64_t v) {  // uint64 as a decimal string (JS numbers lose precision above 2^53)
    char b[32];
    std::snprintf(b, sizeof b, "%llu", static_cast<unsigned long long>(v));
    return str(std::string(b));
  }
  JsonOut& boolean(bool v) {
    sep();
    s_ += v ? "true" : "false";
    return *this;
  }
  JsonOut& null() {
    sep();
    s_ += "null";
    return *this;
  }
  // key + value shorthands
  JsonOut& kv(const char* k, const std::string& v) { return key(k).str(v); }
  JsonOut& kv(const char* k, const char* v) { return key(k).str(v); }
  JsonOut& kv(const char* k, bool v) { return key(k).boolean(v); }
  JsonOut& kv(const char* k, int v) { return key(k).num(v); }
  JsonOut& kv(const char* k, uint32_t v) { return key(k).num(v); }
  JsonOut& kv(const char* k, double v) { return key(k).num(v); }
  JsonOut& kv(const char* k, float v) { return key(k).num(double(v)); }
  const std::string& text() const { return s_; }

 private:
  std::string s_;
  std::vector<bool> first_;
  bool afterKey_ = false;
  void sep() {
    if (afterKey_) {
      afterKey_ = false;
      return;
    }
    if (first_.empty()) return;
    if (!first_.back()) s_ += ',';
    first_.back() = false;
  }
  void quote(const std::string& v) {
    s_ += '"';
    for (unsigned char c : v) {
      if (c == '"' || c == '\\') {
        s_ += '\\';
        s_ += char(c);
      } else if (c == '\n') {
        s_ += "\\n";
      } else if (c < 0x20 || c == 0x7F) {
        char b[8];
        std::snprintf(b, sizeof b, "\\u%04x", unsigned(c));
        s_ += b;
      } else if (c >= 0x80) {
        s_ += '?';
      } else {
        s_ += char(c);
      }
    }
    s_ += '"';
  }
};

}  // namespace emu
}  // namespace ripar
