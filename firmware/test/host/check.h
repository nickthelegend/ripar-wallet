// Tiny header-only check framework for the host unit tests (C++14, no dependencies on firmware code).
//
//   #include "check.h"
//   int main() {
//     CHECK_SECTION("keccak");
//     CHECK(x == 3);
//     CHECK_EQ(a, b);                        // ints / enums / bool / std::string / const char*
//     CHECK_EQ_HEX(buf, 32, "c5d246...");    // bytes vs hex string ("0x" optional, any case)
//     CHECK_EQ_BYTES(a, b, n);               // two buffers
//     return CHECK_SUMMARY();                // prints totals; exit code 1 if anything failed (or 0 checks ran)
//   }
//
// Every macro evaluates its arguments exactly once and returns bool (true = passed), so a test can stop
// early:  if (!CHECK(ok)) return CHECK_SUMMARY();
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>
#include <type_traits>

namespace chk {

struct State {
  int total = 0;
  int failed = 0;
  const char* section = "";
  // unbuffered stdout: if the test crashes, everything printed so far still reaches the runner's log
  State() { std::setvbuf(stdout, nullptr, _IONBF, 0); }
};
inline State& state() {
  static State s;
  return s;
}

inline void section(const char* name) {
  state().section = name ? name : "";
  std::printf("-- %s\n", state().section);
}

inline std::string hex(const uint8_t* p, size_t n) {
  static const char H[] = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; i++) {
    s += H[p[i] >> 4];
    s += H[p[i] & 15];
  }
  return s;
}

inline int nib(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
// normalises an expected hex string: drops "0x", lower-cases; returns "" + sets ok=false if malformed
inline std::string norm_hex(const char* s, bool& ok) {
  ok = true;
  std::string r;
  if (!s) {
    ok = false;
    return r;
  }
  if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
  for (; *s; s++) {
    int v = nib(*s);
    if (v < 0) {
      ok = false;
      continue;
    }
    r += "0123456789abcdef"[v];
  }
  if (r.size() & 1) ok = false;
  return r;
}

// value printers for CHECK_EQ
template <typename T>
typename std::enable_if<std::is_arithmetic<T>::value, std::string>::type show(const T& v) {
  std::ostringstream o;
  o << +v;
  return o.str();
}
template <typename T>
typename std::enable_if<std::is_enum<T>::value, std::string>::type show(const T& v) {
  std::ostringstream o;
  o << static_cast<long long>(v);
  return o.str();
}
inline std::string show(const std::string& s) { return "\"" + s + "\""; }
inline std::string show(const char* s) { return s ? "\"" + std::string(s) + "\"" : std::string("(null)"); }

inline bool report(bool ok, const char* file, int line, const char* expr, const std::string& detail) {
  State& s = state();
  s.total++;
  if (!ok) {
    s.failed++;
    const char* base = std::strrchr(file, '/');
    const char* base2 = std::strrchr(file, '\\');
    if (base2 && (!base || base2 > base)) base = base2;
    std::printf("FAIL %s:%d [%s] %s\n", base ? base + 1 : file, line, s.section, expr);
    if (!detail.empty()) std::printf("     %s\n", detail.c_str());
    std::fflush(stdout);
  }
  return ok;
}

inline bool eq_hex(const uint8_t* p, size_t n, const char* expected, const char* file, int line, const char* expr) {
  bool wellformed;
  std::string want = norm_hex(expected, wellformed);
  std::string got = p ? hex(p, n) : std::string("(null)");
  bool ok = wellformed && got == want;
  std::string detail;
  if (!ok) {
    detail = "got  " + got + "\n     want " + want;
    if (!wellformed) detail += "  (expected string is not valid hex)";
  }
  return report(ok, file, line, expr, detail);
}

inline bool eq_bytes(const uint8_t* a, const uint8_t* b, size_t n, const char* file, int line, const char* expr) {
  bool ok = (n == 0) || (a && b && std::memcmp(a, b, n) == 0);
  std::string detail;
  if (!ok) detail = "a " + (a ? hex(a, n) : std::string("(null)")) + "\n     b " + (b ? hex(b, n) : std::string("(null)"));
  return report(ok, file, line, expr, detail);
}

inline int summary(const char* file) {
  State& s = state();
  const char* base = std::strrchr(file, '/');
  const char* base2 = std::strrchr(file, '\\');
  if (base2 && (!base || base2 > base)) base = base2;
  const char* name = base ? base + 1 : file;
  if (s.total == 0) {
    std::printf("%s: no checks ran -> FAIL\n", name);
    return 1;
  }
  std::printf("%s: %d checks, %d failed -> %s\n", name, s.total, s.failed, s.failed ? "FAIL" : "PASS");
  std::fflush(stdout);
  return s.failed ? 1 : 0;
}

}  // namespace chk

#define CHECK_SECTION(name) ::chk::section(name)
#define CHECK(cond) ::chk::report(static_cast<bool>(cond), __FILE__, __LINE__, #cond, std::string())
#define CHECK_EQ(a, b)                                                                                    \
  ([&]() -> bool {                                                                                        \
    const auto& chk_a_ = (a);                                                                             \
    const auto& chk_b_ = (b);                                                                             \
    bool chk_ok_ = (chk_a_ == chk_b_);                                                                    \
    return ::chk::report(chk_ok_, __FILE__, __LINE__, #a " == " #b,                                       \
                         chk_ok_ ? std::string() : ::chk::show(chk_a_) + " != " + ::chk::show(chk_b_));  \
  }())
#define CHECK_EQ_HEX(ptr, len, hexstr) \
  ::chk::eq_hex(reinterpret_cast<const uint8_t*>(ptr), (len), (hexstr), __FILE__, __LINE__, #ptr " == " #hexstr)
#define CHECK_EQ_BYTES(a, b, n)                                                                       \
  ::chk::eq_bytes(reinterpret_cast<const uint8_t*>(a), reinterpret_cast<const uint8_t*>(b), (n), __FILE__, \
                  __LINE__, #a " == " #b)
#define CHECK_SUMMARY() ::chk::summary(__FILE__)
