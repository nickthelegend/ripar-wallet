// Strict JSON (RFC 8259) DOM parser - see include/json_strict.h for the exact policy. Portable C++14.
#include "json_strict.h"

#include <cstring>

namespace ripar {

const JsonVal* JsonVal::get(const char* key) const {
  if (type != Object || !key) return nullptr;
  for (size_t i = 0; i < keys.size() && i < items.size(); i++)
    if (keys[i] == key) return &items[i];
  return nullptr;
}

namespace {

class Parser {
 public:
  Parser(const uint8_t* p, size_t n) : p_(p), n_(n), pos_(0), values_(0) {}

  bool document(JsonVal& v) {
    ws();
    if (pos_ >= n_) return fail("empty document");
    if (!value(v, 0)) return false;
    ws();
    if (pos_ != n_) return fail("trailing garbage after the JSON value");
    return true;
  }
  const std::string& error() const { return err_; }

 private:
  const uint8_t* p_;
  size_t n_, pos_, values_;
  std::string err_;

  bool fail(const char* m) {
    if (err_.empty()) {
      err_ = m;
      err_ += " (at byte ";
      char buf[24];
      unsigned long v = static_cast<unsigned long>(pos_);
      size_t k = 0;
      do {
        buf[k++] = char('0' + v % 10);
        v /= 10;
      } while (v && k < sizeof(buf));
      while (k) err_ += buf[--k];
      err_ += ")";
    }
    return false;
  }

  void ws() {
    while (pos_ < n_ && (p_[pos_] == ' ' || p_[pos_] == '\t' || p_[pos_] == '\n' || p_[pos_] == '\r')) pos_++;
  }

  bool value(JsonVal& v, unsigned depth) {
    if (++values_ > JSON_MAX_VALUES) return fail("more than 2048 JSON values");
    if (pos_ >= n_) return fail("truncated: value expected");
    const uint8_t c = p_[pos_];
    switch (c) {
      case '{':
        return object(v, depth + 1);
      case '[':
        return array(v, depth + 1);
      case '"':
        v.type = JsonVal::String;
        return string(v.str);
      case 't':
        v.type = JsonVal::Bool;
        v.boolean = true;
        return literal("true");
      case 'f':
        v.type = JsonVal::Bool;
        v.boolean = false;
        return literal("false");
      case 'n':
        v.type = JsonVal::Null;
        return literal("null");
      default:
        if (c == '-' || (c >= '0' && c <= '9')) {
          v.type = JsonVal::Number;
          return number(v.str);
        }
        return fail("unexpected character");
    }
  }

  bool literal(const char* lit) {
    const size_t len = std::strlen(lit);
    if (n_ - pos_ < len || std::memcmp(p_ + pos_, lit, len) != 0) return fail("invalid literal");
    pos_ += len;
    return true;
  }

  bool object(JsonVal& v, unsigned depth) {
    if (depth > JSON_MAX_DEPTH) return fail("nesting deeper than 16");
    v.type = JsonVal::Object;
    pos_++;  // '{'
    ws();
    if (pos_ < n_ && p_[pos_] == '}') {
      pos_++;
      return true;
    }
    for (;;) {
      ws();
      if (pos_ >= n_ || p_[pos_] != '"') return fail("object member name expected");
      std::string key;
      if (!string(key)) return false;
      for (const std::string& k : v.keys)
        if (k == key) return fail("duplicate object member name");
      ws();
      if (pos_ >= n_ || p_[pos_] != ':') return fail("':' expected");
      pos_++;
      ws();
      v.keys.push_back(std::move(key));
      v.items.push_back(JsonVal());
      if (!value(v.items.back(), depth)) return false;
      ws();
      if (pos_ >= n_) return fail("truncated object");
      if (p_[pos_] == ',') {
        pos_++;
        continue;
      }
      if (p_[pos_] == '}') {
        pos_++;
        return true;
      }
      return fail("',' or '}' expected");
    }
  }

  bool array(JsonVal& v, unsigned depth) {
    if (depth > JSON_MAX_DEPTH) return fail("nesting deeper than 16");
    v.type = JsonVal::Array;
    pos_++;  // '['
    ws();
    if (pos_ < n_ && p_[pos_] == ']') {
      pos_++;
      return true;
    }
    for (;;) {
      ws();
      v.items.push_back(JsonVal());
      if (!value(v.items.back(), depth)) return false;
      ws();
      if (pos_ >= n_) return fail("truncated array");
      if (p_[pos_] == ',') {
        pos_++;
        continue;
      }
      if (p_[pos_] == ']') {
        pos_++;
        return true;
      }
      return fail("',' or ']' expected");
    }
  }

  static int hexval(uint8_t c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  }

  bool hex4(uint32_t& out) {
    if (n_ - pos_ < 4) return fail("truncated \\u escape");
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
      int h = hexval(p_[pos_ + size_t(i)]);
      if (h < 0) return fail("bad hex digit in \\u escape");
      v = (v << 4) | uint32_t(h);
    }
    pos_ += 4;
    out = v;
    return true;
  }

  static void put_utf8(std::string& s, uint32_t cp) {
    if (cp < 0x80) {
      s += char(cp);
    } else if (cp < 0x800) {
      s += char(0xC0 | (cp >> 6));
      s += char(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
      s += char(0xE0 | (cp >> 12));
      s += char(0x80 | ((cp >> 6) & 0x3F));
      s += char(0x80 | (cp & 0x3F));
    } else {
      s += char(0xF0 | (cp >> 18));
      s += char(0x80 | ((cp >> 12) & 0x3F));
      s += char(0x80 | ((cp >> 6) & 0x3F));
      s += char(0x80 | (cp & 0x3F));
    }
  }

  // One raw (unescaped) UTF-8 sequence starting at pos_ with lead byte >= 0x80; appended to s.
  bool utf8_seq(std::string& s) {
    const uint8_t c = p_[pos_];
    size_t len;
    uint32_t cp, min;
    if ((c & 0xE0) == 0xC0) {
      len = 2;
      cp = c & 0x1Fu;
      min = 0x80;
    } else if ((c & 0xF0) == 0xE0) {
      len = 3;
      cp = c & 0x0Fu;
      min = 0x800;
    } else if ((c & 0xF8) == 0xF0) {
      len = 4;
      cp = c & 0x07u;
      min = 0x10000;
    } else {
      return fail("invalid UTF-8");
    }
    if (n_ - pos_ < len) return fail("invalid UTF-8 (truncated sequence)");
    for (size_t k = 1; k < len; k++) {
      const uint8_t cc = p_[pos_ + k];
      if ((cc & 0xC0) != 0x80) return fail("invalid UTF-8");
      cp = (cp << 6) | (cc & 0x3Fu);
    }
    if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return fail("invalid UTF-8");
    s.append(reinterpret_cast<const char*>(p_ + pos_), len);
    pos_ += len;
    return true;
  }

  bool string(std::string& out) {
    pos_++;  // opening quote
    std::string s;
    for (;;) {
      if (pos_ >= n_) return fail("unterminated string");
      const uint8_t c = p_[pos_];
      if (c == '"') {
        pos_++;
        out.swap(s);
        return true;
      }
      if (c < 0x20) return fail("raw control character in string");
      if (c >= 0x80) {
        if (!utf8_seq(s)) return false;
        continue;
      }
      if (c != '\\') {
        s += char(c);
        pos_++;
        continue;
      }
      pos_++;  // backslash
      if (pos_ >= n_) return fail("truncated escape");
      const uint8_t e = p_[pos_++];
      switch (e) {
        case '"':
          s += '"';
          break;
        case '\\':
          s += '\\';
          break;
        case '/':
          s += '/';
          break;
        case 'b':
          s += '\b';
          break;
        case 'f':
          s += '\f';
          break;
        case 'n':
          s += '\n';
          break;
        case 'r':
          s += '\r';
          break;
        case 't':
          s += '\t';
          break;
        case 'u': {
          uint32_t u;
          if (!hex4(u)) return false;
          if (u == 0) return fail("\\u0000 is not allowed");
          if (u >= 0xDC00 && u <= 0xDFFF) return fail("lone low surrogate escape");
          if (u >= 0xD800 && u <= 0xDBFF) {
            if (n_ - pos_ < 2 || p_[pos_] != '\\' || p_[pos_ + 1] != 'u') return fail("lone high surrogate escape");
            pos_ += 2;
            uint32_t lo;
            if (!hex4(lo)) return false;
            if (lo < 0xDC00 || lo > 0xDFFF) return fail("high surrogate not followed by a low surrogate");
            u = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00);
          }
          put_utf8(s, u);
          break;
        }
        default:
          return fail("invalid escape");
      }
    }
  }

  bool digits() {
    const size_t start = pos_;
    while (pos_ < n_ && p_[pos_] >= '0' && p_[pos_] <= '9') pos_++;
    return pos_ > start;
  }

  bool number(std::string& out) {
    const size_t start = pos_;
    if (p_[pos_] == '-') pos_++;
    if (pos_ >= n_) return fail("truncated number");
    if (p_[pos_] == '0') {
      pos_++;
      if (pos_ < n_ && p_[pos_] >= '0' && p_[pos_] <= '9') return fail("leading zero in number");
    } else if (p_[pos_] >= '1' && p_[pos_] <= '9') {
      digits();
    } else {
      return fail("digit expected");
    }
    if (pos_ < n_ && p_[pos_] == '.') {
      pos_++;
      if (!digits()) return fail("digit expected after '.'");
    }
    if (pos_ < n_ && (p_[pos_] == 'e' || p_[pos_] == 'E')) {
      pos_++;
      if (pos_ < n_ && (p_[pos_] == '+' || p_[pos_] == '-')) pos_++;
      if (!digits()) return fail("digit expected in exponent");
    }
    out.assign(reinterpret_cast<const char*>(p_ + start), pos_ - start);
    return true;
  }
};

}  // namespace

bool json_parse_strict(const uint8_t* p, size_t n, JsonVal& out, std::string* err) {
  if (!p && n) {
    if (err) *err = "null input";
    return false;
  }
  if (n > JSON_MAX_BYTES) {
    if (err) *err = "JSON longer than 16384 bytes";
    return false;
  }
  static const uint8_t kEmpty = 0;
  Parser ps(p ? p : &kEmpty, n);
  JsonVal v;
  if (!ps.document(v)) {
    if (err) *err = ps.error();
    return false;
  }
  out = std::move(v);
  if (err) err->clear();
  return true;
}

}  // namespace ripar
