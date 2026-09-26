// Minimal CBOR (RFC 8949): canonical writer + bounded, strict DOM decoder. Portable C++14 (host tests + device).
//
// Decoder policy (the input comes from an untrusted companion through the camera):
//  - exactly one well-formed item spanning the whole buffer; trailing bytes are an error
//  - definite lengths only (indefinite strings/arrays/maps are rejected, as is a stray "break")
//  - nesting depth <= 8 (arrays, maps and tags each count as one level), <= 256 elements per array,
//    <= 256 entries (key/value pairs) per map
//  - duplicate map keys are rejected (compared by decoded value, so 0x01 and 0x18 0x01 are the same key)
//  - text strings must be valid UTF-8 (no overlongs, no surrogates, <= U+10FFFF)
//  - simple values other than false/true/null/undefined are rejected; floats (half/single/double) are accepted
//    and stored as the IEEE-754 double bit pattern in CborVal::u
//  - 1/2/4/8-byte argument heads are accepted even when not minimal (the writer always emits the shortest)
//  - nothing is allocated from a length field before checking that the input actually holds that many bytes
#include "cbor.h"

#include <cstring>

namespace ripar {

namespace {

const unsigned kMaxDepth = 8;
const uint64_t kMaxItems = 256;

}  // namespace

// ---------------------------------------------------------------------------------------------------------------
// Writer

void CborWriter::head(uint8_t major, uint64_t v) {
  const uint8_t m = uint8_t(major << 5);
  if (v < 24) {
    out_.push_back(uint8_t(m | v));
  } else if (v <= 0xFFu) {
    out_.push_back(uint8_t(m | 24));
    out_.push_back(uint8_t(v));
  } else if (v <= 0xFFFFu) {
    out_.push_back(uint8_t(m | 25));
    out_.push_back(uint8_t(v >> 8));
    out_.push_back(uint8_t(v));
  } else if (v <= 0xFFFFFFFFu) {
    out_.push_back(uint8_t(m | 26));
    for (int i = 3; i >= 0; i--) out_.push_back(uint8_t(v >> (8 * i)));
  } else {
    out_.push_back(uint8_t(m | 27));
    for (int i = 7; i >= 0; i--) out_.push_back(uint8_t(v >> (8 * i)));
  }
}

void CborWriter::uint(uint64_t v) { head(0, v); }
void CborWriter::nint(uint64_t v) { head(1, v); }

void CborWriter::bytes(const uint8_t* p, size_t n) {
  head(2, n);
  if (n) out_.insert(out_.end(), p, p + n);
}

void CborWriter::text(const std::string& s) {
  head(3, s.size());
  out_.insert(out_.end(), s.begin(), s.end());
}

void CborWriter::array(size_t n) { head(4, n); }
void CborWriter::map(size_t n) { head(5, n); }
void CborWriter::tag(uint64_t t) { head(6, t); }
void CborWriter::boolean(bool b) { out_.push_back(b ? 0xF5 : 0xF4); }
void CborWriter::null() { out_.push_back(0xF6); }

// ---------------------------------------------------------------------------------------------------------------
// Decoder

namespace {

bool utf8_valid(const uint8_t* s, size_t n) {
  size_t i = 0;
  while (i < n) {
    uint8_t c = s[i];
    if (c < 0x80) {
      i++;
      continue;
    }
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
      return false;  // continuation byte or 0xF8..0xFF as a lead byte
    }
    if (n - i < len) return false;
    for (size_t k = 1; k < len; k++) {
      uint8_t cc = s[i + k];
      if ((cc & 0xC0) != 0x80) return false;
      cp = (cp << 6) | (cc & 0x3Fu);
    }
    if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
    i += len;
  }
  return true;
}

// half-precision bits -> double bits (exact)
uint64_t half_to_double_bits(uint16_t h) {
  uint64_t sign = uint64_t(h >> 15) << 63;
  int exp = (h >> 10) & 0x1F;
  uint64_t mant = h & 0x3FFu;
  if (exp == 0x1F) return sign | (uint64_t(0x7FF) << 52) | (mant << 42);  // inf / NaN (payload kept)
  if (exp == 0) {
    if (mant == 0) return sign;  // +-0
    // subnormal: value = mant * 2^-24; normalise
    int e = -14;
    while (!(mant & 0x400u)) {
      mant <<= 1;
      e--;
    }
    mant &= 0x3FFu;
    return sign | (uint64_t(e + 1023) << 52) | (mant << 42);
  }
  return sign | (uint64_t(exp - 15 + 1023) << 52) | (mant << 42);
}

// single-precision bits -> double bits (exact)
uint64_t float_to_double_bits(uint32_t f) {
  uint64_t sign = uint64_t(f >> 31) << 63;
  int exp = (f >> 23) & 0xFF;
  uint64_t mant = f & 0x7FFFFFu;
  if (exp == 0xFF) return sign | (uint64_t(0x7FF) << 52) | (mant << 29);
  if (exp == 0) {
    if (mant == 0) return sign;
    int e = -126;
    while (!(mant & 0x800000u)) {
      mant <<= 1;
      e--;
    }
    mant &= 0x7FFFFFu;
    return sign | (uint64_t(e + 1023) << 52) | (mant << 29);
  }
  return sign | (uint64_t(exp - 127 + 1023) << 52) | (mant << 29);
}

bool same_value(const CborVal& a, const CborVal& b) {
  if (a.type != b.type || a.u != b.u) return false;
  if (a.b != b.b) return false;
  if (a.items.size() != b.items.size()) return false;
  for (size_t i = 0; i < a.items.size(); i++)
    if (!same_value(a.items[i], b.items[i])) return false;
  return true;
}

class Parser {
 public:
  Parser(const uint8_t* p, size_t n) : p_(p), n_(n), pos_(0) {}

  bool item(CborVal& v, unsigned depth) {
    uint8_t ib;
    if (!byte(ib)) return fail("truncated: missing initial byte");
    const uint8_t major = ib >> 5;
    const uint8_t ai = ib & 0x1F;

    if (major == 7) return simple(v, ai);

    if (ai == 31) {
      if (major == 2 || major == 3 || major == 4 || major == 5) return fail("indefinite length not supported");
      return fail("malformed: indefinite length on int/tag");
    }
    uint64_t arg;
    if (!argument(ai, arg)) return false;

    switch (major) {
      case 0:
        v.type = CborVal::UInt;
        v.u = arg;
        return true;
      case 1:
        v.type = CborVal::NInt;
        v.u = arg;
        return true;
      case 2:
      case 3: {
        if (arg > uint64_t(n_ - pos_)) return fail("truncated: string longer than input");
        const size_t len = size_t(arg);
        if (major == 3 && !utf8_valid(p_ + pos_, len)) return fail("text is not valid UTF-8");
        v.type = major == 2 ? CborVal::Bytes_ : CborVal::Text;
        v.b.assign(p_ + pos_, p_ + pos_ + len);
        pos_ += len;
        return true;
      }
      case 4:
      case 5: {
        if (depth >= kMaxDepth) return fail("nesting deeper than 8");
        if (arg > kMaxItems) return fail("container has more than 256 entries");
        const size_t count = size_t(arg) * (major == 5 ? 2u : 1u);
        if (count > n_ - pos_) return fail("truncated: container longer than input");  // >= 1 byte per item
        v.type = major == 4 ? CborVal::Array : CborVal::Map;
        v.items.resize(count);
        for (size_t i = 0; i < count; i++) {
          if (!item(v.items[i], depth + 1)) return false;
          if (major == 5 && (i & 1) == 0) {
            for (size_t k = 0; k < i; k += 2)
              if (same_value(v.items[k], v.items[i])) return fail("duplicate map key");
          }
        }
        return true;
      }
      case 6: {
        if (depth >= kMaxDepth) return fail("nesting deeper than 8");
        if (pos_ >= n_) return fail("truncated: tag without content");
        v.type = CborVal::Tag;
        v.u = arg;
        v.items.resize(1);
        return item(v.items[0], depth + 1);
      }
      default:
        return fail("internal");
    }
  }

  bool at_end() const { return pos_ == n_; }
  const std::string& error() const { return err_; }
  size_t pos() const { return pos_; }

 private:
  const uint8_t* p_;
  size_t n_, pos_;
  std::string err_;

  bool fail(const char* m) {
    if (err_.empty()) err_ = m;
    return false;
  }

  bool byte(uint8_t& b) {
    if (pos_ >= n_) return false;
    b = p_[pos_++];
    return true;
  }

  bool be(size_t nbytes, uint64_t& out) {
    if (n_ - pos_ < nbytes) return fail("truncated: argument");
    uint64_t v = 0;
    for (size_t i = 0; i < nbytes; i++) v = (v << 8) | p_[pos_ + i];
    pos_ += nbytes;
    out = v;
    return true;
  }

  bool argument(uint8_t ai, uint64_t& out) {
    if (ai < 24) {
      out = ai;
      return true;
    }
    switch (ai) {
      case 24:
        return be(1, out);
      case 25:
        return be(2, out);
      case 26:
        return be(4, out);
      case 27:
        return be(8, out);
      default:
        return fail("malformed: reserved additional info 28..30");
    }
  }

  bool simple(CborVal& v, uint8_t ai) {
    uint64_t x;
    switch (ai) {
      case 20:
      case 21:
        v.type = CborVal::Bool;
        v.u = ai == 21 ? 1 : 0;
        return true;
      case 22:
        v.type = CborVal::Null;
        return true;
      case 23:
        v.type = CborVal::Undefined;
        return true;
      case 24:
        if (!be(1, x)) return false;
        if (x < 32) return fail("malformed: two-byte simple value < 32");
        return fail("unsupported simple value");
      case 25:
        if (!be(2, x)) return false;
        v.type = CborVal::Float;
        v.u = half_to_double_bits(uint16_t(x));
        return true;
      case 26:
        if (!be(4, x)) return false;
        v.type = CborVal::Float;
        v.u = float_to_double_bits(uint32_t(x));
        return true;
      case 27:
        if (!be(8, x)) return false;
        v.type = CborVal::Float;
        v.u = x;
        return true;
      case 28:
      case 29:
      case 30:
        return fail("malformed: reserved additional info 28..30");
      case 31:
        return fail("malformed: unexpected break");
      default:
        return fail("unsupported simple value");  // 0..19 (unassigned)
    }
  }
};

}  // namespace

bool cbor_decode(const uint8_t* p, size_t n, CborVal& out, std::string* err) {
  if (!p && n) {
    if (err) *err = "null input";
    return false;
  }
  static const uint8_t kEmpty = 0;
  Parser ps(p ? p : &kEmpty, n);
  CborVal v;
  bool ok = ps.item(v, 0);
  if (ok && !ps.at_end()) {
    if (err) *err = "trailing bytes after the item";
    return false;
  }
  if (!ok) {
    if (err) *err = ps.error().empty() ? std::string("truncated") : ps.error();
    return false;
  }
  out = std::move(v);
  if (err) err->clear();
  return true;
}

const CborVal* cbor_get(const CborVal& map, uint64_t key) {
  if (map.type != CborVal::Map) return nullptr;
  for (size_t i = 0; i + 1 < map.items.size(); i += 2) {
    const CborVal& k = map.items[i];
    if (k.type == CborVal::UInt && k.u == key) return &map.items[i + 1];
  }
  return nullptr;
}

}  // namespace ripar
