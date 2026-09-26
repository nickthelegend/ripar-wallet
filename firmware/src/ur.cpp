// BC-UR (BCR-2020-005) with minimal bytewords (BCR-2020-012) and the multipart fountain code (BCR-2024-001).
// Portable C++14 (host tests + device).
//
// The fountain fragment selection (Xoshiro256**, the alias-method degree sampler and the shuffle) is a faithful
// port of the Blockchain Commons bc-ur C++ reference (xoshiro256.cpp, random-sampler.cpp, fountain-utils.cpp),
// including its IEEE-754 double arithmetic, so mixed parts produced by any conforming encoder are understood.
// It is checked against the official bc-ur test vectors in test/host/test_cbor_ur.cpp.
//
// The decoder keeps the received parts as a GF(2) system in reduced row-echelon form (solved fragments in frags_,
// the remaining independent mixed rows in mixed_). It therefore finishes as soon as the parts received so far
// determine the message (never later than the reference decoder), and needs at most seqLen rows of storage.
//
// Receive policy (camera input is untrusted):
//  - anything not starting with "ur:" (any case) -> Ignored; a UR of another type while a multipart message is
//    being collected -> Ignored; anything once complete() -> Ignored (call reset() to start over)
//  - a malformed part (bad path, bytewords CRC, CBOR shape, inconsistent lengths, limits) -> Error; the parts
//    collected so far are kept, so one bad frame never loses progress
//  - a multipart part whose seqLen / messageLen / checksum / fragment length differ from the message being
//    collected starts over with the new message (the old parts are dropped, never mixed) -> Accepted
//  - a single-part UR of the expected type completes immediately (as in the reference decoder)
//  - when all fragments are known the message is truncated to messageLen and its CRC-32 must equal the checksum;
//    otherwise -> Error and the collected state is dropped
#include "ur.h"

#include <algorithm>
#include <cstring>

#include "cbor.h"
#include "hashes.h"

// The fountain part selection depends on exact IEEE double rounding. The 32-bit MinGW host compiler defaults to
// x87 math (80-bit intermediates, FLT_EVAL_METHOD 2), which can round differently from the reference; use SSE2
// scalar double math there. (The ESP32-S3 has no double FPU: libgcc soft-float is exact IEEE double.)
#if defined(__GNUC__) && !defined(__clang__) && defined(__i386__) && !defined(__SSE2_MATH__)
#pragma GCC target("sse2", "fpmath=sse")
#endif

namespace ripar {

namespace {

// Limits for a multipart message (Ripar requests are well below 2 KB).
const size_t kMaxMessageLen = 8192;
const size_t kMaxSeqLen = 128;

// The 256 bytewords (BCR-2020-012), same string as bc-ur src/bytewords.cpp. Minimal form = first + last letter.
const char kWords[] =
    "ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabiasbluebodybragbrewbulbbuzzcalmcashcatschefcity"
    "clawcodecolacookcostcruxcurlcuspcyandarkdatadaysdelidicedietdoordowndrawdropdrumdulldutyeacheasyechoedgeepic"
    "evenexamexiteyesfactfairfernfigsfilmfishfizzflapflewfluxfoxyfreefrogfuelfundgalagamegeargemsgiftgirlglowgood"
    "graygrimgurugushgyrohalfhanghardhawkheathelphighhillholyhopehornhutsicedideaidleinchinkyintoirisironitemjade"
    "jazzjoinjoltjowljudojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwiknoblamblavalazyleaflegsliarlimplion"
    "listlogoloudloveluaulucklungmainmanymathmazememomenumeowmildmintmissmonknailnavyneednewsnextnoonnotenumbobey"
    "oboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolposepuffpumapurrquadquizraceramprealredorichroadrockroof"
    "rubyruinrunsrustsafesagascarsetssilkskewslotsoapsolosongstubsurfswantacotasktaxitenttiedtimetinytoiltombtoys"
    "triptunatwinuglyundouniturgeuservastveryvetovialvibeviewvisavoidvowswallwandwarmwaspwavewaxywebswhatwhenwhiz"
    "wolfworkyankyawnyellyogayurtzapszerozestzinczonezoom";
static_assert(sizeof(kWords) == 1024 + 1, "bytewords table must hold 256 four-letter words");

struct MinTable {
  int16_t v[26 * 26];
  MinTable() {
    for (int i = 0; i < 26 * 26; i++) v[i] = -1;
    for (int b = 0; b < 256; b++) v[(kWords[b * 4] - 'a') * 26 + (kWords[b * 4 + 3] - 'a')] = int16_t(b);
  }
};

const MinTable& min_table() {
  static const MinTable t;
  return t;
}

inline char lower_c(char c) { return (c >= 'A' && c <= 'Z') ? char(c - 'A' + 'a') : c; }
inline char upper_c(char c) { return (c >= 'a' && c <= 'z') ? char(c - 'a' + 'A') : c; }

// -1 if not a minimal byteword (case-insensitive)
int min_word(char a, char b) {
  a = lower_c(a);
  b = lower_c(b);
  if (a < 'a' || a > 'z' || b < 'a' || b > 'z') return -1;
  return min_table().v[(a - 'a') * 26 + (b - 'a')];
}

void put_be32(uint8_t* p, uint32_t v) {
  p[0] = uint8_t(v >> 24);
  p[1] = uint8_t(v >> 16);
  p[2] = uint8_t(v >> 8);
  p[3] = uint8_t(v);
}

// ---- Xoshiro256** as in bc-ur xoshiro256.cpp ----
class Xoshiro256 {
 public:
  Xoshiro256(const uint8_t* seed, size_t n) {
    uint8_t d[32];
    sha256(seed, n, d);
    for (int i = 0; i < 4; i++) {
      uint64_t v = 0;
      for (int k = 0; k < 8; k++) v = (v << 8) | d[i * 8 + k];
      s_[i] = v;
    }
  }
  uint64_t next() {
    const uint64_t result = rotl(s_[1] * 5, 7) * 9;
    const uint64_t t = s_[1] << 17;
    s_[2] ^= s_[0];
    s_[3] ^= s_[1];
    s_[1] ^= s_[2];
    s_[0] ^= s_[3];
    s_[2] ^= t;
    s_[3] = rotl(s_[3], 45);
    return result;
  }
  // next() / ((double)UINT64_MAX + 1), i.e. / 2^64
  double next_double() {
    const double m = 18446744073709551616.0;
    return double(next()) / m;
  }
  uint64_t next_int(uint64_t low, uint64_t high) { return uint64_t(next_double() * double(high - low + 1)) + low; }

 private:
  uint64_t s_[4];
  static uint64_t rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
};

// ---- degree chooser: bc-ur RandomSampler (Vose alias method) over weights 1/1 .. 1/seqLen ----
size_t choose_degree(size_t seq_len, Xoshiro256& rng) {
  const int n = int(seq_len);
  std::vector<double> P(seq_len);
  double sum = 0.0;
  for (int i = 1; i <= n; i++) {
    P[size_t(i - 1)] = 1.0 / double(i);
    sum += P[size_t(i - 1)];  // std::accumulate order: left to right, starting from 0.0
  }
  for (int i = 0; i < n; i++) P[size_t(i)] = P[size_t(i)] * double(n) / sum;

  std::vector<int> S, L;
  S.reserve(seq_len);
  L.reserve(seq_len);
  for (int i = n - 1; i >= 0; i--) {  // reversed index order (bc-ur variant)
    if (P[size_t(i)] < 1)
      S.push_back(i);
    else
      L.push_back(i);
  }
  std::vector<double> probs(seq_len, 0.0);
  std::vector<int> aliases(seq_len, 0);
  while (!S.empty() && !L.empty()) {
    const int a = S.back();
    S.pop_back();
    const int g = L.back();
    L.pop_back();
    probs[size_t(a)] = P[size_t(a)];
    aliases[size_t(a)] = g;
    P[size_t(g)] += P[size_t(a)] - 1;
    if (P[size_t(g)] < 1)
      S.push_back(g);
    else
      L.push_back(g);
  }
  while (!L.empty()) {
    probs[size_t(L.back())] = 1;
    L.pop_back();
  }
  while (!S.empty()) {  // only through numeric instability
    probs[size_t(S.back())] = 1;
    S.pop_back();
  }

  const double r1 = rng.next_double();
  const double r2 = rng.next_double();
  int i = int(double(n) * r1);
  if (i < 0) i = 0;  // defensive; r1 is in [0, 1)
  if (i >= n) i = n - 1;
  const int pick = r2 < probs[size_t(i)] ? i : aliases[size_t(i)];
  return size_t(pick) + 1;
}

// ---- small helpers for the GF(2) rows ----
bool has_index(const std::vector<size_t>& v, size_t x) { return std::binary_search(v.begin(), v.end(), x); }

void xor_into(Bytes& dst, const Bytes& src) {
  const size_t n = std::min(dst.size(), src.size());
  for (size_t i = 0; i < n; i++) dst[i] ^= src[i];
}

std::vector<size_t> sym_diff(const std::vector<size_t>& a, const std::vector<size_t>& b) {
  std::vector<size_t> r;
  r.reserve(a.size() + b.size());
  std::set_symmetric_difference(a.begin(), a.end(), b.begin(), b.end(), std::back_inserter(r));
  return r;
}

bool valid_type(const std::string& t) {
  if (t.empty()) return false;
  for (char c : t)
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
  return true;
}

// "N-M" with decimal N, M in [1, 2^32-1]
bool parse_seq(const std::string& s, uint32_t& num, uint32_t& len) {
  const size_t dash = s.find('-');
  if (dash == std::string::npos || dash == 0 || dash + 1 >= s.size()) return false;
  uint64_t v[2] = {0, 0};
  const std::string parts[2] = {s.substr(0, dash), s.substr(dash + 1)};
  for (int k = 0; k < 2; k++) {
    if (parts[k].empty() || parts[k].size() > 10) return false;
    for (char c : parts[k]) {
      if (c < '0' || c > '9') return false;
      v[k] = v[k] * 10 + uint64_t(c - '0');
    }
    if (v[k] == 0 || v[k] > 0xFFFFFFFFu) return false;
  }
  num = uint32_t(v[0]);
  len = uint32_t(v[1]);
  return true;
}

}  // namespace

// ---------------------------------------------------------------------------------------------------------------
// Bytewords

std::string bytewords_minimal_encode(const Bytes& payload) {
  std::string s;
  s.reserve((payload.size() + 4) * 2);
  uint8_t crc[4];
  put_be32(crc, crc32(payload.data(), payload.size()));
  for (size_t i = 0; i < payload.size() + 4; i++) {
    const uint8_t b = i < payload.size() ? payload[i] : crc[i - payload.size()];
    s += kWords[b * 4];
    s += kWords[b * 4 + 3];
  }
  return s;
}

bool bytewords_minimal_decode(const std::string& s, Bytes& payload) {
  if (s.size() % 2 != 0 || s.size() < 2 * 5) return false;  // at least one payload byte + 4 CRC bytes
  Bytes buf;
  buf.reserve(s.size() / 2);
  for (size_t i = 0; i < s.size(); i += 2) {
    const int b = min_word(s[i], s[i + 1]);
    if (b < 0) return false;
    buf.push_back(uint8_t(b));
  }
  const size_t n = buf.size() - 4;
  uint8_t crc[4];
  put_be32(crc, crc32(buf.data(), n));
  if (std::memcmp(crc, buf.data() + n, 4) != 0) return false;
  buf.resize(n);
  payload.swap(buf);
  return true;
}

std::string ur_encode(const std::string& type, const Bytes& cbor) {
  std::string s = "UR:";
  for (char c : type) s += upper_c(c);
  s += '/';
  const std::string bw = bytewords_minimal_encode(cbor);
  for (char c : bw) s += upper_c(c);
  return s;
}

// ---------------------------------------------------------------------------------------------------------------
// Fountain fragment selection (bc-ur fountain-utils.cpp choose_fragments), sorted ascending

std::vector<size_t> ur_choose_fragments(uint32_t seqNum, size_t seqLen, uint32_t checksum) {
  std::vector<size_t> out;
  if (seqLen == 0 || seqNum == 0) return out;
  if (size_t(seqNum) <= seqLen) {
    out.push_back(size_t(seqNum) - 1);
    return out;
  }
  uint8_t seed[8];
  put_be32(seed, seqNum);
  put_be32(seed + 4, checksum);
  Xoshiro256 rng(seed, sizeof seed);
  const size_t degree = choose_degree(seqLen, rng);
  // shuffled(indexes, rng), keeping only the first `degree` picks (later picks cannot change them)
  std::vector<size_t> remaining(seqLen);
  for (size_t i = 0; i < seqLen; i++) remaining[i] = i;
  out.reserve(degree);
  while (out.size() < degree && !remaining.empty()) {
    size_t idx = size_t(rng.next_int(0, uint64_t(remaining.size() - 1)));
    if (idx >= remaining.size()) idx = remaining.size() - 1;  // defensive
    out.push_back(remaining[idx]);
    remaining.erase(remaining.begin() + std::ptrdiff_t(idx));
  }
  std::sort(out.begin(), out.end());
  return out;
}

// ---------------------------------------------------------------------------------------------------------------
// Decoder

void UrDecoder::reset() {
  complete_ = false;
  type_.clear();
  err_.clear();
  message_.clear();
  seq_len_ = msg_len_ = frag_len_ = 0;
  checksum_ = 0;
  frags_.clear();
  mixed_.clear();
}

size_t UrDecoder::received_pure() const {
  size_t n = 0;
  for (const Bytes& f : frags_)
    if (!f.empty()) n++;
  return n;
}

float UrDecoder::progress() const {
  if (complete_) return 1.0f;
  if (seq_len_ == 0) return 0.0f;
  // rank of the received system / number of fragments (reaches 1 exactly when the message is determined)
  const float p = float(received_pure() + mixed_.size()) / float(seq_len_);
  return p > 1.0f ? 1.0f : p;
}

// Inserts the row mixed_.back() into the reduced row-echelon system.
// Invariants: every mixed_ row has >= 2 indexes, sorted, none of them solved; its pivot is idx[0] and no other row
// contains that pivot.
void UrDecoder::reduce() {
  if (mixed_.empty()) return;
  Mixed r = std::move(mixed_.back());
  mixed_.pop_back();

  // 1. substitute the solved fragments
  std::vector<size_t> keep;
  keep.reserve(r.idx.size());
  for (size_t i : r.idx) {
    if (i < frags_.size() && !frags_[i].empty())
      xor_into(r.data, frags_[i]);
    else
      keep.push_back(i);
  }
  r.idx.swap(keep);
  // 2. eliminate the existing pivots (their rows never contain another pivot, so one pass suffices)
  for (const Mixed& m : mixed_) {
    if (has_index(r.idx, m.idx[0])) {
      r.idx = sym_diff(r.idx, m.idx);
      xor_into(r.data, m.data);
    }
  }
  if (r.idx.empty()) return;  // nothing new (duplicate or linearly dependent part)

  if (r.idx.size() == 1) {
    // 3a. a new fragment: remove it from every row; rows left with only their pivot are solved too
    const size_t f = r.idx[0];
    frags_[f] = std::move(r.data);
    for (size_t k = 0; k < mixed_.size();) {
      Mixed& m = mixed_[k];
      std::vector<size_t>::iterator it = std::lower_bound(m.idx.begin(), m.idx.end(), f);
      if (it != m.idx.end() && *it == f) {
        m.idx.erase(it);
        xor_into(m.data, frags_[f]);
        if (m.idx.size() == 1) {
          frags_[m.idx[0]] = std::move(m.data);
          mixed_.erase(mixed_.begin() + std::ptrdiff_t(k));
          continue;
        }
      }
      k++;
    }
    return;
  }

  // 3b. a new pivot q: eliminate it from the other rows, then keep r
  const size_t q = r.idx[0];
  for (size_t k = 0; k < mixed_.size();) {
    Mixed& m = mixed_[k];
    if (has_index(m.idx, q)) {
      m.idx = sym_diff(m.idx, r.idx);  // m's pivot is < q, so it stays m's smallest index
      xor_into(m.data, r.data);
      if (m.idx.size() == 1) {
        frags_[m.idx[0]] = std::move(m.data);
        mixed_.erase(mixed_.begin() + std::ptrdiff_t(k));
        continue;
      }
    }
    k++;
  }
  mixed_.push_back(std::move(r));
}

// All fragments are known: assemble, strip the padding, verify the message CRC.
bool UrDecoder::try_finish() {
  if (seq_len_ == 0 || frags_.size() != seq_len_) return false;
  for (const Bytes& f : frags_)
    if (f.size() != frag_len_) return false;
  Bytes msg;
  msg.reserve(seq_len_ * frag_len_);
  for (const Bytes& f : frags_) msg.insert(msg.end(), f.begin(), f.end());
  msg.resize(msg_len_);
  if (crc32(msg.data(), msg.size()) != checksum_) {
    reset();
    err_ = "message checksum mismatch";
    return false;
  }
  message_.swap(msg);
  complete_ = true;
  std::vector<Bytes>().swap(frags_);
  std::vector<Mixed>().swap(mixed_);
  err_.clear();
  return true;
}

UrDecoder::Result UrDecoder::receive(const std::string& part) {
  if (part.size() < 3 || lower_c(part[0]) != 'u' || lower_c(part[1]) != 'r' || part[2] != ':') return Ignored;
  if (complete_) return Ignored;

  std::string s(part);
  for (char& c : s) c = lower_c(c);
  const size_t p1 = s.find('/', 3);
  if (p1 == std::string::npos) {
    err_ = "UR has no '/'";
    return Error;
  }
  const std::string type = s.substr(3, p1 - 3);
  if (!valid_type(type)) {
    err_ = "invalid UR type";
    return Error;
  }
  const bool in_progress = seq_len_ != 0;
  if (in_progress && type != type_) return Ignored;

  const size_t p2 = s.find('/', p1 + 1);
  if (p2 == std::string::npos) {
    // single-part UR
    Bytes body;
    if (!bytewords_minimal_decode(s.substr(p1 + 1), body)) {
      err_ = "bad bytewords or checksum";
      return Error;
    }
    reset();
    type_ = type;
    message_.swap(body);
    complete_ = true;
    return Complete;
  }
  if (s.find('/', p2 + 1) != std::string::npos) {
    err_ = "too many UR path components";
    return Error;
  }
  uint32_t path_num = 0, path_len = 0;
  if (!parse_seq(s.substr(p1 + 1, p2 - p1 - 1), path_num, path_len)) {
    err_ = "bad sequence component";
    return Error;
  }
  Bytes pc;
  if (!bytewords_minimal_decode(s.substr(p2 + 1), pc)) {
    err_ = "bad bytewords or checksum";
    return Error;
  }
  CborVal v;
  std::string cerr;
  if (!cbor_decode(pc, v, &cerr)) {
    err_ = "part CBOR: " + cerr;
    return Error;
  }
  if (v.type != CborVal::Array || v.items.size() != 5 || v.items[0].type != CborVal::UInt ||
      v.items[1].type != CborVal::UInt || v.items[2].type != CborVal::UInt || v.items[3].type != CborVal::UInt ||
      v.items[4].type != CborVal::Bytes_) {
    err_ = "part is not [seqNum, seqLen, messageLen, checksum, fragment]";
    return Error;
  }
  const uint64_t seq_num = v.items[0].u, seq_len = v.items[1].u, msg_len = v.items[2].u, sum = v.items[3].u;
  const Bytes& frag = v.items[4].b;
  if (seq_num == 0 || seq_num > 0xFFFFFFFFu || sum > 0xFFFFFFFFu) {
    err_ = "part seqNum/checksum out of range";
    return Error;
  }
  if (seq_len == 0 || seq_len > kMaxSeqLen || msg_len == 0 || msg_len > kMaxMessageLen || frag.empty()) {
    err_ = "part lengths out of range";
    return Error;
  }
  if ((msg_len + frag.size() - 1) / frag.size() != seq_len) {
    err_ = "part lengths inconsistent";
    return Error;
  }
  if (seq_num != path_num || seq_len != path_len) {
    err_ = "part sequence does not match its UR path";
    return Error;
  }

  if (in_progress && (seq_len != seq_len_ || msg_len != msg_len_ || sum != checksum_ || frag.size() != frag_len_)) {
    reset();  // a different message: start over with it (parts of the two are never mixed)
  }
  if (seq_len_ == 0) {
    reset();
    type_ = type;
    seq_len_ = size_t(seq_len);
    msg_len_ = size_t(msg_len);
    checksum_ = uint32_t(sum);
    frag_len_ = frag.size();
    frags_.assign(seq_len_, Bytes());
  }
  err_.clear();

  Mixed row;
  row.idx = ur_choose_fragments(uint32_t(seq_num), seq_len_, checksum_);
  row.data = frag;
  mixed_.push_back(std::move(row));
  reduce();

  if (received_pure() == seq_len_) return try_finish() ? Complete : Error;
  return Accepted;
}

}  // namespace ripar
