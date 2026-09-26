// DEPS: hashes util
// Host tests for src/hashes.cpp + src/util.cpp. Expected values: published vectors (FIPS 180-4 / NIST SHA-256
// examples, Ethereum keccak256, zlib crc32 check value, EIP-55 spec) and tools/ref_hashes.py for the aggregates.
#include <string>
#include <vector>

#include "check.h"
#include "hashes.h"
#include "util.h"

using namespace ripar;

static const uint8_t* S(const char* s) { return reinterpret_cast<const uint8_t*>(s); }

// byte i = (i*7 + 3) & 0xff   (same as ref_hashes.pattern)
static std::vector<uint8_t> pattern(size_t n) {
  std::vector<uint8_t> v(n);
  for (size_t i = 0; i < n; i++) v[i] = uint8_t(i * 7 + 3);
  return v;
}

static void test_sha256() {
  CHECK_SECTION("sha256 vectors");
  uint8_t d[32];
  sha256(S(""), 0, d);
  CHECK_EQ_HEX(d, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  sha256(nullptr, 0, d);
  CHECK_EQ_HEX(d, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  sha256(S("abc"), 3, d);
  CHECK_EQ_HEX(d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  const char* m448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";  // 56 bytes: padding spills a block
  sha256(S(m448), std::strlen(m448), d);
  CHECK_EQ_HEX(d, 32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  const char* m896 =
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
  sha256(S(m896), std::strlen(m896), d);
  CHECK_EQ_HEX(d, 32, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");

  // 1,000,000 x 'a', fed in uneven chunks
  {
    std::vector<uint8_t> a(1000000, 'a');
    Sha256 h;
    size_t off = 0, step = 1;
    while (off < a.size()) {
      size_t n = step;
      if (n > a.size() - off) n = a.size() - off;
      h.update(a.data() + off, n);
      off += n;
      step = (step * 3 + 1) % 997 + 1;
    }
    h.final(d);
    CHECK_EQ_HEX(d, 32, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
  }

  CHECK_SECTION("sha256 aggregate lengths 0..300 (ref_hashes.sha256_many(300))");
  {
    std::vector<uint8_t> m = pattern(300), cat;
    for (size_t n = 0; n <= 300; n++) {
      sha256(m.data(), n, d);
      cat.insert(cat.end(), d, d + 32);
    }
    sha256(cat.data(), cat.size(), d);
    CHECK_EQ_HEX(d, 32, "7d917fbd2cf49ddff9ad0a8706bba32d204e92e71d2e369c5a03d6af29278c9f");
  }
  {
    std::vector<uint8_t> m = pattern(5000);
    sha256(m.data(), m.size(), d);
    CHECK_EQ_HEX(d, 32, "34398b85297bf7d9dfb59b8d511d8bbb44ab23e891570e4395e7871475fc8afb");
  }
}

static void test_keccak() {
  CHECK_SECTION("keccak256 vectors");
  uint8_t d[32];
  keccak256(S(""), 0, d);
  CHECK_EQ_HEX(d, 32, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  keccak256(nullptr, 0, d);
  CHECK_EQ_HEX(d, 32, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  keccak256(S("abc"), 3, d);
  CHECK_EQ_HEX(d, 32, "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
  const char* fox = "The quick brown fox jumps over the lazy dog";
  keccak256(S(fox), std::strlen(fox), d);
  CHECK_EQ_HEX(d, 32, "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15");
  const char* ev = "Transfer(address,address,uint256)";
  keccak256(S(ev), std::strlen(ev), d);
  CHECK_EQ_HEX(d, 32, "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");
  const char* sel1 = "transfer(address,uint256)";
  keccak256(S(sel1), std::strlen(sel1), d);
  CHECK_EQ_HEX(d, 4, "a9059cbb");
  const char* sel2 = "approve(address,uint256)";
  keccak256(S(sel2), std::strlen(sel2), d);
  CHECK_EQ_HEX(d, 4, "095ea7b3");
  const char* sel3 = "transferFrom(address,address,uint256)";
  keccak256(S(sel3), std::strlen(sel3), d);
  CHECK_EQ_HEX(d, 4, "23b872dd");

  CHECK_SECTION("keccak256 aggregate lengths 0..300 (ref_hashes.keccak_many(300))");
  {
    std::vector<uint8_t> m = pattern(300), cat;
    for (size_t n = 0; n <= 300; n++) {
      keccak256(m.data(), n, d);
      cat.insert(cat.end(), d, d + 32);
    }
    keccak256(cat.data(), cat.size(), d);
    CHECK_EQ_HEX(d, 32, "2c42f3ea255cc9e489b3111815c1014717c9fe06d269a2b51cbc4d99c5390a8b");
  }
  {
    std::vector<uint8_t> m = pattern(5000);
    keccak256(m.data(), m.size(), d);
    CHECK_EQ_HEX(d, 32, "824a5ee6f1075dbe1500a4f8696fbfe69a13d0fa0310692c5271547474dfaea8");
  }
  {
    std::vector<uint8_t> a(1000000, 'a');
    keccak256(a.data(), a.size(), d);
    CHECK_EQ_HEX(d, 32, "fadae6b49f129bbb812be8407b7b2894f34aecf6dbd1f9b0f0c7e9853098fc96");
  }
}

// incremental update in many chunkings == one shot; final() re-initialises the object
static void test_incremental() {
  CHECK_SECTION("incremental == one-shot, reuse after final");
  std::vector<uint8_t> m = pattern(1000);
  uint8_t ks[32], ss[32], k[32], s[32];
  keccak256(m.data(), m.size(), ks);
  sha256(m.data(), m.size(), ss);
  const size_t chunks[] = {1, 2, 3, 7, 8, 9, 13, 63, 64, 65, 100, 135, 136, 137, 271, 272, 999, 1000};
  Keccak256 kr;  // one object reused across all chunkings
  Sha256 sr;
  bool all_k = true, all_s = true, all_kr = true, all_sr = true;
  for (size_t c : chunks) {
    Keccak256 kh;
    Sha256 sh;
    for (size_t off = 0; off < m.size(); off += c) {
      size_t n = c < m.size() - off ? c : m.size() - off;
      kh.update(m.data() + off, n);
      sh.update(m.data() + off, n);
      kr.update(m.data() + off, n);
      sr.update(m.data() + off, n);
      kh.update(m.data() + off, 0);  // zero-length updates are no-ops
      sh.update(nullptr, 0);
    }
    kh.final(k);
    sh.final(s);
    all_k = all_k && std::memcmp(k, ks, 32) == 0;
    all_s = all_s && std::memcmp(s, ss, 32) == 0;
    kr.final(k);
    sr.final(s);
    all_kr = all_kr && std::memcmp(k, ks, 32) == 0;
    all_sr = all_sr && std::memcmp(s, ss, 32) == 0;
  }
  CHECK(all_k);
  CHECK(all_s);
  CHECK(all_kr);
  CHECK(all_sr);
  // irregular chunk sequence starting unaligned
  {
    Keccak256 kh;
    Sha256 sh;
    size_t off = 0, step = 5;
    while (off < m.size()) {
      size_t n = step < m.size() - off ? step : m.size() - off;
      kh.update(m.data() + off, n);
      sh.update(m.data() + off, n);
      off += n;
      step = (step * 7 + 3) % 150;
    }
    kh.final(k);
    sh.final(s);
    CHECK_EQ_BYTES(k, ks, 32);
    CHECK_EQ_BYTES(s, ss, 32);
  }
  // fresh object after final hashes "" correctly
  {
    Keccak256 kh;
    kh.update(S("junk"), 4);
    kh.final(k);
    kh.final(k);
    CHECK_EQ_HEX(k, 32, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    Sha256 sh;
    sh.update(S("junk"), 4);
    sh.final(s);
    sh.final(s);
    CHECK_EQ_HEX(s, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  }
}

static void test_crc32() {
  CHECK_SECTION("crc32");
  CHECK_EQ(crc32(S("123456789"), 9), 0xCBF43926u);
  CHECK_EQ(crc32(S(""), 0), 0u);
  CHECK_EQ(crc32(nullptr, 0), 0u);
  CHECK_EQ(crc32(S("a"), 1), 0xE8B7BE43u);
  std::vector<uint8_t> m = pattern(1000);
  CHECK_EQ(crc32(m.data(), m.size()), 0x17BC2A46u);
}

static void test_hex() {
  CHECK_SECTION("hex");
  const uint8_t b[] = {0x00, 0x01, 0xab, 0xff, 0x7f};
  CHECK_EQ(to_hex(b, 5), std::string("0x0001abff7f"));
  CHECK_EQ(to_hex(b, 5, false), std::string("0001abff7f"));
  CHECK_EQ(to_hex(b, 0), std::string("0x"));
  CHECK_EQ(to_hex(Bytes(b, b + 5), false), std::string("0001abff7f"));

  Bytes out;
  CHECK(from_hex("0x0001ABff7F", out));
  CHECK_EQ(out.size(), size_t(5));
  CHECK_EQ_BYTES(out.data(), b, 5);
  CHECK(from_hex("0001abff7f", out) && out.size() == 5);
  CHECK(from_hex("0X0a", out) && out.size() == 1 && out[0] == 0x0a);
  CHECK(from_hex("", out) && out.empty());
  CHECK(from_hex("0x", out) && out.empty());

  Bytes keep = {1, 2, 3};
  out = keep;
  CHECK(!from_hex("abc", out));    // odd
  CHECK(!from_hex("0xabc", out));  // odd after prefix
  CHECK(!from_hex("zz", out));
  CHECK(!from_hex("0x0g", out));
  CHECK(!from_hex(" 12", out));
  CHECK(!from_hex("12 ", out));
  CHECK(!from_hex("0x0x12", out));
  CHECK(!from_hex(std::string("1\0", 2), out));
  CHECK(out == keep);  // untouched on failure

  // round trip all byte values
  std::vector<uint8_t> all(256);
  for (int i = 0; i < 256; i++) all[i] = uint8_t(i);
  std::string hx = to_hex(all.data(), all.size());
  CHECK_EQ(hx.size(), size_t(2 + 512));
  CHECK(from_hex(hx, out) && out == all);
  CHECK(from_hex(to_hex(all.data(), all.size(), false), out) && out == all);
}

static Addr addr_from_hex(const char* h) {
  Addr a;
  Bytes b;
  if (from_hex(h, b) && b.size() == 20) std::memcpy(a.v, b.data(), 20);
  return a;
}

static void test_short_addr() {
  CHECK_SECTION("short_addr / EIP-55");
  // EIP-55 spec vectors: first 6 and last 4 chars of the checksummed form
  const char* vec[] = {
      "0x52908400098527886E0F7030069857D2E4169EE7", "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
      "0xde709f2102306220921060314715629080e2fb77", "0x27b1fdb04752bbc536007a920d24acb045561c26",
      "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
      "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
  };
  for (const char* v : vec) {
    std::string full(v);
    CHECK_EQ(short_addr(addr_from_hex(v)), full.substr(0, 6) + "..." + full.substr(38, 4));
  }
  CHECK_EQ(short_addr(addr_from_hex("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")), std::string("0x5aAe...eAed"));
  // addresses keccak256(bytes([i]))[12:], expectations from tools/ref_hashes.py short_addr()
  const char* expect[] = {"0x828f...c98A", "0x057b...Ffd2", "0x245B...B4f2",
                          "0x0553...e287", "0x8748...6393", "0x3657...d795"};
  for (int i = 0; i < 6; i++) {
    uint8_t in = uint8_t(i), h[32];
    keccak256(&in, 1, h);
    Addr a;
    std::memcpy(a.v, h + 12, 20);
    CHECK_EQ(short_addr(a), std::string(expect[i]));
  }
  CHECK_EQ(short_addr(Addr()), std::string("0x0000...0000"));
  Addr ff;
  std::memset(ff.v, 0xff, 20);
  CHECK_EQ(short_addr(ff).size(), size_t(13));
}

static void test_u256() {
  CHECK_SECTION("U256");
  U256 u;
  const uint8_t one[] = {0x01};
  CHECK(U256::from_be(one, 1, u));
  CHECK(u.fits_u64() && u.low_u64() == 1 && !u.is_zero());
  CHECK_EQ(u.cmp(U256::from_u64(1)), 0);

  CHECK(U256::from_be(nullptr, 0, u));
  CHECK(u.is_zero() && u.fits_u64() && u.low_u64() == 0);

  const uint8_t eth[] = {0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00};  // 1e18
  CHECK(U256::from_be(eth, sizeof(eth), u));
  CHECK_EQ(u.low_u64(), uint64_t(1000000000000000000ULL));
  CHECK_EQ(u.cmp(U256::from_u64(1000000000000000000ULL)), 0);
  CHECK_EQ(u.cmp(U256::from_u64(999999999999999999ULL)), 1);
  CHECK_EQ(U256::from_u64(5).cmp(u), -1);

  // leading zeros accepted, value right-aligned
  uint8_t p32[32] = {0};
  p32[31] = 0x2a;
  CHECK(U256::from_be(p32, 32, u) && u.low_u64() == 42 && u.fits_u64());
  const uint8_t lz[] = {0x00, 0x00, 0x2a};
  U256 u2;
  CHECK(U256::from_be(lz, 3, u2) && u2.cmp(u) == 0);

  // 9-byte value: does not fit u64; low_u64 is the low 8 bytes
  const uint8_t big9[] = {0x01, 0, 0, 0, 0, 0, 0, 0, 0x05};
  CHECK(U256::from_be(big9, 9, u));
  CHECK(!u.fits_u64());
  CHECK_EQ(u.low_u64(), uint64_t(5));
  CHECK_EQ(u.cmp(U256::from_u64(~0ULL)), 1);
  CHECK_EQ(U256::from_u64(~0ULL).cmp(u), -1);

  // max value, cmp decided by the most significant byte
  uint8_t mx[32];
  std::memset(mx, 0xff, 32);
  U256 umax;
  CHECK(U256::from_be(mx, 32, umax));
  CHECK(!umax.is_zero() && !umax.fits_u64());
  uint8_t hi[32] = {0};
  hi[0] = 0x80;
  U256 uhi;
  CHECK(U256::from_be(hi, 32, uhi));
  CHECK_EQ(uhi.cmp(umax), -1);
  CHECK_EQ(umax.cmp(uhi), 1);
  CHECK_EQ(uhi.cmp(uhi), 0);
  CHECK(!uhi.fits_u64());
  CHECK_EQ(uhi.low_u64(), uint64_t(0));

  // > 32 bytes is rejected (strict, even with a zero leading byte); out untouched
  uint8_t p33[33] = {0};
  p33[32] = 7;
  U256 keep = U256::from_u64(77);
  CHECK(!U256::from_be(p33, 33, keep));
  CHECK_EQ(keep.low_u64(), uint64_t(77));
  p33[0] = 1;
  CHECK(!U256::from_be(p33, 33, keep));
  CHECK_EQ(keep.low_u64(), uint64_t(77));

  // from_u64 layout
  U256 f = U256::from_u64(0x0102030405060708ULL);
  CHECK_EQ_HEX(f.v, 32, "0000000000000000000000000000000000000000000000000102030405060708");
}

int main() {
  test_sha256();
  test_keccak();
  test_incremental();
  test_crc32();
  test_hex();
  test_short_addr();
  test_u256();
  return CHECK_SUMMARY();
}
