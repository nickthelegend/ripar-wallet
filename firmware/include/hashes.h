// Portable SHA-256 and Keccak-256 (Ethereum keccak, NOT SHA3-256). Host + device.
#pragma once
#include <cstddef>
#include <cstdint>

namespace ripar {

class Sha256 {
 public:
  Sha256();
  void update(const uint8_t* data, size_t len);
  void final(uint8_t out[32]);

 private:
  uint32_t h_[8];
  uint64_t bits_;
  uint8_t buf_[64];
  size_t n_;
  void block(const uint8_t* p);
};
void sha256(const uint8_t* data, size_t len, uint8_t out[32]);

class Keccak256 {
 public:
  Keccak256();
  void update(const uint8_t* data, size_t len);
  void final(uint8_t out[32]);  // pad10*1 with domain byte 0x01 (legacy Keccak)

 private:
  uint64_t st_[25];
  size_t pos_;  // byte position in the 136-byte rate
};
void keccak256(const uint8_t* data, size_t len, uint8_t out[32]);

uint32_t crc32(const uint8_t* data, size_t len);  // IEEE 802.3 (zlib), as used by BC-UR

}  // namespace ripar
