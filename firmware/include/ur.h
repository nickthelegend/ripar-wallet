// BC-UR (BCR-2020-005): bytewords (minimal), single- and multi-part (fountain) UR. Host + device.
#pragma once
#include <string>
#include <vector>

#include "util.h"

namespace ripar {

// Minimal bytewords (first+last letter of each word) of payload||crc32(payload), lower-case.
std::string bytewords_minimal_encode(const Bytes& payload);
bool bytewords_minimal_decode(const std::string& s, Bytes& payload);  // verifies and strips the CRC

// Single-part UR string, UPPER-CASE (QR alphanumeric mode), e.g. "UR:RIPAR-COSIGN/AEAD...".
std::string ur_encode(const std::string& type, const Bytes& cbor);

// Collects parts from the camera; accepts upper or lower case, single-part and multipart
// ("ur:type/seq-len/bw"). Multipart fragments are the CBOR array
// [seqNum, seqLen, messageLen, checksum, fragment]; pure parts (seqNum <= seqLen) and mixed fountain parts
// (Xoshiro256** fragment selection as in the BC-UR reference) are both accepted.
class UrDecoder {
 public:
  enum Result { Ignored, Accepted, Complete, Error };
  Result receive(const std::string& part);  // Ignored = not a UR / other type while one is in progress
  bool complete() const { return complete_; }
  const std::string& type() const { return type_; }
  const Bytes& message() const { return message_; }  // CBOR payload once complete
  float progress() const;                            // 0..1
  size_t seq_len() const { return seq_len_; }
  size_t received_pure() const;
  const std::string& error() const { return err_; }
  void reset();

 private:
  bool complete_ = false;
  std::string type_, err_;
  Bytes message_;
  size_t seq_len_ = 0, msg_len_ = 0;
  uint32_t checksum_ = 0;
  size_t frag_len_ = 0;
  std::vector<Bytes> frags_;        // solved pure fragments (empty = unknown)
  struct Mixed {
    std::vector<size_t> idx;
    Bytes data;
  };
  std::vector<Mixed> mixed_;
  void reduce();
  bool try_finish();
};

// Fountain fragment selection (exposed for tests): indexes (0-based) mixed into part seqNum.
std::vector<size_t> ur_choose_fragments(uint32_t seqNum, size_t seqLen, uint32_t checksum);

}  // namespace ripar
