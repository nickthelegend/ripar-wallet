// Context NVS blob (include/context.h). Portable C++14 (host + device); depends on hashes (crc32) only, so the
// chk_device environment can link it with store.cpp.
#include "context.h"

#include <cstring>

#include "hashes.h"

namespace ripar {

namespace {

void put_u64(uint8_t* p, uint64_t v) {
  for (int i = 0; i < 8; i++) p[i] = uint8_t(v >> (56 - 8 * i));
}
uint64_t get_u64(const uint8_t* p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
  return v;
}
void put_u32(uint8_t* p, uint32_t v) {
  for (int i = 0; i < 4; i++) p[i] = uint8_t(v >> (24 - 8 * i));
}
uint32_t get_u32(const uint8_t* p) {
  uint32_t v = 0;
  for (int i = 0; i < 4; i++) v = (v << 8) | p[i];
  return v;
}

}  // namespace

void context_serialize(const Context& c, uint8_t out[CONTEXT_BLOB_SIZE]) {
  uint8_t* p = out;
  *p++ = CONTEXT_VERSION;
  put_u64(p, c.chainId);
  p += 8;
  const Addr* addrs[6] = {&c.delegationManager, &c.pulseCosignEnforcer, &c.sentinel, &c.relay, &c.registry, &c.vault};
  for (const Addr* a : addrs) {
    std::memcpy(p, a->v, 20);
    p += 20;
  }
  std::memcpy(p, c.lastDelegationHash.v, 32);
  p += 32;
  *p++ = c.hasAgentId ? 1 : 0;
  put_u64(p, c.agentId);
  p += 8;
  put_u64(p, c.minEpoch);
  p += 8;
  put_u64(p, c.reopenNonce);
  p += 8;
  put_u64(p, c.notBefore);
  p += 8;
  put_u32(p, crc32(out, CONTEXT_BODY_SIZE));
}

bool context_deserialize(const uint8_t* p, size_t n, Context& out) {
  if (!p || n != CONTEXT_BLOB_SIZE) return false;
  if (p[0] != CONTEXT_VERSION) return false;
  if (crc32(p, CONTEXT_BODY_SIZE) != get_u32(p + CONTEXT_BODY_SIZE)) return false;
  Context c;
  const uint8_t* q = p + 1;
  c.chainId = get_u64(q);
  q += 8;
  Addr* addrs[6] = {&c.delegationManager, &c.pulseCosignEnforcer, &c.sentinel, &c.relay, &c.registry, &c.vault};
  for (Addr* a : addrs) {
    std::memcpy(a->v, q, 20);
    q += 20;
  }
  std::memcpy(c.lastDelegationHash.v, q, 32);
  q += 32;
  if (*q > 1) return false;
  c.hasAgentId = *q++ == 1;
  c.agentId = get_u64(q);
  q += 8;
  c.minEpoch = get_u64(q);
  q += 8;
  c.reopenNonce = get_u64(q);
  q += 8;
  c.notBefore = get_u64(q);
  out = c;
  return true;
}

}  // namespace ripar
