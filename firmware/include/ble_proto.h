// Portable logic of the optional Bluetooth LE fallback link (docs/BLE_LINK.md). C++14, no radio code: host-tested in
// test/host/test_ble_link.cpp. The radio driver around it is src/ble_link.cpp (built only with RIPAR_BLE=1).
//
//   - LineAssembler: the RX characteristic is a byte stream; each '\n'-terminated line is one UR part (exactly the
//     text a QR code would carry). Lines longer than 4096 bytes are dropped whole.
//   - chunk_for_mtu(): TX notifications carry at most MTU - 3 bytes each.
//   - status_json(): the STATUS characteristic (<= 180 bytes of UTF-8 JSON).
//   - IdleTimer: the radio turns itself off after 5 min without link traffic.
//   - auth_outcome(): what an SMP "authentication complete" means for the link (the MITM / user-confirmation rule).
//   - uuid128_le(), adv_name(): the GATT UUIDs in Bluedroid byte order, the advertised name.
#pragma once
#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <vector>

#include "fsm.h"  // Screen

namespace ripar {
namespace blep {

// ---- GATT layout (docs/BLE_LINK.md; the mobile app is built against these values)
constexpr const char* kServiceUuid = "52495041-5200-4c49-4e4b-000000000001";  // "RIPAR LINK"
constexpr const char* kRxUuid = "52495041-5200-4c49-4e4b-000000000002";       // phone -> device, write / write NR
constexpr const char* kTxUuid = "52495041-5200-4c49-4e4b-000000000003";       // device -> phone, notify
constexpr const char* kStatusUuid = "52495041-5200-4c49-4e4b-000000000004";   // read + notify, JSON
constexpr uint16_t kLocalMtu = 247;                                             // requested (local) ATT MTU
constexpr size_t kMaxLine = 4096;       // longest RX line (without the '\n') that is kept
constexpr size_t kMaxStatus = 180;      // STATUS JSON limit
constexpr uint32_t kIdleOffMs = 5u * 60u * 1000u;  // radio off after 5 min without link traffic

// "52495041-5200-4c49-4e4b-000000000001" -> 16 bytes, least significant first (the order Bluedroid and the
// advertising data use). False (out zeroed) if the text is not a 36-character UUID with dashes at 8/13/18/23.
bool uuid128_le(const char* uuid, uint8_t out[16]);

// Advertised name: "RIPAR-" + 4 upper-case hex digits of `rnd` (drawn per enable).
std::string adv_name(uint16_t rnd);

// ---- RX: '\n'-terminated lines from a byte stream (write boundaries are irrelevant)
class LineAssembler {
 public:
  // Appends bytes; every completed line (without '\n', and without one trailing '\r') is appended to `out`.
  // Empty lines are skipped. A line longer than kMaxLine bytes is dropped whole (counted in dropped()).
  void push(const uint8_t* p, size_t n, std::vector<std::string>& out);
  void reset();                       // drops a partial line (link lost / radio off)
  size_t pending() const { return buf_.size(); }
  uint32_t dropped() const { return dropped_; }

 private:
  std::string buf_;
  bool overflow_ = false;
  uint32_t dropped_ = 0;
};

// Bounded FIFO of complete lines between the Bluetooth task and the app loop: at most maxLines lines and maxBytes
// bytes; a line that does not fit is dropped (counted). UR multipart is a fountain code and the phone keeps cycling
// the parts, so a dropped part only costs time.
class LineQueue {
 public:
  LineQueue(size_t maxLines = 32, size_t maxBytes = 64 * 1024) : maxLines_(maxLines), maxBytes_(maxBytes) {}
  bool push(std::string line);  // false = dropped (full)
  bool pop(std::string& line);
  void clear();
  size_t size() const { return q_.size(); }
  uint32_t dropped() const { return dropped_; }

 private:
  std::deque<std::string> q_;
  size_t maxLines_, maxBytes_, bytes_ = 0;
  uint32_t dropped_ = 0;
};

// TX: `text` split into notifications of at most mtu - 3 bytes (mtu below 23 counts as 23, above 517 as 517).
std::vector<std::string> chunk_for_mtu(const std::string& text, uint16_t mtu);

// ---- STATUS
const char* screen_code(Screen s);  // HOME SCAN REVIEW PULSE ARMED QR MESSAGE MENU BLE_PAIR (HomeHold = HOME, ...)

struct StatusInfo {
  Screen screen = Screen::Home;
  bool paired = false;      // the device context is paired (a companion pairing was signed), not the BLE bond
  std::string k1;           // short K1, e.g. "0xAbCd...1234" (empty = no keys)
  unsigned got = 0, of = 0; // UR parts received / expected (only sent on SCAN)
  std::string fw;           // firmware id, 16 hex digits
  std::string note;         // optional short message (e.g. why a line was ignored); cut to fit
};
// {"v":1,"screen":"SCAN","paired":true,"k1":"0x..","scan":{"got":2,"of":5},"radio":"on","fw":"..","note":".."}
// "scan" only on SCAN, "note" only when not empty. Never longer than kMaxStatus bytes (note, then k1 / fw are cut).
std::string status_json(const StatusInfo& s);

// ---- radio auto-off: millis() based, wrap-safe
class IdleTimer {
 public:
  explicit IdleTimer(uint32_t limitMs = kIdleOffMs) : limit_(limitMs) {}
  void start(uint32_t now) { running_ = true; last_ = now; }
  void stop() { running_ = false; }
  void touch(uint32_t now) { if (running_) last_ = now; }
  bool running() const { return running_; }
  bool expired(uint32_t now) const { return running_ && uint32_t(now - last_) >= limit_; }
  uint32_t remaining_ms(uint32_t now) const {
    if (!running_) return 0;
    const uint32_t e = uint32_t(now - last_);
    return e >= limit_ ? 0 : limit_ - e;
  }

 private:
  uint32_t limit_;
  uint32_t last_ = 0;
  bool running_ = false;
};

// ---- link authentication (SMP "authentication complete")
// authMode bits as in the Bluetooth spec / ESP-IDF esp_ble_auth_req_t
constexpr uint8_t kAuthBond = 0x01, kAuthMitm = 0x04, kAuthSc = 0x08;
enum class AuthOutcome : uint8_t {
  Authenticated,      // the link may use the GATT service
  Refuse,             // failed / not MITM: disconnect, nothing stored
  RemoveBond,         // a NEW pairing the user did not confirm on the device (e.g. passkey entry): forget it + drop
};
// success / authMode: from the stack. pairedOnThisLink: an SMP pairing ran on this connection (security request,
// numeric comparison or passkey event seen); userConfirmed: the user pressed SIGN on the code shown on the device
// for this link. A re-encryption with an existing bond (no pairing on this link) is accepted when it is MITM.
AuthOutcome auth_outcome(bool success, uint8_t authMode, bool pairedOnThisLink, bool userConfirmed);

}  // namespace blep
}  // namespace ripar
