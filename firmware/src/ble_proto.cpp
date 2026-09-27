// Portable logic of the Bluetooth LE fallback link (include/ble_proto.h). No radio code; host-tested in
// test/host/test_ble_link.cpp.
#include "ble_proto.h"

#include <cstdio>
#include <cstring>

namespace ripar {
namespace blep {

namespace {

int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// JSON string body: printable ASCII only (the values are device-made; anything else becomes '?'), " and \ escaped
std::string json_str(const std::string& s) {
  std::string o;
  o.reserve(s.size() + 2);
  for (unsigned char c : s) {
    if (c == '"' || c == '\\') {
      o += '\\';
      o += char(c);
    } else if (c >= 0x20 && c < 0x7F) {
      o += char(c);
    } else {
      o += '?';
    }
  }
  return o;
}

std::string build_status(const StatusInfo& s, const std::string& k1, const std::string& fw, const std::string& note) {
  std::string j = "{\"v\":1,\"screen\":\"";
  j += screen_code(s.screen);
  j += "\",\"paired\":";
  j += s.paired ? "true" : "false";
  j += ",\"k1\":\"" + json_str(k1) + "\"";
  if (s.screen == Screen::Scan) {
    char b[48];
    std::snprintf(b, sizeof b, ",\"scan\":{\"got\":%u,\"of\":%u}", s.got, s.of);
    j += b;
  }
  j += ",\"radio\":\"on\",\"fw\":\"" + json_str(fw) + "\"";
  if (!note.empty()) j += ",\"note\":\"" + json_str(note) + "\"";
  j += "}";
  return j;
}

}  // namespace

bool uuid128_le(const char* uuid, uint8_t out[16]) {
  std::memset(out, 0, 16);
  if (!uuid || std::strlen(uuid) != 36) return false;
  uint8_t be[16];
  int n = 0;
  for (int i = 0; i < 36; i++) {
    const char c = uuid[i];
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (c != '-') return false;
      continue;
    }
    const int hi = hexval(c), lo = (i + 1 < 36) ? hexval(uuid[i + 1]) : -1;
    if (hi < 0 || lo < 0 || n >= 16) return false;
    be[n++] = uint8_t(hi << 4 | lo);
    i++;
  }
  if (n != 16) return false;
  for (int i = 0; i < 16; i++) out[i] = be[15 - i];
  return true;
}

std::string adv_name(uint16_t rnd) {
  char b[16];
  std::snprintf(b, sizeof b, "RIPAR-%04X", unsigned(rnd));
  return b;
}

// ---------------------------------------------------------------------------------------------- LineAssembler
void LineAssembler::push(const uint8_t* p, size_t n, std::vector<std::string>& out) {
  for (size_t i = 0; i < n; i++) {
    const char c = char(p[i]);
    if (c == '\n') {
      if (!overflow_) {
        if (!buf_.empty() && buf_.back() == '\r') buf_.pop_back();
        if (!buf_.empty()) out.push_back(buf_);
      }
      buf_.clear();
      overflow_ = false;
      continue;
    }
    if (overflow_) continue;
    if (buf_.size() >= kMaxLine) {  // this byte makes the line longer than kMaxLine: drop the whole line
      overflow_ = true;
      dropped_++;
      std::string().swap(buf_);
      continue;
    }
    buf_ += c;
  }
}

void LineAssembler::reset() {
  std::string().swap(buf_);
  overflow_ = false;
}

// ---------------------------------------------------------------------------------------------- LineQueue
bool LineQueue::push(std::string line) {
  if (q_.size() >= maxLines_ || bytes_ + line.size() > maxBytes_) {
    dropped_++;
    return false;
  }
  bytes_ += line.size();
  q_.push_back(std::move(line));
  return true;
}

bool LineQueue::pop(std::string& line) {
  if (q_.empty()) return false;
  line = std::move(q_.front());
  q_.pop_front();
  bytes_ -= line.size();
  return true;
}

void LineQueue::clear() {
  q_.clear();
  bytes_ = 0;
}

// ---------------------------------------------------------------------------------------------- TX chunks
std::vector<std::string> chunk_for_mtu(const std::string& text, uint16_t mtu) {
  if (mtu < 23) mtu = 23;
  if (mtu > 517) mtu = 517;
  const size_t max = size_t(mtu) - 3;
  std::vector<std::string> out;
  for (size_t i = 0; i < text.size(); i += max) out.push_back(text.substr(i, max));
  return out;
}

// ---------------------------------------------------------------------------------------------- STATUS
const char* screen_code(Screen s) {
  switch (s) {
    case Screen::Home:
    case Screen::HomeHold:
      return "HOME";
    case Screen::Scan:
      return "SCAN";
    case Screen::Review:
      return "REVIEW";
    case Screen::Pulse:
      return "PULSE";
    case Screen::Armed:
      return "ARMED";
    case Screen::Qr:
    case Screen::PairQr:
      return "QR";
    case Screen::Menu:
      return "MENU";
    case Screen::BlePair:
      return "BLE_PAIR";
    case Screen::Message:
    case Screen::Fail:
      return "MESSAGE";
  }
  return "MESSAGE";
}

std::string status_json(const StatusInfo& s) {
  std::string k1 = s.k1.size() > 24 ? s.k1.substr(0, 24) : s.k1;
  std::string fw = s.fw.size() > 16 ? s.fw.substr(0, 16) : s.fw;
  std::string j = build_status(s, k1, fw, std::string());
  if (j.size() > kMaxStatus) return j;  // cannot happen with the caps above (max ~150 bytes)
  if (!s.note.empty()) {
    // ,"note":"" costs 10 bytes; escaping can double a character, so cut until it fits
    const size_t room = kMaxStatus - j.size();
    if (room > 10) {
      std::string note = s.note.substr(0, room - 10);
      std::string withNote = build_status(s, k1, fw, note);
      while (withNote.size() > kMaxStatus && !note.empty()) {
        note.pop_back();
        withNote = build_status(s, k1, fw, note);
      }
      if (!note.empty()) j = withNote;
    }
  }
  return j;
}

// ---------------------------------------------------------------------------------------------- auth
AuthOutcome auth_outcome(bool success, uint8_t authMode, bool pairedOnThisLink, bool userConfirmed) {
  if (!success) return AuthOutcome::Refuse;
  const bool mitm = (authMode & kAuthMitm) != 0;
  if (pairedOnThisLink) {
    // a new bond counts only after the user confirmed the code on the device (numeric comparison, MITM);
    // anything else that got through (passkey entry typed on the phone, Just Works) is forgotten again
    if (!userConfirmed || !mitm) return AuthOutcome::RemoveBond;
    return AuthOutcome::Authenticated;
  }
  // re-encryption with a stored bond: only bonds made under the rule above exist (the stack only accepts LE Secure
  // Connections + MITM pairings), but the link must still report MITM
  return mitm ? AuthOutcome::Authenticated : AuthOutcome::Refuse;
}

}  // namespace blep
}  // namespace ripar
