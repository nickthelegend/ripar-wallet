// Portable logic of the Wi-Fi test link (docs/WIFI_LINK.md). TEMPORARY TEST FEATURE: Ripar's pitch is the air-gapped
// signer; this link exists only in env:ripar (RIPAR_WIFI=1) for testing and goes away with that flag. C++14, no radio
// code: host-tested in test/host/test_wifi_link.cpp. The driver around it is src/wifi_link.cpp.
//
//   - parse_prov(): the Bluetooth PROV characteristic's JSON {"v":1,"ssid":"...","pass":"..."} (strict)
//   - code_from_random() / code_equal() / FailLimiter: the per-boot 8-digit link code shown on the device, compared in
//     constant time, with an exponential lock-out after failed attempts
//   - HttpReader / HttpLink / http_serialize(): a deliberately small HTTP/1.1 server core (one request per
//     connection, bounded head and body, the code checked BEFORE any body byte is read) and the three routes
//     GET /status, POST /rx, GET /tx. The Arduino WebServer class is not used: it reads a whole POST body of any size
//     (before any handler, so before authentication) with blocking waits on the caller's task.
#pragma once
#include <cstddef>
#include <cstdint>
#include <string>

namespace ripar {
namespace wifip {

// ---- credentials (PROV characteristic, NVS namespace "ripar-wifi")
constexpr size_t kMaxProv = 512;  // longest PROV value (JSON bytes)
constexpr size_t kMaxSsid = 32;   // SSID: 1..32 bytes (UTF-8, no control characters)
constexpr size_t kMinPass = 8;    // passphrase: "" (open network) or 8..63 printable ASCII characters
constexpr size_t kMaxPass = 63;

struct Creds {
  std::string ssid;
  std::string pass;
  void wipe();  // overwrites both strings, then empties them
};

// Overwrites the characters of `s`, then empties it.
void wipe_str(std::string& s);

// {"v":1,"ssid":"...","pass":"..."}: strict JSON (json_strict.h), exactly these three members, v = 1 (the number),
// ssid 1..32 bytes without control characters, pass "" or 8..63 printable ASCII. At most kMaxProv bytes. On failure
// `out` is left empty and `err` says why (never containing the password).
bool parse_prov(const uint8_t* p, size_t n, Creds& out, std::string& err);
inline bool parse_prov(const std::string& s, Creds& out, std::string& err) {
  return parse_prov(reinterpret_cast<const uint8_t*>(s.data()), s.size(), out, err);
}

// The SSID as the device shows it: printable ASCII kept, every other byte '?'. *altered = a byte was replaced.
std::string ssid_display(const std::string& ssid, bool* altered = nullptr);

// ---- link code: 8 decimal digits, drawn per boot from the TRNG, shown only on the device screen
constexpr size_t kCodeLen = 8;
// r -> 8 digits (r mod 10^8, zero-padded). False (out unchanged) for r >= 4 200 000 000: draw again (no modulo bias).
bool code_from_random(uint32_t r, std::string& out);
// Constant time in the code: every one of its 8 digits is compared whatever `given` holds.
bool code_equal(const std::string& given, const std::string& code);
std::string code_display(const std::string& code);  // "12345678" -> "1234 5678"

// Failed-code lock-out: kFree failures are free, then every further failure locks the link for 1 s, 2 s, 4 s, ...
// up to 300 s. While locked no code is compared (HTTP 429). A correct code resets the count. millis() based, wrap-safe.
class FailLimiter {
 public:
  static constexpr unsigned kFree = 3;
  static constexpr uint32_t kBaseMs = 1000;
  static constexpr uint32_t kMaxMs = 300000;
  bool locked(uint32_t now) const { return lockMs_ != 0 && uint32_t(now - since_) < lockMs_; }
  uint32_t retry_after_ms(uint32_t now) const;  // 0 = not locked
  void fail(uint32_t now);
  void success() { fails_ = 0; lockMs_ = 0; }
  unsigned fails() const { return fails_; }
  uint32_t total_fails() const { return total_; }

 private:
  unsigned fails_ = 0;
  uint32_t total_ = 0;
  uint32_t since_ = 0, lockMs_ = 0;
};

// mDNS host name "ripar-" + the last two bytes of the Wi-Fi station MAC, lower-case hex ("ripar-3f9a" ->
// ripar-3f9a.local).
std::string mdns_host(const uint8_t mac[6]);

// ---- HTTP (docs/WIFI_LINK.md section 4)
constexpr uint16_t kHttpPort = 80;
constexpr size_t kMaxHead = 2048;      // request line + headers, incl. the empty line
constexpr size_t kMaxBody = 16384;     // POST /rx body
constexpr size_t kMaxRxLine = 4096;    // one UR part (as the BLE RX line limit)
constexpr uint32_t kRequestMs = 5000;  // the whole request must arrive within 5 s of the connection
constexpr const char* kCodeHeader = "X-Ripar-Code";

// One request per connection. feed() takes what arrives; the head is parsed as soon as it is complete. Nothing after
// the head counts until want_body() (the caller authenticates and routes first).
class HttpReader {
 public:
  enum Stage : uint8_t {
    Head,      // reading the request line + headers
    HeadDone,  // head parsed: method(), path(), code, content_length() valid; call want_body() or answer now
    Body,      // reading content_length() body bytes
    Done,      // body complete
    Bad,       // malformed / too large: answer bad_status() and close
  };
  void feed(const uint8_t* p, size_t n);
  Stage stage() const { return stage_; }
  int bad_status() const { return bad_; }  // 400, 431 (head too large), 501 (Transfer-Encoding), 505 (version)
  const std::string& method() const { return method_; }
  const std::string& path() const { return path_; }  // without "?query"
  bool has_code() const { return hasCode_; }
  const std::string& code() const { return code_; }
  long content_length() const { return contentLength_; }  // -1 = no Content-Length header
  void want_body(size_t n);  // HeadDone -> Body (or Done when n bytes are already here); n <= kMaxBody
  const std::string& body() const { return body_; }
  void wipe();  // back to a fresh reader, buffers overwritten

 private:
  void parse_head();
  void fail(int status) {
    stage_ = Bad;
    bad_ = status;
  }
  Stage stage_ = Head;
  int bad_ = 0;
  std::string head_, body_;
  size_t want_ = 0;
  std::string method_, path_, code_;
  bool hasCode_ = false;
  long contentLength_ = -1;
};

struct HttpResponse {
  int status = 500;
  std::string type;          // Content-Type ("" = none)
  std::string body;
  uint32_t retryAfterS = 0;  // 429: Retry-After
  const char* allow = nullptr;  // 405: Allow
};
const char* http_reason(int status);
// HTTP/1.1 status line + Content-Type / Content-Length (not for 204) / Cache-Control: no-store / Retry-After / Allow /
// Connection: close + body.
std::string http_serialize(const HttpResponse& r);

// The device side of the link (src/flows.cpp implements it on the app loop).
class LinkApp {
 public:
  virtual ~LinkApp() {}
  virtual std::string status_json() = 0;                // the STATUS JSON (the same document BLE STATUS carries)
  virtual bool on_scan() = 0;                           // the device shows SCAN (the user pressed SIGN on Home)
  virtual void rx_line(const std::string& line) = 0;    // one UR part -> the camera's intake; only while on_scan()
  virtual void rx_refused() = 0;                        // a POST /rx while not on SCAN: sets the STATUS note
  virtual std::string output() = 0;                     // UR text of the QR on screen ("" = none)
};

// Authentication + routes (docs/WIFI_LINK.md section 4). Every request needs X-Ripar-Code; it is checked before
// the route and before any body byte is used.
class HttpLink {
 public:
  void set_code(const std::string& code) { code_ = code; }
  // After HttpReader::HeadDone or Bad. True: `out` is the answer (send it, close). False: POST /rx accepted so far:
  // r.want_body(r.content_length()), then on_body() once the reader is Done.
  bool on_head(const HttpReader& r, uint32_t nowMs, LinkApp& app, HttpResponse& out);
  HttpResponse on_body(const HttpReader& r, LinkApp& app);
  const FailLimiter& limiter() const { return lim_; }

 private:
  std::string code_;
  FailLimiter lim_;
};

}  // namespace wifip
}  // namespace ripar
