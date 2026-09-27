// Portable logic of the Wi-Fi test link (include/wifi_proto.h, docs/WIFI_LINK.md). TEMPORARY TEST FEATURE, built only
// with RIPAR_WIFI=1. No radio code; host-tested in test/host/test_wifi_link.cpp.
#include "wifi_proto.h"

#include <cstdio>
#include <cstring>
#include <vector>

#include "json_strict.h"

namespace ripar {
namespace wifip {

constexpr unsigned FailLimiter::kFree;
constexpr uint32_t FailLimiter::kBaseMs;
constexpr uint32_t FailLimiter::kMaxMs;

namespace {

void wipe_json(JsonVal& v) {
  wipe_str(v.str);
  for (std::string& k : v.keys) wipe_str(k);
  for (JsonVal& i : v.items) wipe_json(i);
  v.keys.clear();
  v.items.clear();
}

bool has_control(const std::string& s) {
  for (unsigned char c : s)
    if (c < 0x20 || c == 0x7F) return true;
  return false;
}

bool printable_ascii(const std::string& s) {
  for (unsigned char c : s)
    if (c < 0x20 || c > 0x7E) return false;
  return true;
}

bool check_prov(const JsonVal& v, Creds& out, std::string& err) {
  if (v.type != JsonVal::Object) {
    err = "not a JSON object";
    return false;
  }
  for (const std::string& k : v.keys) {
    if (k != "v" && k != "ssid" && k != "pass") {
      err = "unknown member \"" + ssid_display(k.size() > 16 ? k.substr(0, 16) : k) + "\"";
      return false;
    }
  }
  const JsonVal* ver = v.get("v");
  const JsonVal* ssid = v.get("ssid");
  const JsonVal* pass = v.get("pass");
  if (!ver || !ssid || !pass) {
    err = "needs exactly the members v, ssid and pass";
    return false;
  }
  if (ver->type != JsonVal::Number || ver->str != "1") {
    err = "v must be the number 1";
    return false;
  }
  if (ssid->type != JsonVal::String || pass->type != JsonVal::String) {
    err = "ssid and pass must be strings";
    return false;
  }
  if (ssid->str.empty() || ssid->str.size() > kMaxSsid) {
    err = "ssid must be 1..32 bytes";
    return false;
  }
  if (has_control(ssid->str)) {
    err = "ssid contains a control character";
    return false;
  }
  const size_t pl = pass->str.size();
  if (pl != 0 && (pl < kMinPass || pl > kMaxPass)) {
    err = "pass must be empty (open network) or 8..63 characters";
    return false;
  }
  if (!printable_ascii(pass->str)) {
    err = "pass must be printable ASCII";
    return false;
  }
  out.ssid = ssid->str;
  out.pass = pass->str;
  return true;
}

bool ieq(const std::string& a, const char* b) {  // ASCII case-insensitive
  const size_t n = std::strlen(b);
  if (a.size() != n) return false;
  for (size_t i = 0; i < n; i++) {
    char x = a[i], y = b[i];
    if (x >= 'A' && x <= 'Z') x = char(x - 'A' + 'a');
    if (y >= 'A' && y <= 'Z') y = char(y - 'A' + 'a');
    if (x != y) return false;
  }
  return true;
}

bool is_tchar(char c) {  // RFC 9110 token characters
  if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) return true;
  return std::strchr("!#$%&'*+-.^_`|~", c) != nullptr && c != '\0';
}

std::string json_escape(const std::string& s) {
  std::string o;
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

HttpResponse error_json(int status, const std::string& msg) {
  HttpResponse r;
  r.status = status;
  r.type = "application/json";
  r.body = "{\"error\":\"" + json_escape(msg) + "\"}";
  return r;
}

HttpResponse status_response(int status, LinkApp& app) {
  HttpResponse r;
  r.status = status;
  r.type = "application/json";
  r.body = app.status_json();
  return r;
}

}  // namespace

// ------------------------------------------------------------------------------------------------ credentials
void wipe_str(std::string& s) {
  if (!s.empty()) {
    volatile char* p = &s[0];
    for (size_t i = 0; i < s.size(); i++) p[i] = 0;
  }
  s.clear();
}

void Creds::wipe() {
  wipe_str(ssid);
  wipe_str(pass);
}

bool parse_prov(const uint8_t* p, size_t n, Creds& out, std::string& err) {
  out.wipe();
  err.clear();
  if (!p || n == 0) {
    err = "empty";
    return false;
  }
  if (n > kMaxProv) {
    err = "longer than 512 bytes";
    return false;
  }
  JsonVal v;
  std::string jerr;
  bool ok = json_parse_strict(p, n, v, &jerr);  // its messages are fixed texts + a byte offset, never input bytes
  if (!ok)
    err = "not strict JSON: " + jerr;
  else
    ok = check_prov(v, out, err);
  wipe_json(v);
  if (!ok) out.wipe();
  return ok;
}

std::string ssid_display(const std::string& ssid, bool* altered) {
  std::string o;
  bool alt = false;
  for (unsigned char c : ssid) {
    if (c >= 0x20 && c < 0x7F) {
      o += char(c);
    } else {
      o += '?';
      alt = true;
    }
  }
  if (altered) *altered = alt;
  return o;
}

// ------------------------------------------------------------------------------------------------ link code
bool code_from_random(uint32_t r, std::string& out) {
  constexpr uint32_t kLimit = 4200000000u;  // 42 * 10^8: the largest multiple of 10^8 below 2^32
  if (r >= kLimit) return false;
  char b[16];
  std::snprintf(b, sizeof b, "%08lu", static_cast<unsigned long>(r % 100000000u));
  out = b;
  return true;
}

bool code_equal(const std::string& given, const std::string& code) {
  if (code.size() != kCodeLen) return false;  // no code yet: nothing matches
  unsigned diff = given.size() == kCodeLen ? 0u : 1u;
  for (size_t i = 0; i < kCodeLen; i++) {
    const unsigned char g = i < given.size() ? static_cast<unsigned char>(given[i]) : 0;
    diff |= unsigned(g ^ static_cast<unsigned char>(code[i]));
  }
  return diff == 0;
}

std::string code_display(const std::string& code) {
  if (code.size() != kCodeLen) return code;
  return code.substr(0, 4) + " " + code.substr(4);
}

uint32_t FailLimiter::retry_after_ms(uint32_t now) const {
  if (!locked(now)) return 0;
  return lockMs_ - uint32_t(now - since_);
}

void FailLimiter::fail(uint32_t now) {
  if (fails_ < 1000) fails_++;
  if (total_ != 0xFFFFFFFFu) total_++;
  if (fails_ > kFree) {
    const unsigned k = fails_ - kFree - 1;
    uint32_t ms = k >= 20 ? kMaxMs : kBaseMs << k;
    if (ms > kMaxMs) ms = kMaxMs;
    since_ = now;
    lockMs_ = ms;
  }
}

std::string mdns_host(const uint8_t mac[6]) {
  char b[16];
  std::snprintf(b, sizeof b, "ripar-%02x%02x", unsigned(mac[4]), unsigned(mac[5]));
  return b;
}

// ------------------------------------------------------------------------------------------------ HttpReader
void HttpReader::feed(const uint8_t* p, size_t n) {
  if (!p || !n) return;
  size_t i = 0;
  if (stage_ == Head) {
    for (; i < n; i++) {
      head_ += char(p[i]);
      const size_t m = head_.size();
      if (m > kMaxHead) {
        wipe_str(head_);
        fail(431);
        return;
      }
      // end of the head: an empty line ("\r\n\r\n", also tolerated: "\n\n", "\n\r\n")
      if (head_[m - 1] == '\n' && m >= 2 &&
          (head_[m - 2] == '\n' || (m >= 3 && head_[m - 2] == '\r' && head_[m - 3] == '\n'))) {
        i++;
        parse_head();
        break;
      }
    }
  }
  if (stage_ == HeadDone || stage_ == Body) {
    const size_t cap = stage_ == Body ? want_ : kMaxBody;  // before want_body(): keep at most what could be wanted
    const size_t room = body_.size() < cap ? cap - body_.size() : 0;
    const size_t take = (n - i) < room ? (n - i) : room;
    if (take) body_.append(reinterpret_cast<const char*>(p + i), take);
    if (stage_ == Body && body_.size() >= want_) stage_ = Done;
  }
}

void HttpReader::parse_head() {
  std::vector<std::string> lines;
  size_t i = 0;
  while (i < head_.size()) {
    size_t e = head_.find('\n', i);
    if (e == std::string::npos) e = head_.size();
    std::string l = head_.substr(i, e - i);
    if (!l.empty() && l[l.size() - 1] == '\r') l.erase(l.size() - 1);
    lines.push_back(l);
    i = e + 1;
  }
  wipe_str(head_);  // it held the code
  struct Wipe {
    std::vector<std::string>& v;
    ~Wipe() {
      for (std::string& s : v) wipe_str(s);
    }
  } wipeLines{lines};
  if (lines.empty() || lines[0].empty()) return fail(400);

  // request line: METHOD SP request-target SP HTTP-version
  const std::string& rl = lines[0];
  const size_t s1 = rl.find(' ');
  const size_t s2 = s1 == std::string::npos ? std::string::npos : rl.find(' ', s1 + 1);
  if (s1 == std::string::npos || s2 == std::string::npos || rl.find(' ', s2 + 1) != std::string::npos) return fail(400);
  const std::string method = rl.substr(0, s1), target = rl.substr(s1 + 1, s2 - s1 - 1), version = rl.substr(s2 + 1);
  if (method.empty() || method.size() > 16) return fail(400);
  for (char c : method)
    if (c < 'A' || c > 'Z') return fail(400);
  if (target.empty() || target[0] != '/' || target.size() > 1024) return fail(400);
  for (char c : target)
    if (static_cast<unsigned char>(c) <= 0x20 || static_cast<unsigned char>(c) >= 0x7F) return fail(400);
  if (version != "HTTP/1.1" && version != "HTTP/1.0") return fail(version.compare(0, 5, "HTTP/") == 0 ? 505 : 400);

  bool haveLength = false;
  for (size_t k = 1; k < lines.size(); k++) {
    const std::string& h = lines[k];
    if (h.empty()) continue;  // the final empty line
    if (h[0] == ' ' || h[0] == '\t') return fail(400);  // obsolete line folding
    const size_t c = h.find(':');
    if (c == std::string::npos || c == 0) return fail(400);
    const std::string name = h.substr(0, c);
    for (char ch : name)
      if (!is_tchar(ch)) return fail(400);
    size_t b = c + 1, e = h.size();
    while (b < e && (h[b] == ' ' || h[b] == '\t')) b++;
    while (e > b && (h[e - 1] == ' ' || h[e - 1] == '\t')) e--;
    std::string value = h.substr(b, e - b);
    for (char ch : value) {
      const unsigned char u = static_cast<unsigned char>(ch);
      if ((u < 0x20 && u != '\t') || u == 0x7F) {
        wipe_str(value);
        return fail(400);
      }
    }
    if (ieq(name, kCodeHeader)) {
      if (hasCode_) {
        wipe_str(value);
        return fail(400);  // twice: ambiguous
      }
      hasCode_ = true;
      code_ = value;
    } else if (ieq(name, "Content-Length")) {
      if (haveLength || value.empty() || value.size() > 9) return fail(400);
      long v = 0;
      for (char ch : value) {
        if (ch < '0' || ch > '9') return fail(400);
        v = v * 10 + (ch - '0');
      }
      haveLength = true;
      contentLength_ = v;
    } else if (ieq(name, "Transfer-Encoding")) {
      return fail(501);  // chunked bodies are not supported: send Content-Length
    }
    wipe_str(value);
  }
  method_ = method;
  const size_t q = target.find('?');
  path_ = q == std::string::npos ? target : target.substr(0, q);
  stage_ = HeadDone;
}

void HttpReader::want_body(size_t n) {
  if (stage_ != HeadDone) return;
  if (n > kMaxBody) return fail(413);
  want_ = n;
  if (body_.size() > n) body_.resize(n);  // bytes after the body (pipelining) are not used: Connection: close
  stage_ = body_.size() >= n ? Done : Body;
}

void HttpReader::wipe() {
  wipe_str(head_);
  wipe_str(body_);
  wipe_str(code_);
  *this = HttpReader();
}

// ------------------------------------------------------------------------------------------------ responses
const char* http_reason(int status) {
  switch (status) {
    case 200: return "OK";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 409: return "Conflict";
    case 411: return "Length Required";
    case 413: return "Payload Too Large";
    case 429: return "Too Many Requests";
    case 431: return "Request Header Fields Too Large";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    case 505: return "HTTP Version Not Supported";
    default: return "Internal Server Error";
  }
}

std::string http_serialize(const HttpResponse& r) {
  char b[96];
  std::snprintf(b, sizeof b, "HTTP/1.1 %d %s\r\n", r.status, http_reason(r.status));
  std::string o = b;
  if (r.status != 204) {
    if (!r.type.empty()) o += "Content-Type: " + r.type + "\r\n";
    std::snprintf(b, sizeof b, "Content-Length: %lu\r\n", static_cast<unsigned long>(r.body.size()));
    o += b;
  }
  o += "Cache-Control: no-store\r\n";
  if (r.status == 429 && r.retryAfterS) {
    std::snprintf(b, sizeof b, "Retry-After: %lu\r\n", static_cast<unsigned long>(r.retryAfterS));
    o += b;
  }
  if (r.status == 405 && r.allow) o += std::string("Allow: ") + r.allow + "\r\n";
  o += "Connection: close\r\n\r\n";
  if (r.status != 204) o += r.body;
  return o;
}

// ------------------------------------------------------------------------------------------------ HttpLink
bool HttpLink::on_head(const HttpReader& r, uint32_t now, LinkApp& app, HttpResponse& out) {
  if (r.stage() == HttpReader::Bad) {
    const int st = r.bad_status();
    out = error_json(st ? st : 400, st == 431   ? "request head longer than 2048 bytes"
                                    : st == 413 ? "body longer than 16384 bytes"
                                    : st == 501 ? "Transfer-Encoding is not supported: send Content-Length"
                                    : st == 505 ? "HTTP/1.1 or HTTP/1.0 only"
                                                : "malformed request");
    return true;
  }
  if (r.stage() != HttpReader::HeadDone) {
    out = error_json(400, "incomplete request");
    return true;
  }
  // authentication first: nothing about the routes is revealed without the code
  if (lim_.locked(now)) {
    out = error_json(429, "too many wrong codes: wait");
    out.retryAfterS = (lim_.retry_after_ms(now) + 999) / 1000;
    return true;
  }
  if (!r.has_code() || !code_equal(r.code(), code_)) {
    lim_.fail(now);
    out = error_json(401, "X-Ripar-Code missing or wrong: use the 8-digit link code on the device's Home screen");
    return true;
  }
  lim_.success();

  const std::string& m = r.method();
  const std::string& path = r.path();
  if (path == "/status") {
    if (m != "GET") {
      out = error_json(405, "GET only");
      out.allow = "GET";
      return true;
    }
    out = status_response(200, app);
    return true;
  }
  if (path == "/tx") {
    if (m != "GET") {
      out = error_json(405, "GET only");
      out.allow = "GET";
      return true;
    }
    const std::string text = app.output();
    out = HttpResponse();
    if (text.empty()) {
      out.status = 204;  // no QR on screen
    } else {
      out.status = 200;
      out.type = "text/plain";
      out.body = text + "\n";
    }
    return true;
  }
  if (path == "/rx") {
    if (m != "POST") {
      out = error_json(405, "POST only");
      out.allow = "POST";
      return true;
    }
    if (r.content_length() < 0) {
      out = error_json(411, "Content-Length required");
      return true;
    }
    if (static_cast<unsigned long>(r.content_length()) > kMaxBody) {
      out = error_json(413, "body longer than 16384 bytes");
      return true;
    }
    if (r.content_length() == 0) {
      out = error_json(400, "empty body: send one or more UR lines");
      return true;
    }
    if (!app.on_scan()) {  // the same rule as BLE RX: lines only while the device is on SCAN
      app.rx_refused();
      out = status_response(409, app);
      return true;
    }
    return false;  // read the body
  }
  out = error_json(404, "routes: GET /status, POST /rx, GET /tx");
  return true;
}

HttpResponse HttpLink::on_body(const HttpReader& r, LinkApp& app) {
  if (r.stage() != HttpReader::Done) return error_json(400, "incomplete body");
  if (!app.on_scan()) {  // SCAN left while the body was arriving
    app.rx_refused();
    return status_response(409, app);
  }
  const std::string& b = r.body();
  bool any = false;
  size_t i = 0;
  while (i < b.size()) {
    size_t e = b.find('\n', i);
    if (e == std::string::npos) e = b.size();
    std::string line = b.substr(i, e - i);
    i = e + 1;
    if (!line.empty() && line[line.size() - 1] == '\r') line.erase(line.size() - 1);
    if (line.empty() || line.size() > kMaxRxLine) continue;  // empty / overlong lines are skipped (as on BLE RX)
    any = true;
    if (!app.on_scan()) break;  // the request completed (or the scan ended): the remaining parts are not needed
    app.rx_line(line);
  }
  if (!any) return error_json(400, "no UR line in the body");
  return status_response(200, app);
}

}  // namespace wifip
}  // namespace ripar
