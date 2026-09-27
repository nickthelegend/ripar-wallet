// DEPS: wifi_proto json_strict ble_proto fsm
// Host tests for the portable part of the Wi-Fi TEST link (include/wifi_proto.h, docs/WIFI_LINK.md), the STATUS JSON
// keys it adds (include/ble_proto.h: "radio" off, "wifi", "ip", the <= 180-byte rule) and the state-machine additions
// (include/fsm.h: Job::WifiJoin / Job::WifiOn confirmed without the pulse by Act::Confirm, the 7-item menu):
//   - PROV JSON: strict parsing, exactly v / ssid / pass, v = 1, ssid 1..32 bytes, pass "" or 8..63 printable ASCII,
//     <= 512 bytes, error texts never contain the password
//   - link code: 8 digits without modulo bias, constant-time comparison, display form
//   - lock-out after wrong codes (3 free, then 1 s, 2 s, ... 300 s; reset by a correct code; millis() wrap)
//   - mDNS host name
//   - HTTP reader: request line / headers / limits (2048-byte head, 16384-byte body), duplicate or bad headers,
//     Transfer-Encoding, byte-by-byte arrival, the body only after want_body()
//   - HTTP routes: authentication before routing, 401 / 429, GET /status, GET /tx (204 / text), POST /rx (411 / 413 /
//     409 off SCAN with the note / lines into the intake in order, stopping when SCAN is left), 404 / 405
//   - response serialisation (Content-Length, no body on 204, Connection: close, no-store, Retry-After, Allow)
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "ble_proto.h"
#include "check.h"
#include "fsm.h"
#include "wifi_proto.h"

using namespace ripar;
using namespace ripar::wifip;

namespace {

bool prov(const std::string& json, Creds& c, std::string& err) { return parse_prov(json, c, err); }

bool prov_fails(const std::string& json, const char* expectInErr = nullptr) {
  Creds c;
  std::string err;
  const bool ok = parse_prov(json, c, err);
  if (ok) return false;
  if (!c.ssid.empty() || !c.pass.empty() || err.empty()) return false;
  if (expectInErr && err.find(expectInErr) == std::string::npos) {
    std::printf("   (error was: %s)\n", err.c_str());
    return false;
  }
  return true;
}

void test_prov() {
  CHECK_SECTION("prov: valid");
  Creds c;
  std::string err;
  CHECK(prov("{\"v\":1,\"ssid\":\"HomeNet\",\"pass\":\"correct horse\"}", c, err));
  CHECK_EQ(c.ssid, std::string("HomeNet"));
  CHECK_EQ(c.pass, std::string("correct horse"));
  CHECK(err.empty());
  // member order and whitespace do not matter
  CHECK(prov(" {\n \"pass\" : \"12345678\", \"ssid\":\"x\", \"v\" : 1 }\r\n", c, err));
  CHECK_EQ(c.ssid, std::string("x"));
  CHECK_EQ(c.pass, std::string("12345678"));
  // open network
  CHECK(prov("{\"v\":1,\"ssid\":\"Cafe\",\"pass\":\"\"}", c, err));
  CHECK(c.pass.empty());
  // limits: ssid 32 bytes, pass 8 and 63 characters
  const std::string s32(32, 'S'), p63(63, 'p');
  CHECK(prov("{\"v\":1,\"ssid\":\"" + s32 + "\",\"pass\":\"" + p63 + "\"}", c, err));
  CHECK_EQ(c.ssid.size(), size_t(32));
  CHECK_EQ(c.pass.size(), size_t(63));
  // escapes are decoded; a UTF-8 ssid counts in bytes
  CHECK(prov("{\"v\":1,\"ssid\":\"caf\\u00e9 \\\"q\\\"\",\"pass\":\"a\\\\b\\/cdefg\"}", c, err));
  CHECK_EQ(c.ssid, std::string("caf\xc3\xa9 \"q\""));
  CHECK_EQ(c.pass, std::string("a\\b/cdefg"));
  bool altered = false;
  CHECK_EQ(ssid_display(c.ssid, &altered), std::string("caf?? \"q\""));
  CHECK(altered);
  CHECK_EQ(ssid_display("Plain Net", &altered), std::string("Plain Net"));
  CHECK(!altered);
  // 16 x "é" = 32 bytes: fits; 17 = 34 bytes: too long
  std::string e16, e17;
  for (int i = 0; i < 16; i++) e16 += "\\u00e9";
  e17 = e16 + "\\u00e9";
  CHECK(prov("{\"v\":1,\"ssid\":\"" + e16 + "\",\"pass\":\"\"}", c, err));
  CHECK_EQ(c.ssid.size(), size_t(32));
  CHECK(prov_fails("{\"v\":1,\"ssid\":\"" + e17 + "\",\"pass\":\"\"}", "1..32"));

  CHECK_SECTION("prov: refused");
  CHECK(prov_fails("", "empty"));
  CHECK(prov_fails("{\"v\":1,\"ssid\":\"\",\"pass\":\"\"}", "1..32"));
  CHECK(prov_fails("{\"v\":1,\"ssid\":\"" + std::string(33, 'S') + "\",\"pass\":\"\"}", "1..32"));
  CHECK(prov_fails("{\"v\":1,\"ssid\":\"n\",\"pass\":\"1234567\"}", "8..63"));
  CHECK(prov_fails("{\"v\":1,\"ssid\":\"n\",\"pass\":\"" + std::string(64, 'p') + "\"}", "8..63"));
  CHECK(prov_fails("{\"v\":1,\"ssid\":\"n\",\"pass\":\"p\\u00e9ssword1\"}", "printable ASCII"));
  CHECK(prov_fails("{\"v\":1,\"ssid\":\"n\",\"pass\":\"pass\\tword\"}", "printable ASCII"));
  CHECK(prov_fails("{\"v\":1,\"ssid\":\"a\\nb\",\"pass\":\"\"}", "control"));
  CHECK(prov_fails("{\"v\":1,\"ssid\":\"a\\u007fb\",\"pass\":\"\"}", "control"));
  CHECK(prov_fails("{\"v\":1,\"ssid\":\"a\\u0000b\",\"pass\":\"\"}", "JSON"));  // json_strict refuses \u0000
  CHECK(prov_fails("{\"v\":2,\"ssid\":\"n\",\"pass\":\"\"}", "v must be"));
  CHECK(prov_fails("{\"v\":1.0,\"ssid\":\"n\",\"pass\":\"\"}", "v must be"));
  CHECK(prov_fails("{\"v\":\"1\",\"ssid\":\"n\",\"pass\":\"\"}", "v must be"));
  CHECK(prov_fails("{\"v\":1,\"ssid\":7,\"pass\":\"\"}", "strings"));
  CHECK(prov_fails("{\"v\":1,\"ssid\":\"n\",\"pass\":null}", "strings"));
  CHECK(prov_fails("{\"v\":1,\"ssid\":\"n\"}", "v, ssid and pass"));
  CHECK(prov_fails("{\"ssid\":\"n\",\"pass\":\"\"}", "v, ssid and pass"));
  CHECK(prov_fails("{\"v\":1,\"ssid\":\"n\",\"pass\":\"\",\"bssid\":\"x\"}", "unknown member \"bssid\""));
  CHECK(prov_fails("{\"v\":1,\"ssid\":\"n\",\"ssid\":\"m\",\"pass\":\"\"}", "duplicate"));
  CHECK(prov_fails("[1,2]", "not a JSON object"));
  CHECK(prov_fails("{\"v\":1,\"ssid\":\"n\",\"pass\":\"\"} x", "trailing"));
  CHECK(prov_fails("{'v':1}", "JSON"));
  CHECK(prov_fails("{\"v\":1,\"ssid\":\"n\",\"pass\":\"\",}", "JSON"));
  // longer than 512 bytes (whitespace padding) even though it is otherwise valid
  CHECK(prov_fails("{\"v\":1,\"ssid\":\"n\",\"pass\":\"\"}" + std::string(512, ' '), "512"));
  CHECK(parse_prov(reinterpret_cast<const uint8_t*>("{}"), 0, c, err) == false);
  CHECK(parse_prov(nullptr, 5, c, err) == false);
  // the password never appears in an error text
  err.clear();
  CHECK(!prov("{\"v\":1,\"ssid\":\"n\",\"pass\":\"SECRETPW\",\"x\":1}", c, err));
  CHECK(err.find("SECRETPW") == std::string::npos);
  const std::string longPw(64, 'S');  // "SSSS...": one character too long
  CHECK(!prov("{\"v\":1,\"ssid\":\"n\",\"pass\":\"" + longPw + "\"}", c, err));
  CHECK(err.find("SSSS") == std::string::npos);
  // a failed parse leaves nothing behind; a previous value is wiped
  c.ssid = "old";
  c.pass = "oldpassword";
  CHECK(!prov("{\"v\":1}", c, err));
  CHECK(c.ssid.empty() && c.pass.empty());

  CHECK_SECTION("prov: wipe");
  Creds w;
  w.ssid = "net";
  w.pass = "password1";
  w.wipe();
  CHECK(w.ssid.empty() && w.pass.empty());
  std::string s = "secret";
  wipe_str(s);
  CHECK(s.empty());
  CHECK_EQ(kMaxProv, blep::kMaxProv);  // the GATT value limit and the parser limit agree
}

void test_code() {
  CHECK_SECTION("link code");
  std::string code = "unchanged";
  CHECK(code_from_random(0, code));
  CHECK_EQ(code, std::string("00000000"));
  CHECK(code_from_random(12345678, code));
  CHECK_EQ(code, std::string("12345678"));
  CHECK(code_from_random(99999999, code));
  CHECK_EQ(code, std::string("99999999"));
  CHECK(code_from_random(100000000, code));
  CHECK_EQ(code, std::string("00000000"));
  CHECK(code_from_random(4199999999u, code));
  CHECK_EQ(code, std::string("99999999"));
  code = "keep";
  CHECK(!code_from_random(4200000000u, code));  // biased tail: draw again
  CHECK(!code_from_random(0xFFFFFFFFu, code));
  CHECK_EQ(code, std::string("keep"));
  CHECK(code_from_random(7, code));
  CHECK_EQ(code.size(), kCodeLen);
  CHECK_EQ(code, std::string("00000007"));

  CHECK(code_equal("12345678", "12345678"));
  CHECK(!code_equal("12345679", "12345678"));
  CHECK(!code_equal("02345678", "12345678"));
  CHECK(!code_equal("1234567", "12345678"));
  CHECK(!code_equal("123456789", "12345678"));
  CHECK(!code_equal("", "12345678"));
  CHECK(!code_equal("12345678 ", "12345678"));
  CHECK(!code_equal(std::string("1234\0" "678", 8), "12345678"));
  CHECK(!code_equal("", ""));                  // no code yet: nothing matches
  CHECK(!code_equal("1234", "1234"));          // not an 8-digit code
  CHECK_EQ(code_display("12345678"), std::string("1234 5678"));
  CHECK_EQ(code_display(""), std::string(""));
}

void test_limiter() {
  CHECK_SECTION("wrong-code lock-out");
  FailLimiter l;
  uint32_t t = 1000;
  CHECK(!l.locked(t));
  l.fail(t);
  l.fail(t);
  l.fail(t);
  CHECK(!l.locked(t));  // 3 free
  CHECK_EQ(l.fails(), 3u);
  l.fail(t);  // 4th: 1 s
  CHECK(l.locked(t));
  CHECK(l.locked(t + 999));
  CHECK_EQ(l.retry_after_ms(t + 400), 600u);
  CHECK(!l.locked(t + 1000));
  CHECK_EQ(l.retry_after_ms(t + 1000), 0u);
  t += 1000;
  l.fail(t);  // 5th: 2 s
  CHECK(l.locked(t + 1999));
  CHECK(!l.locked(t + 2000));
  t += 2000;
  l.fail(t);  // 6th: 4 s
  CHECK(l.locked(t + 3999));
  CHECK(!l.locked(t + 4000));
  for (int i = 0; i < 30; i++) l.fail(t);  // capped at 300 s
  CHECK(l.locked(t + 299999));
  CHECK(!l.locked(t + 300000));
  CHECK_EQ(l.total_fails(), 36u);
  l.success();
  CHECK_EQ(l.fails(), 0u);
  CHECK(!l.locked(t + 1));
  l.fail(t);
  CHECK(!l.locked(t));  // free again after a correct code
  // millis() wrap
  FailLimiter w;
  for (int i = 0; i < 4; i++) w.fail(0xFFFFFE00u);  // 1 s lock starting 512 ms before the wrap
  CHECK(w.locked(0x00000100u));                    // 768 ms later
  CHECK(!w.locked(0x00000200u));                   // 1024 ms later
  CHECK_EQ(FailLimiter::kFree, 3u);
  CHECK_EQ(FailLimiter::kMaxMs, 300000u);
}

void test_host() {
  CHECK_SECTION("mdns host");
  const uint8_t mac[6] = {0x24, 0x6f, 0x28, 0x01, 0x3F, 0x9A};
  CHECK_EQ(mdns_host(mac), std::string("ripar-3f9a"));
  const uint8_t z[6] = {0, 0, 0, 0, 0, 0};
  CHECK_EQ(mdns_host(z), std::string("ripar-0000"));
}

// ---------------------------------------------------------------------------------------------------------- HTTP
HttpReader read_all(const std::string& req) {
  HttpReader r;
  r.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
  return r;
}

void test_reader() {
  CHECK_SECTION("http reader: head");
  HttpReader r = read_all("GET /status?x=1 HTTP/1.1\r\nHost: ripar-3f9a.local\r\nX-Ripar-Code:  12345678 \r\n\r\n");
  CHECK_EQ(int(r.stage()), int(HttpReader::HeadDone));
  CHECK_EQ(r.method(), std::string("GET"));
  CHECK_EQ(r.path(), std::string("/status"));
  CHECK(r.has_code());
  CHECK_EQ(r.code(), std::string("12345678"));  // optional whitespace trimmed
  CHECK_EQ(r.content_length(), -1L);
  // header names are case-insensitive; LF-only line ends are tolerated; HTTP/1.0
  r = read_all("POST /rx HTTP/1.0\nx-ripar-code: 1\ncontent-length: 12\n\n");
  CHECK_EQ(int(r.stage()), int(HttpReader::HeadDone));
  CHECK_EQ(r.content_length(), 12L);
  CHECK_EQ(r.code(), std::string("1"));
  // no code header
  r = read_all("GET /tx HTTP/1.1\r\n\r\n");
  CHECK_EQ(int(r.stage()), int(HttpReader::HeadDone));
  CHECK(!r.has_code());
  // incomplete head
  r = read_all("GET /tx HTTP/1.1\r\nX-Ripar-Code: 1");
  CHECK_EQ(int(r.stage()), int(HttpReader::Head));

  CHECK_SECTION("http reader: malformed");
  struct Bad {
    const char* req;
    int status;
  };
  const Bad bad[] = {
      {"\r\n\r\n", 400},
      {"GET /status\r\n\r\n", 400},                          // no version
      {"GET  /status HTTP/1.1\r\n\r\n", 400},                // double space
      {"get /status HTTP/1.1\r\n\r\n", 400},                 // lower-case method
      {"GET status HTTP/1.1\r\n\r\n", 400},                  // not origin-form
      {"GET http://x/status HTTP/1.1\r\n\r\n", 400},
      {"GET /st\x01us HTTP/1.1\r\n\r\n", 400},
      {"GET /status HTTP/2.0\r\n\r\n", 505},
      {"GET /status FTP/1.1\r\n\r\n", 400},
      {"GET /status HTTP/1.1\r\nNoColon\r\n\r\n", 400},
      {"GET /status HTTP/1.1\r\n: empty-name\r\n\r\n", 400},
      {"GET /status HTTP/1.1\r\nBad Name: x\r\n\r\n", 400},
      {"GET /status HTTP/1.1\r\nA: b\r\n folded\r\n\r\n", 400},
      {"GET /status HTTP/1.1\r\nA: b\x01\r\n\r\n", 400},
      {"GET /status HTTP/1.1\r\nX-Ripar-Code: 1\r\nX-Ripar-Code: 2\r\n\r\n", 400},
      {"POST /rx HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n", 400},
      {"POST /rx HTTP/1.1\r\nContent-Length: -5\r\n\r\n", 400},
      {"POST /rx HTTP/1.1\r\nContent-Length: 5x\r\n\r\n", 400},
      {"POST /rx HTTP/1.1\r\nContent-Length: 1234567890\r\n\r\n", 400},
      {"POST /rx HTTP/1.1\r\nContent-Length:\r\n\r\n", 400},
      {"POST /rx HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", 501},
  };
  for (const Bad& b : bad) {
    r = read_all(b.req);
    const bool ok = r.stage() == HttpReader::Bad && r.bad_status() == b.status;
    if (!ok) std::printf("   request %s -> stage %d status %d\n", b.req, int(r.stage()), r.bad_status());
    CHECK(ok);
  }
  // a head longer than 2048 bytes
  r = read_all("GET /status HTTP/1.1\r\nX-Pad: " + std::string(2100, 'a') + "\r\n\r\n");
  CHECK_EQ(int(r.stage()), int(HttpReader::Bad));
  CHECK_EQ(r.bad_status(), 431);
  const std::string exact = "GET /status HTTP/1.1\r\nX-Pad: ";
  const std::string fill(kMaxHead - exact.size() - 4, 'b');
  r = read_all(exact + fill + "\r\n\r\n");  // exactly 2048 bytes
  CHECK_EQ(int(r.stage()), int(HttpReader::HeadDone));

  CHECK_SECTION("http reader: body");
  const std::string head = "POST /rx HTTP/1.1\r\nX-Ripar-Code: 12345678\r\nContent-Length: 10\r\n\r\n";
  r = read_all(head + "UR:A/B\nUR:CD");
  CHECK_EQ(int(r.stage()), int(HttpReader::HeadDone));  // body bytes are kept but nothing counts before want_body
  r.want_body(10);
  CHECK_EQ(int(r.stage()), int(HttpReader::Done));
  CHECK_EQ(r.body(), std::string("UR:A/B\nUR:"));  // exactly Content-Length bytes; what follows is not used
  // body arriving later, byte by byte; extra bytes after the body are ignored
  HttpReader b;
  const std::string all = head + "0123456789EXTRA";
  size_t i = 0;
  for (; i < head.size(); i++) b.feed(reinterpret_cast<const uint8_t*>(&all[i]), 1);
  CHECK_EQ(int(b.stage()), int(HttpReader::HeadDone));
  b.want_body(10);
  CHECK_EQ(int(b.stage()), int(HttpReader::Body));
  for (; i < all.size(); i++) b.feed(reinterpret_cast<const uint8_t*>(&all[i]), 1);
  CHECK_EQ(int(b.stage()), int(HttpReader::Done));
  CHECK_EQ(b.body(), std::string("0123456789"));
  // want_body larger than the limit
  HttpReader big = read_all("POST /rx HTTP/1.1\r\nContent-Length: 99999\r\n\r\n");
  big.want_body(kMaxBody + 1);
  CHECK_EQ(int(big.stage()), int(HttpReader::Bad));
  CHECK_EQ(big.bad_status(), 413);
  // before want_body() at most kMaxBody bytes are buffered
  HttpReader flood = read_all("POST /rx HTTP/1.1\r\nContent-Length: 16384\r\n\r\n" + std::string(40000, 'z'));
  CHECK_EQ(flood.body().size(), kMaxBody);
  // want_body(0) is done at once
  HttpReader zero = read_all("POST /rx HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
  zero.want_body(0);
  CHECK_EQ(int(zero.stage()), int(HttpReader::Done));
  // wipe resets
  zero.wipe();
  CHECK_EQ(int(zero.stage()), int(HttpReader::Head));
  CHECK(!zero.has_code());
  CHECK(zero.body().empty());
}

struct FakeApp : LinkApp {
  bool scan = false;
  bool leaveScanAfter = false;  // a complete request: the screen leaves SCAN after `leaveAt` lines
  size_t leaveAt = 0;
  std::string out;
  std::string note;
  std::vector<std::string> lines;
  int refused = 0;
  std::string status_json() override {
    const std::string n = note.empty() ? std::string() : ",\"note\":\"" + note + "\"";
    return std::string("{\"screen\":\"") + (scan ? "SCAN" : "HOME") + "\"" + n + "}";
  }
  bool on_scan() override { return scan; }
  void rx_line(const std::string& line) override {
    lines.push_back(line);
    if (leaveScanAfter && lines.size() >= leaveAt) scan = false;
  }
  void rx_refused() override {
    refused++;
    note = "ignored: not on SCAN";
  }
  std::string output() override { return out; }
};

const char* kCode = "31415926";

std::string req(const std::string& method, const std::string& path, const char* code, const std::string& body = "",
                bool withLength = true) {
  std::string r = method + " " + path + " HTTP/1.1\r\nHost: ripar-3f9a.local\r\n";
  if (code) r += std::string("X-Ripar-Code: ") + code + "\r\n";
  if (withLength && (method == "POST" || !body.empty())) {
    char b[48];
    std::snprintf(b, sizeof b, "Content-Length: %lu\r\n", static_cast<unsigned long>(body.size()));
    r += b;
  }
  return r + "\r\n" + body;
}

// one request through reader + link, as src/wifi_link.cpp drives them
HttpResponse run(HttpLink& link, FakeApp& app, const std::string& request, uint32_t now = 1000) {
  HttpReader r;
  r.feed(reinterpret_cast<const uint8_t*>(request.data()), request.size());
  HttpResponse out;
  if (r.stage() == HttpReader::Head) {
    out.status = -1;  // incomplete: the driver would wait (and answer 408 after 5 s)
    return out;
  }
  if (link.on_head(r, now, app, out)) return out;
  r.want_body(size_t(r.content_length()));
  if (r.stage() != HttpReader::Done) {
    out.status = -2;  // the body did not arrive
    return out;
  }
  return link.on_body(r, app);
}

void test_routes() {
  CHECK_SECTION("http: authentication");
  HttpLink link;
  FakeApp app;
  // no code set yet: nothing is accepted
  CHECK_EQ(run(link, app, req("GET", "/status", "")).status, 401);
  link = HttpLink();
  link.set_code(kCode);
  HttpResponse r = run(link, app, req("GET", "/status", nullptr));
  CHECK_EQ(r.status, 401);
  CHECK(r.body.find("X-Ripar-Code") != std::string::npos);
  CHECK_EQ(run(link, app, req("GET", "/status", "31415927")).status, 401);
  CHECK_EQ(run(link, app, req("GET", "/nothing", "00000000")).status, 401);  // routes are not revealed
  CHECK_EQ(link.limiter().fails(), 3u);
  // the 4th wrong code locks for 1 s: even the right code gets 429 then
  CHECK_EQ(run(link, app, req("GET", "/status", "11111111"), 2000).status, 401);
  r = run(link, app, req("GET", "/status", kCode), 2500);
  CHECK_EQ(r.status, 429);
  CHECK_EQ(r.retryAfterS, 1u);
  CHECK(app.lines.empty());
  r = run(link, app, req("GET", "/status", kCode), 3000);  // lock over
  CHECK_EQ(r.status, 200);
  CHECK_EQ(link.limiter().fails(), 0u);  // a correct code resets the count
  // malformed requests are answered without touching the count
  r = run(link, app, "GET /status HTTP/9.9\r\n\r\n");
  CHECK_EQ(r.status, 505);
  r = run(link, app, "POST /rx HTTP/1.1\r\nX-Ripar-Code: 31415926\r\nTransfer-Encoding: chunked\r\n\r\n");
  CHECK_EQ(r.status, 501);
  CHECK_EQ(link.limiter().fails(), 0u);

  CHECK_SECTION("http: GET /status, GET /tx");
  r = run(link, app, req("GET", "/status", kCode));
  CHECK_EQ(r.status, 200);
  CHECK_EQ(r.type, std::string("application/json"));
  CHECK_EQ(r.body, std::string("{\"screen\":\"HOME\"}"));
  r = run(link, app, req("GET", "/status?full=1", kCode));
  CHECK_EQ(r.status, 200);
  r = run(link, app, req("POST", "/status", kCode, "x"));
  CHECK_EQ(r.status, 405);
  CHECK_EQ(std::string(r.allow), std::string("GET"));
  r = run(link, app, req("GET", "/tx", kCode));
  CHECK_EQ(r.status, 204);  // no QR on screen
  CHECK(r.body.empty());
  app.out = "UR:RIPAR-COSIGN/HDCXLKAHSSQZ";
  r = run(link, app, req("GET", "/tx", kCode));
  CHECK_EQ(r.status, 200);
  CHECK_EQ(r.type, std::string("text/plain"));
  CHECK_EQ(r.body, app.out + "\n");
  CHECK_EQ(run(link, app, req("DELETE", "/tx", kCode)).status, 405);
  CHECK_EQ(run(link, app, req("GET", "/", kCode)).status, 404);
  CHECK_EQ(run(link, app, req("GET", "/status/", kCode)).status, 404);
  CHECK_EQ(run(link, app, req("GET", "/keys", kCode)).status, 404);
  CHECK_EQ(run(link, app, req("GET", "/seed", kCode)).status, 404);
  CHECK_EQ(run(link, app, req("GET", "/context", kCode)).status, 404);

  CHECK_SECTION("http: POST /rx");
  app.scan = false;
  r = run(link, app, req("POST", "/rx", kCode, "UR:A/B\n"));
  CHECK_EQ(r.status, 409);  // not on SCAN: the note, nothing taken
  CHECK_EQ(app.refused, 1);
  CHECK(r.body.find("ignored: not on SCAN") != std::string::npos);
  CHECK(app.lines.empty());
  app.note.clear();
  app.scan = true;
  CHECK_EQ(run(link, app, req("GET", "/rx", kCode)).status, 405);
  CHECK_EQ(run(link, app, req("POST", "/rx", kCode, "UR:A/B\n", false)).status, 411);
  CHECK_EQ(run(link, app, req("POST", "/rx", kCode, "")).status, 400);
  const std::string tooBig = "POST /rx HTTP/1.1\r\nX-Ripar-Code: 31415926\r\nContent-Length: 16385\r\n\r\n";
  CHECK_EQ(run(link, app, tooBig).status, 413);
  CHECK(app.lines.empty());
  // lines in order; CR LF, empty lines and a missing final newline are fine; overlong lines are skipped
  const std::string body = "UR:RIPAR-COSIGN-REQ/1-3/AAAA\r\n\r\nUR:RIPAR-COSIGN-REQ/2-3/BBBB\n" +
                           std::string(4097, 'X') + "\nUR:RIPAR-COSIGN-REQ/3-3/CCCC";
  r = run(link, app, req("POST", "/rx", kCode, body));
  CHECK_EQ(r.status, 200);
  CHECK_EQ(r.body, std::string("{\"screen\":\"SCAN\"}"));
  CHECK_EQ(app.lines.size(), size_t(3));
  if (app.lines.size() == 3) {
    CHECK_EQ(app.lines[0], std::string("UR:RIPAR-COSIGN-REQ/1-3/AAAA"));
    CHECK_EQ(app.lines[1], std::string("UR:RIPAR-COSIGN-REQ/2-3/BBBB"));
    CHECK_EQ(app.lines[2], std::string("UR:RIPAR-COSIGN-REQ/3-3/CCCC"));
  }
  // a 4096-byte line is kept
  app.lines.clear();
  r = run(link, app, req("POST", "/rx", kCode, std::string(4096, 'Y')));
  CHECK_EQ(r.status, 200);
  CHECK_EQ(app.lines.size(), size_t(1));
  // only empty / overlong lines: 400
  app.lines.clear();
  CHECK_EQ(run(link, app, req("POST", "/rx", kCode, "\r\n\n" + std::string(5000, 'Z'))).status, 400);
  CHECK(app.lines.empty());
  // the request completes after the 2nd part: the rest is not fed
  app.lines.clear();
  app.leaveScanAfter = true;
  app.leaveAt = 2;
  r = run(link, app, req("POST", "/rx", kCode, "UR:X/1-3/A\nUR:X/2-3/B\nUR:X/3-3/C\n"));
  CHECK_EQ(r.status, 200);
  CHECK_EQ(app.lines.size(), size_t(2));
  CHECK_EQ(r.body, std::string("{\"screen\":\"HOME\"}"));
  // SCAN left between the head and the body: 409
  app.leaveScanAfter = false;
  app.scan = true;
  app.lines.clear();
  {
    const std::string q = req("POST", "/rx", kCode, "UR:A/B\n");
    HttpReader rd;
    rd.feed(reinterpret_cast<const uint8_t*>(q.data()), q.size());
    HttpResponse out;
    CHECK(!link.on_head(rd, 1000, app, out));
    app.scan = false;
    rd.want_body(size_t(rd.content_length()));
    out = link.on_body(rd, app);
    CHECK_EQ(out.status, 409);
    CHECK(app.lines.empty());
  }
  // on_body before the body is complete
  {
    HttpReader rd = read_all("POST /rx HTTP/1.1\r\nX-Ripar-Code: 31415926\r\nContent-Length: 10\r\n\r\nabc");
    rd.want_body(10);
    CHECK_EQ(link.on_body(rd, app).status, 400);
  }

  CHECK_SECTION("http: serialise");
  HttpResponse s;
  s.status = 200;
  s.type = "application/json";
  s.body = "{\"v\":1}";
  CHECK_EQ(http_serialize(s), std::string("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 7\r\n"
                                          "Cache-Control: no-store\r\nConnection: close\r\n\r\n{\"v\":1}"));
  HttpResponse n;
  n.status = 204;
  n.body = "ignored";
  CHECK_EQ(http_serialize(n),
           std::string("HTTP/1.1 204 No Content\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"));
  HttpResponse l;
  l.status = 429;
  l.retryAfterS = 17;
  const std::string ls = http_serialize(l);
  CHECK(ls.find("HTTP/1.1 429 Too Many Requests\r\n") == 0);
  CHECK(ls.find("Retry-After: 17\r\n") != std::string::npos);
  CHECK(ls.find("Content-Length: 0\r\n") != std::string::npos);
  HttpResponse a;
  a.status = 405;
  a.allow = "POST";
  CHECK(http_serialize(a).find("Allow: POST\r\n") != std::string::npos);
  CHECK_EQ(std::string(http_reason(431)), std::string("Request Header Fields Too Large"));
  CHECK_EQ(std::string(http_reason(999)), std::string("Internal Server Error"));
}

void test_status() {
  CHECK_SECTION("status json: wifi keys");
  blep::StatusInfo s;
  s.screen = Screen::Home;
  s.paired = true;
  s.k1 = "0xAbCd...1234";
  s.fw = "0011223344556677";
  // BLE-only builds (no "wifi"): unchanged
  CHECK_EQ(blep::status_json(s), std::string("{\"v\":1,\"screen\":\"HOME\",\"paired\":true,\"k1\":\"0xAbCd...1234\","
                                             "\"radio\":\"on\",\"fw\":\"0011223344556677\"}"));
  s.wifi = "off";
  CHECK_EQ(blep::status_json(s), std::string("{\"v\":1,\"screen\":\"HOME\",\"paired\":true,\"k1\":\"0xAbCd...1234\","
                                             "\"radio\":\"on\",\"wifi\":\"off\",\"fw\":\"0011223344556677\"}"));
  s.wifi = "on";
  s.ip = "192.168.178.23";
  s.radio = false;  // read over HTTP while Bluetooth is off
  CHECK_EQ(blep::status_json(s),
           std::string("{\"v\":1,\"screen\":\"HOME\",\"paired\":true,\"k1\":\"0xAbCd...1234\",\"radio\":\"off\","
                       "\"wifi\":\"on\",\"ip\":\"192.168.178.23\",\"fw\":\"0011223344556677\"}"));
  // SCAN + a short note: everything fits
  s.screen = Screen::Scan;
  s.got = 2;
  s.of = 5;
  s.note = "part not used";
  std::string j = blep::status_json(s);
  CHECK(j.size() <= blep::kMaxStatus);
  CHECK(j.find("\"ip\":\"192.168.178.23\"") != std::string::npos);
  CHECK(j.find("\"note\":\"part not used\"}") != std::string::npos);
  CHECK(j.find("\"scan\":{\"got\":2,\"of\":5}") != std::string::npos);
  // a long note drops "ip" first (it comes back in the next STATUS), then is cut
  s.note = "ignored: not on SCAN (press SIGN on the device first)";
  j = blep::status_json(s);
  CHECK(j.size() <= blep::kMaxStatus);
  CHECK(j.find("\"ip\"") == std::string::npos);
  CHECK(j.find("\"note\":\"ignored: not on SCAN") != std::string::npos);
  CHECK(j.find("\"wifi\":\"on\"") != std::string::npos);
  s.note = std::string(400, 'n');
  j = blep::status_json(s);
  CHECK(j.size() <= blep::kMaxStatus);
  CHECK(j.find("\"note\":\"nnn") != std::string::npos);
  CHECK_EQ(j.back(), '}');
  s.note.clear();
  j = blep::status_json(s);
  CHECK(j.find("\"ip\":\"192.168.178.23\"") != std::string::npos);  // without a note the address is there
  // every key at its cap (and beyond): still <= 180 bytes, still one JSON object
  s.screen = Screen::Scan;
  s.k1 = std::string(100, 'k');
  s.fw = std::string(100, 'f');
  s.wifi = "connecting-and-more";
  s.ip = "255.255.255.255.255";
  s.got = 4000000000u;
  s.of = 4000000000u;
  s.note = std::string(300, '"');
  j = blep::status_json(s);
  CHECK(j.size() <= blep::kMaxStatus);
  CHECK_EQ(j.front(), '{');
  CHECK_EQ(j.back(), '}');
  s.note.clear();
  j = blep::status_json(s);
  CHECK(j.size() <= blep::kMaxStatus);
  s.k1 = std::string(40, '"');  // escaped characters in device-made values: still bounded
  s.fw = std::string(40, '\\');
  j = blep::status_json(s);
  CHECK(j.size() <= blep::kMaxStatus);
  CHECK_EQ(j.back(), '}');
  CHECK_EQ(std::string(blep::kProvUuid), std::string("52495041-5200-4c49-4e4b-000000000005"));
  uint8_t u[16];
  CHECK(blep::uuid128_le(blep::kProvUuid, u));
  CHECK_EQ(int(u[0]), 5);
}

FsmIn in(Key k, uint32_t now, bool passed = false, bool down = false) {
  FsmIn i;
  i.key = k;
  i.nowMs = now;
  i.pulsePassed = passed;
  i.keyDown = down;
  return i;
}

void test_fsm() {
  CHECK_SECTION("fsm: Wi-Fi settings need SIGN, not the pulse");
  CHECK(!job_needs_pulse(Job::WifiJoin));
  CHECK(!job_needs_pulse(Job::WifiOn));
  CHECK(job_is_setting(Job::WifiJoin));
  CHECK(job_is_setting(Job::WifiOn));
  CHECK(!job_is_setting(Job::BleOn));
  CHECK(!job_is_setting(Job::Deny));
  CHECK(job_needs_pulse(Job::BleOn));  // the Bluetooth radio still needs pulse + SIGN
  const Job jobs[] = {Job::WifiJoin, Job::WifiOn};
  for (Job job : jobs) {
    uint32_t now = 100;
    Fsm f(Fsm::DEFAULT_TIMEOUT_MS, MENU_ITEMS_WIFI);
    CHECK(f.open_review(job, true, ++now));
    CHECK_EQ(f.step(in(Key::Short, ++now)), Act::Ignored);  // nothing drawn yet
    f.review_drawn(0, 9, 12);
    CHECK_EQ(f.step(in(Key::Short, ++now)), Act::Redraw);  // not fully seen: next page, no confirm
    f.review_drawn(8, 4, 12);
    CHECK_EQ(f.step(in(Key::Short, ++now)), Act::Confirm);
    CHECK_EQ(f.screen(), Screen::Review);  // the driver applies it and leaves the screen
    CHECK_EQ(f.job(), job);
    CHECK_EQ(f.step(in(Key::None, ++now, true)), Act::None);  // a pulse never arms anything here
    CHECK_EQ(f.screen(), Screen::Review);
    // hold 2 s rejects
    CHECK_EQ(f.step(in(Key::Long2s, ++now, false, true)), Act::Home);
    CHECK_EQ(f.screen(), Screen::Home);
    CHECK_EQ(f.job(), Job::None);
    // a press that began before the review appeared confirms nothing
    f.step(in(Key::None, ++now, false, true));  // key down on Home
    CHECK(f.open_review(job, true, ++now));
    f.review_drawn(0, 5, 5);
    CHECK_EQ(f.step(in(Key::Short, ++now, false, false)), Act::Ignored);
    CHECK_EQ(f.step(in(Key::Short, ++now)), Act::Confirm);  // a new press does
    // a refused review is never confirmed
    CHECK(f.open_review(job, false, ++now));
    f.review_drawn(0, 5, 5);
    f.step(in(Key::None, ++now));
    CHECK_EQ(f.step(in(Key::Short, ++now)), Act::Home);
    // Pulse / Armed cannot be forced
    CHECK(f.open_review(job, true, ++now));
    CHECK(!f.go(Screen::Pulse, ++now));
    CHECK(!f.go(Screen::Armed, ++now));
    // timeout like every review
    const uint32_t t0 = ++now;
    CHECK(f.open_review(job, true, t0));
    CHECK_EQ(f.step(in(Key::None, t0 + Fsm::DEFAULT_TIMEOUT_MS)), Act::Timeout);
    CHECK_EQ(f.screen(), Screen::Home);
  }
  // the other reviews never produce Confirm
  {
    uint32_t now = 5;
    Fsm f;
    const Job others[] = {Job::Pair, Job::Cosign, Job::Mandate, Job::Privy, Job::Revoke, Job::Reopen, Job::BleOn};
    bool ok = true;
    for (Job j : others) {
      f.go(Screen::Home, ++now);
      f.open_review(j, true, ++now);
      f.review_drawn(0, 5, 5);
      f.step(in(Key::None, ++now));
      ok = ok && f.step(in(Key::Short, ++now)) == Act::None && f.screen() == Screen::Pulse;
    }
    f.go(Screen::Home, ++now);
    f.open_review(Job::Deny, true, ++now);
    f.review_drawn(0, 5, 5);
    f.step(in(Key::None, ++now));
    ok = ok && f.step(in(Key::Short, ++now)) == Act::SignNoPulse;
    CHECK(ok);
  }

  CHECK_SECTION("fsm: RIPAR_WIFI menu");
  uint32_t now = 1000;
  Fsm f(Fsm::DEFAULT_TIMEOUT_MS, MENU_ITEMS_WIFI);
  CHECK_EQ(f.menu_items(), 7);
  f.go(Screen::Menu, ++now);
  const int expect[] = {MENU_REOPEN, MENU_BLE, MENU_FORGET, MENU_WIFI, MENU_WIFI_FORGET, MENU_WIFI_BACK, MENU_REVOKE};
  for (int e : expect) {
    CHECK_EQ(f.step(in(Key::Short, ++now)), Act::Redraw);
    CHECK_EQ(f.menu_index(), e);
  }
  for (int i = 0; i < MENU_WIFI; i++) f.step(in(Key::Short, ++now));
  CHECK_EQ(f.step(in(Key::Long2s, ++now)), Act::MenuSelect);  // WI-FI ON / WI-FI OFF: the driver decides
  CHECK_EQ(f.menu_index(), int(MENU_WIFI));
  f.step(in(Key::Short, ++now));
  CHECK_EQ(f.step(in(Key::Long2s, ++now)), Act::MenuSelect);  // FORGET WI-FI
  CHECK_EQ(f.menu_index(), int(MENU_WIFI_FORGET));
  f.step(in(Key::Short, ++now));
  CHECK_EQ(f.step(in(Key::Long2s, ++now)), Act::Home);  // BACK is the last item
  CHECK_EQ(f.screen(), Screen::Home);
  CHECK_EQ(int(MENU_BLE), 2);  // the BLE items keep their places
  CHECK_EQ(int(MENU_FORGET), 3);
}

}  // namespace

int main() {
  test_prov();
  test_code();
  test_limiter();
  test_host();
  test_reader();
  test_routes();
  test_status();
  test_fsm();
  return CHECK_SUMMARY();
}
