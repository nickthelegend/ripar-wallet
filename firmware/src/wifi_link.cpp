// Wi-Fi courier - TEMPORARY TEST FEATURE (include/wifi_link.h, docs/WIFI_LINK.md). Compiled only with RIPAR_WIFI=1
// (env:ripar); env:ripar-ble and env:ripar-airgap exclude this file and link no Wi-Fi code at all.
//
// Stack: the Arduino-ESP32 2.0.17 WiFi library (station mode, credentials in RAM only: WiFi.persistent(false), so the
// Wi-Fi driver never writes them to its own NVS namespace), ESPmDNS (<host>.local, _http._tcp) and a WiFiServer
// socket on port 80. The HTTP handling is the portable, host-tested wifi_proto.cpp (HttpReader / HttpLink), polled
// from the app loop with non-blocking reads: one connection at a time, the code checked before any body byte is
// used, head <= 2048 bytes, body <= 16384 bytes, 5 s per request. (The framework's WebServer class is not used: it
// reads a POST body of any length before a handler - and so before authentication - with blocking waits.)
//
// Coexistence: the framework's prebuilt ESP-IDF 4.4 for the ESP32-S3 has CONFIG_ESP32_WIFI_SW_COEXIST_ENABLE=1, so
// Wi-Fi and the Bluetooth LE link may run together (Wi-Fi then stays in modem sleep, the Arduino default).
//
// Credentials: NVS namespace "ripar-wifi" (ssid, pass, and the persisted WI-FI ON choice "on"), separate from the
// wallet's "ripar" namespace. Only written after the user confirmed the JOIN WI-FI review with SIGN.
#include "device.h"

#if RIPAR_WIFI

#include <Arduino.h>
#include <ESPmDNS.h>
#include <Preferences.h>
#include <WiFi.h>

#include <cstring>
#include <string>

#include "esp_mac.h"
#include "esp_wifi.h"
#include "nvs.h"
#include "wifi_link.h"
#include "wifi_proto.h"

namespace ripar {
namespace {

using wifip::HttpReader;

constexpr const char* kNs = "ripar-wifi";
constexpr const char* kKeySsid = "ssid";
constexpr const char* kKeyPass = "pass";
constexpr const char* kKeyOn = "on";
constexpr uint32_t kRetryMs = 20000;  // not connected: ask the driver to connect again this often
constexpr uint32_t kIpPollMs = 2000;

bool g_on = false;
WifiState g_state = WifiState::Off;
std::string g_host, g_code, g_ssid, g_ip;
uint32_t g_lastRetry = 0, g_lastIp = 0;
bool g_mdns = false;
bool g_serverUp = false;
bool g_everStarted = false;  // wifi_link_enable() reached the driver at least once this boot (nothing else starts it)
WiFiServer g_server(wifip::kHttpPort, 2);  // the constructor only stores the port; begin() opens the socket
wifip::HttpLink g_http;                     // per boot: the lock-out survives WI-FI OFF / ON

struct Conn {
  WiFiClient c;
  HttpReader r;
  uint32_t t0 = 0;
  bool active = false;
  bool routed = false;  // on_head() done
};
Conn g_conn;

bool valid(const wifip::Creds& c) {
  const size_t pl = c.pass.size();
  return !c.ssid.empty() && c.ssid.size() <= wifip::kMaxSsid &&
         (pl == 0 || (pl >= wifip::kMinPass && pl <= wifip::kMaxPass));
}

void new_code() {
  for (;;) {
    uint8_t b[4];
    trng_fill(b, sizeof b);  // before the radio is up: the SAR-ADC entropy source (keys.cpp)
    const uint32_t r = uint32_t(b[0]) << 24 | uint32_t(b[1]) << 16 | uint32_t(b[2]) << 8 | b[3];
    volatile uint8_t* v = b;
    for (size_t i = 0; i < sizeof b; i++) v[i] = 0;
    if (wifip::code_from_random(r, g_code)) return;
  }
}

void close_conn() {
  if (g_conn.active) g_conn.c.stop();
  g_conn.c = WiFiClient();
  g_conn.r.wipe();
  g_conn.active = g_conn.routed = false;
}

void reply(const wifip::HttpResponse& resp) {
  std::string out = wifip::http_serialize(resp);
  // small responses (STATUS <= 180 bytes, one response UR) fit the socket's send buffer: this does not wait
  g_conn.c.write(reinterpret_cast<const uint8_t*>(out.data()), out.size());
  wifip::wipe_str(out);
  if (Serial) {
    const char* m = g_conn.r.stage() == HttpReader::Bad ? "?" : g_conn.r.method().c_str();
    const char* p = g_conn.r.stage() == HttpReader::Bad ? "" : g_conn.r.path().c_str();
    Serial.printf("ripar: wifi http %s %.24s -> %d\n", m, p, resp.status);
  }
  close_conn();
}

void serve(uint32_t now, wifip::LinkApp& app) {
  if (!g_serverUp) return;
  if (!g_conn.active) {
    WiFiClient nc = g_server.available();  // non-blocking accept
    if (!nc) return;
    g_conn.c = nc;
    g_conn.r.wipe();
    g_conn.t0 = now;
    g_conn.active = true;
    g_conn.routed = false;
  }
  uint8_t buf[512];
  for (int i = 0; i < 8; i++) {  // at most 4 KB per pass
    const int a = g_conn.c.available();
    if (a <= 0) break;
    const int n = g_conn.c.read(buf, size_t(a) < sizeof buf ? size_t(a) : sizeof buf);
    if (n <= 0) break;
    g_conn.r.feed(buf, size_t(n));
    if (g_conn.r.stage() == HttpReader::Bad) break;
  }
  volatile uint8_t* v = buf;
  for (size_t i = 0; i < sizeof buf; i++) v[i] = 0;

  wifip::HttpResponse resp;
  const HttpReader::Stage st = g_conn.r.stage();
  if (!g_conn.routed && (st == HttpReader::HeadDone || st == HttpReader::Bad)) {
    g_conn.routed = true;
    if (g_http.on_head(g_conn.r, now, app, resp)) {
      if (resp.status == 401 && Serial)
        Serial.printf("ripar: wifi wrong link code (%u failures)\n", g_http.limiter().fails());
      return reply(resp);
    }
    g_conn.r.want_body(size_t(g_conn.r.content_length()));  // on_head checked it (1..16384)
  }
  if (g_conn.routed && g_conn.r.stage() == HttpReader::Done) return reply(g_http.on_body(g_conn.r, app));
  if (uint32_t(now - g_conn.t0) >= wifip::kRequestMs) {
    resp.status = 408;
    resp.type = "application/json";
    resp.body = "{\"error\":\"the request did not arrive within 5 s\"}";
    return reply(resp);
  }
  if (!g_conn.c.connected()) close_conn();
}

// Everything off. Safe in any partial state (also from a failed enable).
void teardown() {
  close_conn();
  if (g_serverUp) g_server.end();
  g_serverUp = false;
  if (g_mdns) MDNS.end();
  g_mdns = false;
  if (WiFi.getMode() != WIFI_MODE_NULL) WiFi.disconnect(true, true);  // erase the RAM config (password), driver off
  WiFi.mode(WIFI_OFF);  // esp_wifi_stop + esp_wifi_deinit (no-op when already off)
  g_on = false;
  g_state = WifiState::Off;
  wifip::wipe_str(g_ssid);
  g_ip.clear();
  if (Serial)
    Serial.printf("ripar: wifi off (driver %s)\n", wifi_link_radio_alive() ? "STILL INITIALISED" : "de-initialised");
}

}  // namespace

// ================================================================================================ stored network
// Reads use the NVS API directly (read-only, no log line when the namespace does not exist yet, e.g. at every boot of
// a device that never stored a network); writes use Preferences (the same blob / u8 encoding).
bool wifi_creds_load(wifip::Creds& c) {
  c.wipe();
  nvs_handle_t h;
  if (nvs_open(kNs, NVS_READONLY, &h) != ESP_OK) return false;
  char ssid[wifip::kMaxSsid + 1] = {0}, pass[wifip::kMaxPass + 1] = {0};
  size_t sl = sizeof ssid, pl = sizeof pass;
  bool ok = nvs_get_blob(h, kKeySsid, ssid, &sl) == ESP_OK && sl >= 1 && sl <= wifip::kMaxSsid;
  if (ok) {
    const esp_err_t e = nvs_get_blob(h, kKeyPass, pass, &pl);
    if (e == ESP_ERR_NVS_NOT_FOUND)
      pl = 0;  // no "pass" key = open network
    else
      ok = e == ESP_OK && pl >= wifip::kMinPass && pl <= wifip::kMaxPass;
  }
  nvs_close(h);
  if (ok) {
    c.ssid.assign(ssid, sl);
    c.pass.assign(pass, pl);
  }
  volatile char* vs = ssid;
  volatile char* vp = pass;
  for (size_t i = 0; i < sizeof ssid; i++) vs[i] = 0;
  for (size_t i = 0; i < sizeof pass; i++) vp[i] = 0;
  if (!ok || !valid(c)) {
    c.wipe();
    return false;
  }
  return true;
}

bool wifi_creds_ssid(std::string& ssid) {
  wifip::Creds c;
  const bool ok = wifi_creds_load(c);
  ssid = ok ? c.ssid : std::string();
  c.wipe();
  return ok;
}

bool wifi_creds_save(const wifip::Creds& c) {
  if (!valid(c)) return false;
  Preferences p;
  if (!p.begin(kNs, false)) return false;
  bool ok = p.putBytes(kKeySsid, c.ssid.data(), c.ssid.size()) == c.ssid.size();
  if (ok) {
    if (c.pass.empty())
      ok = !p.isKey(kKeyPass) || p.remove(kKeyPass);
    else
      ok = p.putBytes(kKeyPass, c.pass.data(), c.pass.size()) == c.pass.size();
  }
  p.end();
  if (!ok) return false;
  wifip::Creds back;
  ok = wifi_creds_load(back) && back.ssid == c.ssid && back.pass == c.pass;
  back.wipe();
  return ok;
}

bool wifi_creds_forget() {
  Preferences p;
  if (!p.begin(kNs, false)) return false;
  const bool ok = p.clear();  // every key of the namespace: network + WI-FI ON choice
  p.end();
  return ok;
}

bool wifi_auto_on() {
  nvs_handle_t h;
  if (nvs_open(kNs, NVS_READONLY, &h) != ESP_OK) return false;
  uint8_t v = 0;
  const bool on = nvs_get_u8(h, kKeyOn, &v) == ESP_OK && v != 0;
  nvs_close(h);
  return on;
}

bool wifi_set_auto_on(bool on) {
  Preferences p;
  if (!p.begin(kNs, false)) return false;
  const bool ok = on ? p.putUChar(kKeyOn, 1) == 1 : (!p.isKey(kKeyOn) || p.remove(kKeyOn));
  p.end();
  return ok;
}

const char* wifi_state_text(WifiState s) {
  switch (s) {
    case WifiState::Connecting:
      return "connecting";
    case WifiState::On:
      return "on";
    default:
      return "off";
  }
}

// ================================================================================================ radio
bool wifi_link_enable(std::string& err) {
  if (g_on) return true;
  wifip::Creds c;
  if (!wifi_creds_load(c)) {
    err = "no Wi-Fi network stored";
    return false;
  }
  if (g_code.empty()) new_code();  // per boot, drawn before the radio starts
  g_http.set_code(g_code);
  wifi_link_host();  // g_host from the station MAC

  g_everStarted = true;
  WiFi.persistent(false);  // credentials stay in RAM: never in the Wi-Fi driver's own NVS namespace
  WiFi.setAutoReconnect(true);
  WiFi.setHostname(g_host.c_str());  // DHCP host name (before the driver starts)
  if (!WiFi.mode(WIFI_STA)) {
    c.wipe();
    teardown();
    err = "the Wi-Fi driver did not start";
    return false;
  }
  const wl_status_t st = WiFi.begin(c.ssid.c_str(), c.pass.empty() ? nullptr : c.pass.c_str());
  g_ssid = c.ssid;
  c.wipe();
  if (st == WL_CONNECT_FAILED) {
    teardown();
    err = "the Wi-Fi driver refused the network";
    return false;
  }
  g_server.begin();
  g_serverUp = bool(g_server);
  if (!g_serverUp) {
    teardown();
    err = "the HTTP server (port 80) did not start";
    return false;
  }
  g_on = true;
  g_state = WifiState::Connecting;
  g_lastRetry = millis();
  if (Serial)
    Serial.printf("ripar: wifi ON as %s.local (network \"%s\")\n", g_host.c_str(), wifip::ssid_display(g_ssid).c_str());
  return true;
}

void wifi_link_disable() { teardown(); }

bool wifi_link_on() { return g_on; }

bool wifi_link_radio_alive() {
  if (!g_everStarted) return false;  // the driver is only ever initialised by wifi_link_enable()
  wifi_mode_t m;
  return esp_wifi_get_mode(&m) == ESP_OK;  // ESP_ERR_WIFI_NOT_INIT once de-initialised
}

WifiState wifi_link_state() { return g_on ? g_state : WifiState::Off; }
std::string wifi_link_ip() { return g_on && g_state == WifiState::On ? g_ip : std::string(); }
std::string wifi_link_host() {
  if (g_host.empty()) {  // before the first enable: the station MAC comes from the eFuse, no driver needed
    uint8_t mac[6] = {0};
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    g_host = wifip::mdns_host(mac);
  }
  return g_host;
}
std::string wifi_link_ssid() { return g_on ? g_ssid : std::string(); }
std::string wifi_link_code() { return g_code; }

std::string wifi_link_detail() {
  if (!g_on || g_state == WifiState::On) return std::string();
  switch (WiFi.status()) {
    case WL_NO_SSID_AVAIL:
      return "network not found";
    case WL_CONNECT_FAILED:
      return "connection refused (password?)";
    case WL_CONNECTION_LOST:
      return "connection lost";
    default:
      return "connecting";
  }
}

WifiEvt wifi_link_tick(uint32_t now, wifip::LinkApp& app) {
  if (!g_on) return WifiEvt::None;
  WifiEvt ev = WifiEvt::None;
  const wl_status_t ws = WiFi.status();
  const WifiState st = ws == WL_CONNECTED ? WifiState::On : WifiState::Connecting;
  if (st != g_state || (st == WifiState::On && uint32_t(now - g_lastIp) >= kIpPollMs)) {
    const std::string ip = st == WifiState::On ? std::string(WiFi.localIP().toString().c_str()) : std::string();
    g_lastIp = now;
    if (st != g_state || ip != g_ip) {
      g_state = st;
      g_ip = ip;
      ev = WifiEvt::StateChange;
      if (st == WifiState::On && !g_mdns) {
        g_mdns = MDNS.begin(g_host.c_str());
        if (g_mdns) MDNS.addService("http", "tcp", wifip::kHttpPort);
      }
      if (Serial) {
        if (st == WifiState::On)
          Serial.printf("ripar: wifi connected, %s (%s.local)\n", g_ip.c_str(), g_host.c_str());
        else
          Serial.println("ripar: wifi not connected: connecting");
      }
    }
  }
  if (st != WifiState::On) {
    // the driver does not retry after e.g. a wrong password: ask again now and then (a changed network is only
    // stored through the JOIN WI-FI review)
    if (uint32_t(now - g_lastRetry) >= kRetryMs && ws != WL_IDLE_STATUS) {
      g_lastRetry = now;
      WiFi.reconnect();
    }
  } else {
    g_lastRetry = now;
  }
  serve(now, app);
  return ev;
}

}  // namespace ripar

#endif  // RIPAR_WIFI
