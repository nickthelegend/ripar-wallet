// Display: LovyanGFX on the Waveshare ESP32-S3-LCD-2 (ST7789T3 240x320 IPS, SPI2), used in landscape 320x240.
//
// Every ui_* call composes a full screen into a 320x240 RGB565 sprite in PSRAM and pushes it in one go
// (no flicker). If the sprite cannot be allocated, drawing falls back to the panel directly.
// All text is drawn with ASCII (7-bit) GFX fonts; other bytes are shown as '?', so untrusted strings from the
// companion cannot smuggle look-alike characters or control codes onto a review screen.
//
// Assumptions not verified on hardware: RIPAR_LCD_ROTATION 1 gives the intended landscape orientation (use 3
// to turn it 180 degrees); the panel needs colour inversion (IPS) and RGB order, as in Waveshare's demo.
#define LGFX_USE_V1
#include <Arduino.h>
#include <LovyanGFX.hpp>
#include <lgfx/utility/lgfx_qrcode.h>

#include <cmath>
#include <cstdio>
#include <string>
#include <vector>

#include "board.h"
#include "device.h"

#ifndef RIPAR_LCD_ROTATION
#define RIPAR_LCD_ROTATION 1
#endif

namespace ripar {
namespace {

// ---------------- panel ----------------
class LGFX_Ripar : public lgfx::LGFX_Device {
  lgfx::Panel_ST7789 panel_;
  lgfx::Bus_SPI bus_;
  lgfx::Light_PWM light_;

 public:
  LGFX_Ripar() {
    {
      auto cfg = bus_.config();
      cfg.spi_host = SPI2_HOST;
      cfg.spi_mode = 0;
      cfg.freq_write = 40000000;
      cfg.freq_read = 16000000;
      cfg.spi_3wire = false;
      cfg.use_lock = true;
      cfg.dma_channel = SPI_DMA_CH_AUTO;
      cfg.pin_sclk = PIN_LCD_SCLK;
      cfg.pin_mosi = PIN_LCD_MOSI;
      cfg.pin_miso = -1;  // write-only (GPIO40 is the SD card's MISO; the TF slot is unused)
      cfg.pin_dc = PIN_LCD_DC;
      bus_.config(cfg);
      panel_.setBus(&bus_);
    }
    {
      auto cfg = panel_.config();
      cfg.pin_cs = PIN_LCD_CS;
      cfg.pin_rst = PIN_LCD_RST;
      cfg.pin_busy = -1;
      cfg.memory_width = 240;
      cfg.memory_height = 320;
      cfg.panel_width = 240;
      cfg.panel_height = 320;
      cfg.offset_x = 0;
      cfg.offset_y = 0;
      cfg.offset_rotation = 0;
      cfg.readable = false;
      cfg.invert = true;
      cfg.rgb_order = false;
      cfg.dlen_16bit = false;
      cfg.bus_shared = false;  // nothing else on SPI2 (TF slot unused)
      panel_.config(cfg);
    }
    {
      auto cfg = light_.config();
      cfg.pin_bl = PIN_LCD_BL;
      cfg.invert = false;
      cfg.freq = 44100;
      cfg.pwm_channel = 6;  // Arduino LEDC ch 6 -> timer 3 (camera XCLK: timer 0, buzzer: ch 4 -> timer 2)
      light_.config(cfg);
      panel_.setLight(&light_);
    }
    setPanel(&panel_);
  }
};

LGFX_Ripar g_lcd;
lgfx::LGFX_Sprite g_spr(&g_lcd);
lgfx::LovyanGFX* g = &g_lcd;  // current canvas
bool g_useSprite = false;
bool g_inited = false;

constexpr int W = LCD_W, Hh = LCD_H;

constexpr uint16_t rgb(uint8_t r, uint8_t g8, uint8_t b) {
  return uint16_t(((r & 0xF8) << 8) | ((g8 & 0xFC) << 3) | (b >> 3));
}
constexpr uint16_t C_BG = rgb(0, 0, 0);
constexpr uint16_t C_TEXT = UI_TEXT;  // the shared colours are defined in device.h (flows.cpp maps review tones)
constexpr uint16_t C_DIM = UI_DIM;
constexpr uint16_t C_FAINT = rgb(45, 45, 45);
constexpr uint16_t C_ACCENT = UI_ACCENT;
constexpr uint16_t C_HEAD = rgb(20, 40, 60);
constexpr uint16_t C_FOOT = rgb(30, 30, 30);
constexpr uint16_t C_GOOD = UI_GOOD;
constexpr uint16_t C_WARN = UI_WARN;
constexpr uint16_t C_BAD = UI_BAD;
constexpr uint16_t C_WHITE = rgb(255, 255, 255);
constexpr uint16_t C_BLACK = rgb(0, 0, 0);

const lgfx::IFont* const F_BODY = &lgfx::fonts::FreeSans9pt7b;
const lgfx::IFont* const F_BOLD = &lgfx::fonts::FreeSansBold9pt7b;
const lgfx::IFont* const F_BIG = &lgfx::fonts::FreeSansBold24pt7b;
const lgfx::IFont* const F_MID = &lgfx::fonts::FreeSansBold12pt7b;
const lgfx::IFont* const F_MONO = &lgfx::fonts::FreeMonoBold12pt7b;
const lgfx::IFont* const F_SMALL = &lgfx::fonts::Font2;
const lgfx::IFont* const F_TINY = &lgfx::fonts::Font0;

// Radio badge (include/device.h ui_set_radio_badge / ui_set_wifi_badge): drawn by flush() on top of EVERY screen, so
// no screen can be shown without it while the Bluetooth controller or the Wi-Fi driver is alive.
bool g_radio = false;  // Bluetooth (RIPAR_BLE)
bool g_wifi = false;   // Wi-Fi (RIPAR_WIFI test link)
constexpr int kBadgeW = 78, kBadgeH = 18;

bool badge_on() { return g_radio || g_wifi; }

void radio_badge() {
  if (!badge_on()) return;
  const int x = W - kBadgeW;
  const char* text = g_radio && g_wifi ? "BLE+WIFI" : g_wifi ? "WIFI ON" : "RADIO ON";
  g->fillRect(x, 0, kBadgeW, kBadgeH, C_BAD);
  g->setFont(F_SMALL);
  if (g->textWidth(text) > kBadgeW - 4) g->setFont(F_TINY);
  g->setTextDatum(lgfx::textdatum_t::middle_center);
  g->setTextColor(C_WHITE);
  g->drawString(text, x + kBadgeW / 2, kBadgeH / 2 + 1);
}

void flush() {
  radio_badge();
  if (g_useSprite) g_spr.pushSprite(&g_lcd, 0, 0);
}

// ---------------- text helpers ----------------
std::string sanitize(const std::string& s) {
  std::string o;
  o.reserve(s.size());
  for (unsigned char c : s) o += (c == '\n' || (c >= 0x20 && c < 0x7F)) ? char(c) : '?';
  return o;
}

std::string rtrim(const std::string& s) {
  size_t e = s.size();
  while (e > 0 && s[e - 1] == ' ') e--;
  return s.substr(0, e);
}

int text_w(const std::string& s) { return int(g->textWidth(s.c_str())); }

// greedy word wrap in the current font; overlong words are broken by character
std::vector<std::string> wrap(const std::string& text, int maxW) {
  std::vector<std::string> out;
  const std::string s = sanitize(text);
  size_t i = 0;
  while (i <= s.size()) {
    size_t nl = s.find('\n', i);
    if (nl == std::string::npos) nl = s.size();
    const std::string para = s.substr(i, nl - i);
    std::string line;
    size_t p = 0;
    if (para.empty()) out.push_back(std::string());
    while (p < para.size()) {
      size_t e = para.find(' ', p);
      e = (e == std::string::npos) ? para.size() : e + 1;
      const std::string word = para.substr(p, e - p);
      const std::string trial = line + word;
      if (text_w(rtrim(trial)) <= maxW) {
        line = trial;
        p = e;
        continue;
      }
      if (!rtrim(line).empty()) {
        out.push_back(rtrim(line));
        line.clear();
        continue;
      }
      size_t k = 1;
      while (k < word.size() && text_w(word.substr(0, k + 1)) <= maxW) k++;
      out.push_back(word.substr(0, k));
      p += k;
      line.clear();
    }
    if (!rtrim(line).empty()) out.push_back(rtrim(line));
    i = nl + 1;
  }
  return out;
}

// pick the largest of the given fonts in which `s` fits on one line (falls back to the last one)
void fit_font(const std::string& s, int maxW, std::initializer_list<const lgfx::IFont*> fonts) {
  const lgfx::IFont* last = nullptr;
  for (const lgfx::IFont* f : fonts) {
    last = f;
    g->setFont(f);
    if (text_w(s) <= maxW) return;
  }
  if (last) g->setFont(last);
}

void draw_text(const std::string& s, int x, int y, uint16_t color, const lgfx::IFont* f,
               lgfx::textdatum_t datum = lgfx::textdatum_t::top_left) {
  g->setFont(f);
  g->setTextDatum(datum);
  g->setTextColor(color);
  g->drawString(sanitize(s).c_str(), x, y);
}

uint16_t readable_on(uint16_t bg) {
  const int r = (bg >> 11) << 3, gg = ((bg >> 5) & 0x3F) << 2, b = (bg & 0x1F) << 3;
  return (r * 299 + gg * 587 + b * 114) / 1000 > 140 ? C_BLACK : C_WHITE;
}

void header(const char* title, uint16_t bg) {
  constexpr int kH = 28;
  g->fillRect(0, 0, W, kH, bg);
  const std::string t = sanitize(title ? title : "");
  fit_font(t, W - 16 - (badge_on() ? kBadgeW : 0), {F_BOLD, F_SMALL, F_TINY});  // room for the radio badge
  g->setTextDatum(lgfx::textdatum_t::middle_left);
  g->setTextColor(readable_on(bg));
  g->drawString(t.c_str(), 8, kH / 2);
}

void footer(const char* text, int h = 24) {
  g->fillRect(0, Hh - h, W, h, C_FOOT);
  const std::string t = sanitize(text ? text : "");
  fit_font(t, W - 12, {F_BODY, F_SMALL, F_TINY});
  g->setTextDatum(lgfx::textdatum_t::middle_center);
  g->setTextColor(C_TEXT);
  g->drawString(t.c_str(), W / 2, Hh - h / 2);
}

void battery_icon(int x, int y, int pct) {  // 26x12 body + nub, (x,y) = top-left
  g->drawRect(x, y, 24, 12, C_DIM);
  g->fillRect(x + 24, y + 3, 2, 6, C_DIM);
  if (pct >= 0) {
    const int p = pct > 100 ? 100 : pct;
    const uint16_t c = p < 20 ? C_BAD : (p < 50 ? C_WARN : C_GOOD);
    g->fillRect(x + 2, y + 2, (20 * p + 50) / 100, 8, c);
  }
}

void logo(int cx, int cy, uint16_t color) {
  draw_text("RIPAR", cx, cy, color, F_BIG, lgfx::textdatum_t::middle_center);
}

// ---------------- QR capacity (host-tested in isolation) ----------------
// QR-CAPACITY-BEGIN
// Error-correction codewords per version 1..40 (ISO/IEC 18004 table 9; same table as lgfx_qrcode.c).
const uint16_t kEccCodewordsM[40] = {10,  16,  26,  36,  48,  64,  72,  88,  110, 130, 150, 176, 198, 216,
                                     240, 280, 308, 338, 364, 416, 442, 476, 504, 560, 588, 644, 700, 728,
                                     784, 812, 868, 924, 980, 1036, 1064, 1120, 1204, 1260, 1316, 1372};
const uint16_t kEccCodewordsL[40] = {7,   10,  15,  20,  26,  36,  40,  48,  60,  72,  80,  96,  104, 120,
                                     132, 144, 168, 180, 196, 224, 224, 252, 270, 300, 312, 336, 360, 390,
                                     420, 450, 480, 510, 540, 570, 570, 600, 630, 660, 720, 750};
enum QrMode { kQrNumeric = 0, kQrAlnum = 1, kQrByte = 2 };

int qr_raw_modules(int v) {  // data + ECC modules of version v (nayuki's formula)
  int r = (16 * v + 128) * v + 64;
  if (v >= 2) {
    const int na = v / 7 + 2;
    r -= (25 * na - 10) * na - 55;
    if (v >= 7) r -= 36;
  }
  return r;
}

bool qr_alnum_char(char c) {
  return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || c == ' ' || c == '$' || c == '%' || c == '*' ||
         c == '+' || c == '-' || c == '.' || c == '/' || c == ':';
}

// same mode choice as lgfx_qrcode.c: all digits -> numeric, all alphanumeric -> alnum, else byte
int qr_mode(const char* s, size_t n) {
  bool num = true, aln = true;
  for (size_t i = 0; i < n; i++) {
    if (s[i] < '0' || s[i] > '9') num = false;
    if (!qr_alnum_char(s[i])) aln = false;
  }
  return num ? kQrNumeric : (aln ? kQrAlnum : kQrByte);
}

int qr_count_bits(int v, int mode) {
  static const int t[3][3] = {{10, 12, 14}, {9, 11, 13}, {8, 16, 16}};
  return t[mode][v <= 9 ? 0 : (v <= 26 ? 1 : 2)];
}

long qr_payload_bits(size_t n, int mode) {
  if (mode == kQrNumeric) return long(10 * (n / 3) + (n % 3 == 1 ? 4 : (n % 3 == 2 ? 7 : 0)));
  if (mode == kQrAlnum) return long(11 * (n / 2) + 6 * (n % 2));
  return long(8 * n);
}

// smallest version in 1..maxV whose data capacity at `ecc` (ECC_LOW / ECC_MEDIUM) holds the text; 0 if none
int qr_min_version(const char* s, size_t n, int ecc, int maxV) {
  const int mode = qr_mode(s, n);
  const uint16_t* table = ecc == ECC_LOW ? kEccCodewordsL : kEccCodewordsM;
  for (int v = 1; v <= maxV && v <= 40; v++) {
    const int cc = qr_count_bits(v, mode);
    if (n >= (size_t(1) << cc)) continue;
    const long need = 4 + cc + qr_payload_bits(n, mode);
    const long cap = long(qr_raw_modules(v) / 8 - table[v - 1]) * 8;
    if (need <= cap) return v;
  }
  return 0;
}

// Module scale for a version when the symbol + 4-module quiet zone must fit in `side` pixels.
int qr_scale(int v, int side) { return v > 0 ? side / (4 * v + 17 + 8) : 0; }

// ECC M unless L allows a larger module scale. Returns the version (0 = too long) and sets ecc.
int qr_pick(const char* s, size_t n, int side, int maxV, int& ecc) {
  const int vM = qr_min_version(s, n, ECC_MEDIUM, maxV);
  const int vL = qr_min_version(s, n, ECC_LOW, maxV);
  if (vM && qr_scale(vM, side) >= qr_scale(vL, side)) {
    ecc = ECC_MEDIUM;
    return vM;
  }
  ecc = ECC_LOW;
  return vL;
}
// Module (x, y) of a generated symbol, read straight from the bit grid (row-major, MSB first, as bb_setBit
// writes it). lgfx_qrcode_getModule() is not used: it is compiled as C where the header typedefs bool as
// unsigned char and returns the raw masked byte (e.g. 0x40), which is not a valid C++ bool at the call site.
bool qr_module(const QRCode& qr, int x, int y) {
  if (x < 0 || y < 0 || x >= qr.size || y >= qr.size) return false;
  const uint32_t off = uint32_t(y) * qr.size + uint32_t(x);
  return ((qr.modules[off >> 3] >> (7 - (off & 7))) & 1) != 0;
}
// QR-CAPACITY-END

constexpr int kQrMaxVersion = 25;  // (25*4+17+8) = 125 modules > 240/2: anything larger cannot reach scale 2
uint8_t g_qrModules[(117 * 117 + 7) / 8];

// ---------------- fingerprint icons ----------------
void icon(int x, int y, int s, uint8_t idx) {  // s = tile size
  static const uint16_t kColors[8] = {rgb(240, 50, 50),  rgb(255, 150, 0),   rgb(250, 230, 0),  rgb(50, 220, 80),
                                      rgb(0, 220, 230),  rgb(70, 130, 255),  rgb(230, 70, 230), rgb(240, 240, 240)};
  const int shape = idx & 7, style = idx >> 6;
  const uint16_t c = kColors[(idx >> 3) & 7];
  const int cx = x + s / 2, cy = y + s / 2, r = s / 2 - 3;
  if (style & 2) g->fillRoundRect(x, y, s, s, 4, C_FAINT);
  switch (shape) {
    case 0:
      g->fillCircle(cx, cy, r, c);
      break;
    case 1:
      g->fillRect(cx - r + 1, cy - r + 1, 2 * r - 1, 2 * r - 1, c);
      break;
    case 2:
      g->fillTriangle(cx, cy - r, cx - r, cy + r, cx + r, cy + r, c);
      break;
    case 3:
      g->fillTriangle(cx, cy - r, cx - r, cy, cx + r, cy, c);
      g->fillTriangle(cx, cy + r, cx - r, cy, cx + r, cy, c);
      break;
    case 4: {  // plus
      const int t = r / 2;
      g->fillRect(cx - t, cy - r, 2 * t, 2 * r, c);
      g->fillRect(cx - r, cy - t, 2 * r, 2 * t, c);
      break;
    }
    case 5:  // X
      g->drawWideLine(cx - r + 2, cy - r + 2, cx + r - 2, cy + r - 2, float(r) / 2.2f, c);
      g->drawWideLine(cx - r + 2, cy + r - 2, cx + r - 2, cy - r + 2, float(r) / 2.2f, c);
      break;
    case 6: {  // hexagon
      int px[6], py[6];
      for (int i = 0; i < 6; i++) {
        const float a = float(i) * 1.0471976f;
        px[i] = cx + int(lroundf(float(r) * cosf(a)));
        py[i] = cy + int(lroundf(float(r) * sinf(a)));
      }
      for (int i = 0; i < 6; i++) g->fillTriangle(cx, cy, px[i], py[i], px[(i + 1) % 6], py[(i + 1) % 6], c);
      break;
    }
    default: {  // 5-point star
      int px[10], py[10];
      for (int i = 0; i < 10; i++) {
        const float a = -1.5707963f + float(i) * 0.6283185f;
        const float rr = (i & 1) ? float(r) * 0.45f : float(r);
        px[i] = cx + int(lroundf(rr * cosf(a)));
        py[i] = cy + int(lroundf(rr * sinf(a)));
      }
      for (int i = 0; i < 10; i++) g->fillTriangle(cx, cy, px[i], py[i], px[(i + 1) % 10], py[(i + 1) % 10], c);
      break;
    }
  }
  if (style & 1) g->fillCircle(cx, cy, s / 8 > 2 ? s / 8 : 2, C_BLACK);
}

void progress_ring(int cx, int cy, int r0, int r1, float p, uint16_t color) {
  g->fillArc(cx, cy, r0, r1, 0.0f, 360.0f, C_FAINT);
  if (p <= 0.0f) return;
  if (p >= 1.0f) {
    g->fillArc(cx, cy, r0, r1, 0.0f, 360.0f, color);
    return;
  }
  const float end = 270.0f + 360.0f * p;  // 0 deg = 3 o'clock, clockwise; start at 12 o'clock
  if (end <= 360.0f) {
    g->fillArc(cx, cy, r0, r1, 270.0f, end, color);
  } else {
    g->fillArc(cx, cy, r0, r1, 270.0f, 360.0f, color);
    g->fillArc(cx, cy, r0, r1, 0.0f, end - 360.0f, color);
  }
}

void heart(int cx, int cy, int r, uint16_t c) {  // r ~ half width
  const int lobe = r / 2 + 1;
  g->fillCircle(cx - r / 2, cy - r / 3, lobe, c);
  g->fillCircle(cx + r / 2, cy - r / 3, lobe, c);
  g->fillTriangle(cx - r - 1, cy - r / 6, cx + r + 1, cy - r / 6, cx, cy + r, c);
}

}  // namespace

// ================= public API =================
void ui_init() {
  if (g_inited) return;
  // The TF slot shares MOSI/SCLK with the LCD. Hold its CS high so an inserted card never takes LCD traffic
  // as commands (the slot is unused; nothing is ever read from or written to a card).
  pinMode(PIN_SD_CS, OUTPUT);
  digitalWrite(PIN_SD_CS, HIGH);
  g_lcd.init();
  g_lcd.setRotation(RIPAR_LCD_ROTATION);
  g_lcd.setBrightness(200);
  g_lcd.fillScreen(C_BG);
  g_spr.setPsram(true);
  g_spr.setColorDepth(16);
  g_useSprite = g_spr.createSprite(W, Hh) != nullptr;
  g = g_useSprite ? static_cast<lgfx::LovyanGFX*>(&g_spr) : static_cast<lgfx::LovyanGFX*>(&g_lcd);
  g_inited = true;
}

void ui_boot(const char* status) {
  if (!g_inited) ui_init();
  g->fillScreen(C_BG);
  logo(W / 2, 92, C_ACCENT);
  draw_text("air-gapped signer", W / 2, 132, C_DIM, F_BODY, lgfx::textdatum_t::middle_center);
  g->setFont(F_BODY);
  const std::vector<std::string> lines = wrap(status ? status : "", W - 20);
  int y = 180;
  for (size_t i = 0; i < lines.size() && i < 2; i++, y += 22)
    draw_text(lines[i], W / 2, y, C_TEXT, F_BODY, lgfx::textdatum_t::middle_center);
  flush();
}

void ui_home(const std::string& k1short, int battery, bool paired, const std::string& linkLine) {
  if (!g_inited) ui_init();
  g->fillScreen(C_BG);
  // status bar
  if (badge_on())
    draw_text("NOT AIR-GAPPED", 8, 5, C_BAD, F_SMALL);  // Bluetooth or Wi-Fi is on: never claim air-gapped
  else
    draw_text("AIR-GAPPED", 8, 5, C_ACCENT, F_SMALL);
  char pct[8];
  if (battery >= 0) {
    std::snprintf(pct, sizeof pct, "%d%%", battery > 100 ? 100 : battery);
  } else {
    std::snprintf(pct, sizeof pct, "--%%");
  }
  const int shift = badge_on() ? kBadgeW + 4 : 0;  // battery left of the radio badge
  battery_icon(W - 34 - shift, 6, battery);
  draw_text(pct, W - 40 - shift, 5, C_DIM, F_SMALL, lgfx::textdatum_t::top_right);
  g->drawFastHLine(0, 26, W, C_FAINT);

  logo(W / 2, 72, C_ACCENT);
  draw_text("K1", W / 2, 112, C_DIM, F_SMALL, lgfx::textdatum_t::middle_center);
  if (k1short.empty()) {
    draw_text("no keys yet", W / 2, 138, C_WARN, F_MID, lgfx::textdatum_t::middle_center);
  } else {
    draw_text(k1short, W / 2, 138, C_TEXT, F_MONO, lgfx::textdatum_t::middle_center);
  }
  const char* badge = paired ? "PAIRED" : "NOT PAIRED";
  const uint16_t bc = paired ? C_GOOD : C_WARN;
  g->setFont(F_BOLD);
  const int bw = text_w(badge) + 20;
  g->drawRoundRect(W / 2 - bw / 2, 160, bw, 24, 6, bc);
  draw_text(badge, W / 2, 172, bc, F_BOLD, lgfx::textdatum_t::middle_center);
  if (!linkLine.empty()) {  // RIPAR_WIFI: e.g. "192.168.1.23  CODE 1234 5678", between the badge and the hints
    const std::string t = sanitize(linkLine);
    fit_font(t, W - 12, {F_BOLD, F_SMALL, F_TINY});
    g->setTextDatum(lgfx::textdatum_t::middle_center);
    g->setTextColor(C_WARN);
    g->drawString(t.c_str(), W / 2, 197);
  }

  // hints (flows.cpp / fsm.h: Short = scan, hold 2 s -> HomeHold: release = pairing QR, keep holding to 5 s = PANIC)
  g->fillRect(0, Hh - 30, W, 30, C_FOOT);
  draw_text("press = SCAN", 8, Hh - 15, C_TEXT, F_BODY, lgfx::textdatum_t::middle_left);
  draw_text("2s = PAIR", W / 2 + 12, Hh - 15, C_DIM, F_BODY, lgfx::textdatum_t::middle_center);
  draw_text("5s = PANIC", W - 8, Hh - 15, C_BAD, F_BODY, lgfx::textdatum_t::middle_right);
  flush();
}

void ui_scan(const uint8_t* gray, int w, int h, float progress, const char* hint) {
  if (!g_inited) ui_init();
  if (gray && w > 0 && h > 0) {
    if (w != W || h != Hh) g->fillScreen(C_BG);
    g->pushImage((W - w) / 2, (Hh - h) / 2, w, h, reinterpret_cast<const lgfx::grayscale_t*>(gray));
  } else {
    g->fillScreen(C_BG);
    draw_text("camera starting...", W / 2, Hh / 2, C_DIM, F_BODY, lgfx::textdatum_t::middle_center);
  }
  // aiming brackets
  const int s = 180, x0 = (W - s) / 2, y0 = (Hh - s) / 2 + 4, L = 22;
  for (int t = 0; t < 3; t++) {
    g->drawFastHLine(x0, y0 + t, L, C_ACCENT);
    g->drawFastVLine(x0 + t, y0, L, C_ACCENT);
    g->drawFastHLine(x0 + s - L, y0 + t, L, C_ACCENT);
    g->drawFastVLine(x0 + s - 1 - t, y0, L, C_ACCENT);
    g->drawFastHLine(x0, y0 + s - 1 - t, L, C_ACCENT);
    g->drawFastVLine(x0 + t, y0 + s - L, L, C_ACCENT);
    g->drawFastHLine(x0 + s - L, y0 + s - 1 - t, L, C_ACCENT);
    g->drawFastVLine(x0 + s - 1 - t, y0 + s - L, L, C_ACCENT);
  }
  // hint band
  if (hint && *hint) {
    g->fillRect(0, 0, W, 22, C_BLACK);
    const std::string t = sanitize(hint);
    const int hw = W - (badge_on() ? kBadgeW : 0);  // left of the radio badge
    fit_font(t, hw - 8, {F_BODY, F_SMALL, F_TINY});
    g->setTextDatum(lgfx::textdatum_t::middle_center);
    g->setTextColor(C_TEXT);
    g->drawString(t.c_str(), hw / 2, 11);
  }
  // multipart progress
  if (progress > 0.0f) {
    const float p = progress > 1.0f ? 1.0f : progress;
    g->fillRect(0, Hh - 18, W, 18, C_BLACK);
    g->drawRect(8, Hh - 13, W - 64, 8, C_DIM);
    g->fillRect(10, Hh - 11, int(float(W - 68) * p), 4, C_ACCENT);
    char pct[8];
    std::snprintf(pct, sizeof pct, "%d%%", int(p * 100.0f + 0.5f));
    draw_text(pct, W - 8, Hh - 9, C_TEXT, F_SMALL, lgfx::textdatum_t::middle_right);
  }
  flush();
}

// Review screen (security review M2). Every line is split into display rows FIRST (label column on the left with the
// value wrapped on the right, or the value over the full width when the label is empty); then the screen shows
// `visible` consecutive rows starting at the clamped `firstRow`. Nothing is ever dropped: rows that do not fit are
// reachable by paging (fsm.h review_next_first), and arrows + a scrollbar show whenever rows are hidden above or
// below. The caller learns exactly which rows were drawn from the returned ReviewView.
ReviewView ui_review(const char* title, const std::vector<ReviewLine>& lines, int firstRow, const char* footerMore,
                     const char* footerEnd) {
  if (!g_inited) ui_init();
  constexpr int kTop = 32, kFooterH = 24, kRow = 20;
  const int bottom = Hh - kFooterH - 2;
  const int labelX = 6, labelW = 86, valX = 98, valW = W - valX - 12, fullW = W - labelX - 12;
  const int visible = (bottom - kTop) / kRow;  // 9

  struct Row {
    std::string label, value;
    uint16_t color;
    bool full, last;  // value over the full width; last row of its line (separator below)
  };
  std::vector<Row> rows;
  g->setFont(F_BODY);
  for (const ReviewLine& ln : lines) {
    std::vector<std::string> lab, val;
    const bool full = ln.label.empty();
    if (full) {
      val = wrap(ln.value, fullW);
    } else {
      lab = wrap(ln.label, labelW);
      val = wrap(ln.value, valW);
    }
    size_t n = lab.size() > val.size() ? lab.size() : val.size();
    if (n == 0) n = 1;
    for (size_t r = 0; r < n; r++) {
      Row row;
      row.label = r < lab.size() ? lab[r] : std::string();
      row.value = r < val.size() ? val[r] : std::string();
      row.color = ln.color;
      row.full = full;
      row.last = r + 1 == n;
      rows.push_back(row);
    }
  }

  ReviewView v;
  v.totalRows = int(rows.size());
  v.firstRow = review_clamp_first(firstRow, visible, v.totalRows);
  v.rowsShown = v.totalRows - v.firstRow < visible ? v.totalRows - v.firstRow : visible;
  v.moreAbove = v.firstRow > 0;
  v.moreBelow = v.firstRow + v.rowsShown < v.totalRows;

  g->fillScreen(C_BG);
  header(title, C_HEAD);
  for (int i = 0; i < v.rowsShown; i++) {
    const Row& row = rows[size_t(v.firstRow + i)];
    const int y = kTop + i * kRow;
    if (!row.label.empty()) draw_text(row.label, labelX, y, C_DIM, F_BODY);
    if (!row.value.empty()) draw_text(row.value, row.full ? labelX : valX, y, row.color, F_BODY);
    if (row.last && i + 1 < v.rowsShown) g->drawFastHLine(labelX, y + kRow - 2, fullW, C_FAINT);
  }
  if (v.moreAbove || v.moreBelow) {  // scrollbar: thumb = the visible share of all rows
    const int trackH = bottom - kTop;
    g->fillRect(W - 5, kTop, 3, trackH, C_FAINT);
    int thumbH = (trackH * v.rowsShown) / (v.totalRows > 0 ? v.totalRows : 1);
    if (thumbH < 10) thumbH = 10;
    int thumbY = kTop + (trackH * v.firstRow) / (v.totalRows > 0 ? v.totalRows : 1);
    if (thumbY + thumbH > bottom) thumbY = bottom - thumbH;
    g->fillRect(W - 5, thumbY, 3, thumbH, C_ACCENT);
  }
  if (v.moreAbove) g->fillTriangle(W - 22, kTop + 8, W - 12, kTop + 8, W - 17, kTop + 2, C_ACCENT);
  if (v.moreBelow) g->fillTriangle(W - 22, bottom - 8, W - 12, bottom - 8, W - 17, bottom - 2, C_ACCENT);
  footer(v.moreBelow ? footerMore : footerEnd);
  flush();
  return v;
}

void ui_pulse(const PulseResult& p, const char* title) {
  if (!g_inited) ui_init();
  static uint32_t lastBeat = 0;
  const uint32_t now = millis();
  if (p.beatNow) lastBeat = now;
  g->fillScreen(C_BG);
  header(title, C_HEAD);

  const int cx = 82, cy = 136;
  progress_ring(cx, cy, 58, 66, p.progress, p.passed ? C_GOOD : C_ACCENT);
  const bool pulse = p.finger && lastBeat != 0 && now - lastBeat < 180;
  heart(cx, cy, pulse ? 34 : 27, p.finger ? C_BAD : C_FAINT);

  const int tx = 170;
  char buf[32];
  if (p.finger && p.bpm > 0.0f) {
    std::snprintf(buf, sizeof buf, "%d", int(p.bpm + 0.5f));
  } else {
    std::snprintf(buf, sizeof buf, "--");
  }
  draw_text(buf, tx, 48, C_TEXT, F_BIG);
  g->setFont(F_BIG);
  draw_text("BPM", tx + text_w(buf) + 8, 70, C_DIM, F_BODY);
  const PulseConfig cfg = PulseConfig();
  std::snprintf(buf, sizeof buf, "beats %d / %d", p.beats, cfg.minBeats);
  draw_text(buf, tx, 108, C_DIM, F_BODY);
  std::snprintf(buf, sizeof buf, "%.1f s", double(p.elapsedMs) / 1000.0);
  draw_text(buf, tx, 130, C_DIM, F_BODY);

  const char* status;
  uint16_t sc;
  if (!p.finger) {
    status = "Place your thumb on the sensor";
    sc = C_WARN;
  } else if (p.passed) {
    status = "PULSE OK - press SIGN";
    sc = C_GOOD;
  } else {
    status = "Measuring... keep still";
    sc = C_TEXT;
  }
  g->setFont(F_BOLD);
  const std::vector<std::string> st = wrap(status, W - tx - 6);
  int y = 160;
  for (size_t i = 0; i < st.size() && i < 3; i++, y += 22) draw_text(st[i], tx, y, sc, F_BOLD);
  flush();
}

// Output QR: smallest version with ECC M (or L when that gives bigger modules), largest integer module scale
// that fits the 240 px height including a white 4-module quiet zone, symbol on the left, text on the right.
// A UR ("ur:..." in any case) is shown upper-cased: URs are case-insensitive and upper case keeps the whole
// symbol in QR alphanumeric mode (about 30 % smaller than byte mode). Any other text is encoded as given.
void ui_qr(const std::string& textIn, const char* title, const char* footerText) {
  if (!g_inited) ui_init();
  std::string text = textIn;
  if (text.size() >= 3 && (text[0] == 'u' || text[0] == 'U') && (text[1] == 'r' || text[1] == 'R') && text[2] == ':')
    for (char& ch : text)
      if (ch >= 'a' && ch <= 'z') ch = char(ch - 'a' + 'A');
  int ecc = ECC_MEDIUM;
  const int v = qr_pick(text.data(), text.size(), Hh, kQrMaxVersion, ecc);
  const int scale = qr_scale(v, Hh);
  QRCode qr;
  if (v == 0 || scale < 2 || text.size() > 0xFFFF ||
      lgfx_qrcode_initBytes(&qr, g_qrModules, uint8_t(v), uint8_t(ecc),
                            reinterpret_cast<uint8_t*>(const_cast<char*>(text.data())), uint16_t(text.size())) != 0) {
    ui_message("QR TOO LARGE", "The response does not fit in one QR code on this screen.", C_BAD);
    return;
  }
  g->fillScreen(C_BG);
  const int n = qr.size, side = (n + 8) * scale;
  const int x0 = 0, y0 = (Hh - side) / 2;
  g->fillRect(x0, y0, side, side, C_WHITE);
  for (int yy = 0; yy < n; yy++) {
    int xx = 0;
    while (xx < n) {  // draw horizontal runs of dark modules
      if (!qr_module(qr, xx, yy)) {
        xx++;
        continue;
      }
      int e = xx + 1;
      while (e < n && qr_module(qr, e, yy)) e++;
      g->fillRect(x0 + (4 + xx) * scale, y0 + (4 + yy) * scale, (e - xx) * scale, scale, C_BLACK);
      xx = e;
    }
  }
  // right panel
  const int px = side + 8, pw = W - px - 4;
  if (pw >= 40) {
    const lgfx::IFont* tf = pw >= 110 ? F_BOLD : F_SMALL;
    const lgfx::IFont* ff = pw >= 110 ? F_BODY : F_TINY;
    const int trow = pw >= 110 ? 20 : 16, frow = pw >= 110 ? 20 : 10;
    g->setFont(tf);
    const std::vector<std::string> tl = wrap(title ? title : "", pw);
    int y = badge_on() ? kBadgeH + 6 : 8;  // below the radio badge
    for (size_t i = 0; i < tl.size() && y + trow <= Hh / 2; i++, y += trow) draw_text(tl[i], px, y, C_ACCENT, tf);
    g->setFont(ff);
    const std::vector<std::string> fl = wrap(footerText ? footerText : "", pw);
    const int fh = int(fl.size()) * frow;
    y = Hh - 6 - fh;
    if (y < Hh / 2) y = Hh / 2;
    for (size_t i = 0; i < fl.size() && y + frow <= Hh; i++, y += frow) draw_text(fl[i], px, y, C_TEXT, ff);
    char info[16];
    std::snprintf(info, sizeof info, "v%d-%c", v, ecc == ECC_LOW ? 'L' : 'M');
    draw_text(info, px, Hh / 2 - 4, C_FAINT, F_TINY);
  }
  flush();
}

void ui_message(const char* title, const std::string& body, uint16_t color) {
  if (!g_inited) ui_init();
  g->fillScreen(C_BG);
  header(title, color);
  g->setFont(F_BODY);
  const std::vector<std::string> lines = wrap(body, W - 20);
  constexpr int kRow = 22;
  const size_t maxRows = size_t((Hh - 40) / kRow);
  int y = 40;
  for (size_t i = 0; i < lines.size() && i < maxRows; i++, y += kRow) {
    std::string s = lines[i];
    if (i + 1 == maxRows && lines.size() > maxRows) s += " ...";
    draw_text(s, 10, y, C_TEXT, F_BODY);
  }
  flush();
}

void ui_set_radio_badge(bool on) { g_radio = on; }
bool ui_radio_badge() { return g_radio; }
void ui_set_wifi_badge(bool on) { g_wifi = on; }
bool ui_wifi_badge() { return g_wifi; }

void ui_ble_pair(const char* name, const char* code, const std::string& body, const char* footerText) {
  if (!g_inited) ui_init();
  g->fillScreen(C_BG);
  const std::string title = std::string("BLE PAIRING  ") + (name ? name : "");
  header(title.c_str(), C_HEAD);
  constexpr int kFooterH = 24, kRow = 22;
  int y = 40;
  if (code && *code) {  // the numeric comparison value, as large as possible
    draw_text(code, W / 2, 74, C_ACCENT, F_BIG, lgfx::textdatum_t::middle_center);
    y = 110;
  }
  g->setFont(F_BODY);
  const std::vector<std::string> lines = wrap(body, W - 20);
  for (size_t i = 0; i < lines.size() && y + kRow <= Hh - kFooterH - 2; i++, y += kRow)
    draw_text(lines[i], 10, y, C_TEXT, F_BODY);
  footer(footerText, kFooterH);
  flush();
}

// Four icons (28 px tiles, 6 px apart) at (x, y), drawn over the current screen, which is then re-pushed.
// idx bits: 0-2 shape (circle, square, triangle, diamond, plus, X, hexagon, star), 3-5 colour,
// bit 6 black centre dot, bit 7 grey tile behind -> 256 distinct icons per slot.
void ui_fingerprint(int x, int y, const uint8_t idx[4]) {
  if (!g_inited) ui_init();
  constexpr int kTile = 28, kGap = 6;
  for (int i = 0; i < 4; i++) icon(x + i * (kTile + kGap), y, kTile, idx[i]);
  flush();
}

}  // namespace ripar
