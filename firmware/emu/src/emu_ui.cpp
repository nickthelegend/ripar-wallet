// Screen model (emu_ui.h): the layout rules of src/ui.cpp that decide what is visible, without the pixels.
#include "emu_ui.h"

#include <cstddef>

#include "font_freesans9.h"
#include "fsm.h"

// ---- the QR capacity helpers of src/ui.cpp, extracted verbatim at build time (build.sh: the lines between
// "QR-CAPACITY-BEGIN" and "QR-CAPACITY-END" -> build/gen/qr_capacity.inc). They need these two lgfx_qrcode.h
// constants and a QRCode with `size` and `modules` (qr_module() reads the bit grid; unused here).
#define ECC_LOW 0
#define ECC_MEDIUM 1

namespace ripar {
namespace emu {
namespace {

struct QRCode {
  uint8_t version, ecc, mode, mask, size;
  uint8_t* modules;
};

#include "qr_capacity.inc"

constexpr int kQrMaxVersion = 25;  // ui.cpp kQrMaxVersion

std::string rtrim(const std::string& s) {
  size_t e = s.size();
  while (e > 0 && s[e - 1] == ' ') e--;
  return s.substr(0, e);
}

}  // namespace

const char* ui_color_name(UiColor c) {
  switch (c) {
    case UiColor::Dim:
      return "dim";
    case UiColor::Accent:
      return "accent";
    case UiColor::Good:
      return "good";
    case UiColor::Warn:
      return "warn";
    case UiColor::Bad:
      return "bad";
    default:
      return "text";
  }
}

const char* ui_color_hex(UiColor c) {  // device.h: ui_rgb(...) arguments
  switch (c) {
    case UiColor::Dim:
      return "#8c8c8c";  // 140,140,140
    case UiColor::Accent:
      return "#00c8aa";  // 0,200,170
    case UiColor::Good:
      return "#28d250";  // 40,210,80
    case UiColor::Warn:
      return "#ffb000";  // 255,176,0
    case UiColor::Bad:
      return "#f02828";  // 240,40,40
    default:
      return "#ffffff";
  }
}

// ui.cpp sanitize(): '\n' and printable ASCII kept, every other byte -> '?'
std::string ui_sanitize(const std::string& s) {
  std::string o;
  o.reserve(s.size());
  for (unsigned char c : s) o += (c == '\n' || (c >= 0x20 && c < 0x7F)) ? char(c) : '?';
  return o;
}

// LovyanGFX LGFXBase::text_width() for a GFX font at text size 1: right = left + max(xAdvance, width + xOffset),
// left += xAdvance; stops at the first control character. Only printable ASCII reaches it (sanitize()).
int ui_text_width(const std::string& s) {
  int left = 0, right = 0;
  for (unsigned char c : s) {
    if (c < 0x20) break;
    const GlyphMetric& g = (c <= 0x7E) ? kFreeSans9[c - 0x20] : kFreeSans9[0];  // missing glyph -> ' ' metrics
    if (left == 0 && right == 0 && g.xOffset < 0) left = right = -g.xOffset;
    const int adv = g.xAdvance, ext = int(g.width) + g.xOffset;
    right = left + (adv > ext ? adv : ext);
    left += adv;
  }
  return right;
}

// ui.cpp wrap(): greedy word wrap; overlong words are broken by character
std::vector<std::string> ui_wrap(const std::string& text, int maxW) {
  std::vector<std::string> out;
  const std::string s = ui_sanitize(text);
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
      if (ui_text_width(rtrim(trial)) <= maxW) {
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
      while (k < word.size() && ui_text_width(word.substr(0, k + 1)) <= maxW) k++;
      out.push_back(word.substr(0, k));
      p += k;
      line.clear();
    }
    if (!rtrim(line).empty()) out.push_back(rtrim(line));
    i = nl + 1;
  }
  return out;
}

// ui.cpp ui_review(): lines -> display rows, then `visible` rows from the clamped first row
UiReview ui_review_model(const std::string& title, const std::vector<UiLine>& lines, int firstRow,
                         const std::string& footerMore, const std::string& footerEnd) {
  constexpr int kTop = 32, kFooterH = 24, kRow = 20;
  const int bottom = LCD_H - kFooterH - 2;
  const int labelX = 6, labelW = 86, valX = 98, valW = LCD_W - valX - 12, fullW = LCD_W - labelX - 12;
  const int visible = (bottom - kTop) / kRow;  // 9

  std::vector<UiRow> rows;
  for (const UiLine& ln : lines) {
    std::vector<std::string> lab, val;
    const bool full = ln.label.empty();
    if (full) {
      val = ui_wrap(ln.value, fullW);
    } else {
      lab = ui_wrap(ln.label, labelW);
      val = ui_wrap(ln.value, valW);
    }
    size_t n = lab.size() > val.size() ? lab.size() : val.size();
    if (n == 0) n = 1;
    for (size_t r = 0; r < n; r++) {
      UiRow row;
      row.label = r < lab.size() ? lab[r] : std::string();
      row.value = r < val.size() ? val[r] : std::string();
      row.color = ln.color;
      row.full = full;
      row.last = r + 1 == n;
      rows.push_back(row);
    }
  }

  UiReview v;
  v.title = ui_sanitize(title);
  v.totalRows = int(rows.size());
  v.firstRow = review_clamp_first(firstRow, visible, v.totalRows);
  v.rowsShown = v.totalRows - v.firstRow < visible ? v.totalRows - v.firstRow : visible;
  v.moreAbove = v.firstRow > 0;
  v.moreBelow = v.firstRow + v.rowsShown < v.totalRows;
  for (int i = 0; i < v.rowsShown; i++) v.rows.push_back(rows[size_t(v.firstRow + i)]);
  v.footer = ui_sanitize(v.moreBelow ? footerMore : footerEnd);
  return v;
}

// ui.cpp ui_message(): body wrapped at W - 20, 22 px rows from y = 40
std::vector<std::string> ui_message_lines(const std::string& body) {
  const std::vector<std::string> lines = ui_wrap(body, LCD_W - 20);
  constexpr int kRow = 22;
  const size_t maxRows = size_t((LCD_H - 40) / kRow);
  std::vector<std::string> out;
  for (size_t i = 0; i < lines.size() && i < maxRows; i++) {
    std::string s = lines[i];
    if (i + 1 == maxRows && lines.size() > maxRows) s += " ...";
    out.push_back(s);
  }
  return out;
}

// ui.cpp ui_qr(): a UR is upper-cased (QR alphanumeric mode); version / ECC from qr_pick() for the 240 px height
UiQr ui_qr_model(const std::string& textIn) {
  UiQr q;
  q.text = textIn;
  if (q.text.size() >= 3 && (q.text[0] == 'u' || q.text[0] == 'U') && (q.text[1] == 'r' || q.text[1] == 'R') &&
      q.text[2] == ':')
    for (char& ch : q.text)
      if (ch >= 'a' && ch <= 'z') ch = char(ch - 'a' + 'A');
  int ecc = ECC_MEDIUM;
  q.version = qr_pick(q.text.data(), q.text.size(), LCD_H, kQrMaxVersion, ecc);
  q.scale = qr_scale(q.version, LCD_H);
  q.ecc = ecc == ECC_LOW ? 'L' : 'M';
  q.fits = q.version != 0 && q.scale >= 2 && q.text.size() <= 0xFFFF;
  (void)&qr_module;  // part of the extracted block; the companion draws the symbol itself
  return q;
}

}  // namespace emu
}  // namespace ripar
