// Screen model of the emulator: what src/ui.cpp would put on the 320x240 LCD, as data for the web companion to draw.
//
// Every layout decision that changes what the user can SEE or what the state machine is told (fsm.h review_drawn) is
// reproduced exactly: the review's display rows (ui.cpp wrap() with the FreeSans9pt7b metrics, label column 86 px,
// value column 210 px, full width 302 px), the 9 visible rows and their clamping (fsm.h review_clamp_first), the
// more-above / more-below indicators and the footer choice, the message body rows (300 px, 9 rows, " ..."), and the
// QR version / ECC choice of ui_qr() (the QR-CAPACITY block of ui.cpp, extracted at build time). Pixel drawing
// (fonts, colours, icons) is left to the companion.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "pulse_algo.h"

namespace ripar {
namespace emu {

// device.h UI_* colours (review.h Tone -> Normal UI_TEXT, Good UI_GOOD, Warn UI_WARN, Bad UI_BAD, Dim UI_DIM)
enum class UiColor : uint8_t { Text, Dim, Accent, Good, Warn, Bad };
const char* ui_color_name(UiColor c);  // "text", "dim", "accent", "good", "warn", "bad"
const char* ui_color_hex(UiColor c);   // the RGB the firmware passes to ui_rgb(): "#ffffff", ...

// device.h ReviewLine
struct UiLine {
  std::string label, value;
  UiColor color = UiColor::Text;
};

// one display row of ui_review()
struct UiRow {
  std::string label, value;
  UiColor color = UiColor::Text;
  bool full = false;  // value over the full width (empty label)
  bool last = false;  // last row of its line (ui.cpp draws a separator below it)
};

// device.h ReviewView + the rows that were drawn + the footer that was chosen
struct UiReview {
  std::string title;
  std::vector<UiRow> rows;  // the visible rows only (rowsShown of them)
  int firstRow = 0, rowsShown = 0, totalRows = 0;
  bool moreAbove = false, moreBelow = false;
  std::string footer;
};

const int LCD_W = 320, LCD_H = 240;
const int REVIEW_VISIBLE_ROWS = 9;  // ui_review(): (240 - 24 - 2 - 32) / 20

// ui.cpp text helpers (FreeSans9pt7b)
std::string ui_sanitize(const std::string& s);
int ui_text_width(const std::string& s);                              // g->textWidth() in F_BODY
std::vector<std::string> ui_wrap(const std::string& text, int maxW);  // ui.cpp wrap() in F_BODY

// ui_review(): rows, clamping, indicators, footer
UiReview ui_review_model(const std::string& title, const std::vector<UiLine>& lines, int firstRow,
                         const std::string& footerMore, const std::string& footerEnd);
// ui_message(): the body rows as drawn (at most 9, the 9th ends in " ..." when more were cut)
std::vector<std::string> ui_message_lines(const std::string& body);

// ui_qr(): upper-cases a UR, picks the version / ECC level; false = "QR TOO LARGE" (the device shows that message)
struct UiQr {
  std::string text;  // what is encoded
  int version = 0;   // 1..25
  char ecc = 'M';    // 'M' or 'L'
  int scale = 0;     // module size in px
  bool fits = false;
};
UiQr ui_qr_model(const std::string& textIn);

}  // namespace emu
}  // namespace ripar
