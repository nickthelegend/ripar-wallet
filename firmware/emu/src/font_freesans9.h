// Glyph metrics of FreeSans9pt7b (the F_BODY font of src/ui.cpp), characters 0x20..0x7E: {width, xAdvance,
// xOffset}, copied from LovyanGFX src/lgfx/Fonts/GFXFF/FreeSans9pt7b.h (FreeSans9pt7bGlyphs[], the columns width /
// xAdvance / xOffset). Only the metrics are needed: the emulator wraps review and message text into display rows
// exactly as ui.cpp wrap() does with g->textWidth(), so the review pages exactly like the device (fsm.h paging).
#pragma once
#include <cstdint>

namespace ripar {
namespace emu {

struct GlyphMetric {
  uint8_t width, xAdvance;
  int8_t xOffset;
};

const GlyphMetric kFreeSans9[95] = {
    {0, 5, 0},   {2, 6, 2},   {5, 6, 1},   {10, 10, 0}, {9, 10, 1},  {16, 16, 1}, {11, 12, 1}, {2, 4, 1},
    {4, 6, 1},   {4, 6, 1},   {5, 7, 1},   {6, 11, 3},  {2, 5, 2},   {4, 6, 1},   {2, 5, 1},   {5, 5, 0},
    {8, 10, 1},  {4, 10, 3},  {9, 10, 1},  {8, 10, 1},  {7, 10, 2},  {9, 10, 1},  {9, 10, 1},  {8, 10, 0},
    {9, 10, 1},  {8, 10, 1},  {2, 5, 1},   {3, 5, 1},   {9, 11, 1},  {9, 11, 1},  {9, 11, 1},  {9, 10, 1},
    {17, 18, 1}, {12, 12, 0}, {11, 12, 1}, {11, 13, 1}, {11, 13, 1}, {9, 11, 1},  {8, 11, 1},  {12, 14, 1},
    {11, 13, 1}, {2, 5, 2},   {7, 10, 1},  {11, 12, 1}, {8, 10, 1},  {13, 15, 1}, {11, 13, 1}, {13, 14, 1},
    {10, 12, 1}, {13, 14, 1}, {12, 13, 1}, {10, 12, 1}, {9, 11, 1},  {11, 13, 1}, {11, 12, 0}, {17, 17, 0},
    {12, 12, 0}, {12, 12, 0}, {10, 11, 1}, {3, 5, 1},   {5, 5, 0},   {3, 5, 0},   {7, 8, 1},   {10, 10, 0},
    {4, 5, 0},   {9, 10, 1},  {9, 10, 1},  {8, 9, 1},   {8, 10, 1},  {8, 10, 1},  {4, 5, 1},   {8, 10, 1},
    {8, 10, 1},  {2, 4, 1},   {4, 4, 0},   {9, 9, 1},   {2, 4, 1},   {13, 15, 1}, {8, 10, 1},  {8, 10, 1},
    {9, 10, 1},  {8, 10, 1},  {5, 6, 1},   {8, 9, 1},   {4, 5, 1},   {8, 10, 1},  {9, 9, 0},   {13, 13, 0},
    {8, 9, 0},   {9, 9, 0},   {7, 9, 1},   {4, 6, 1},   {2, 4, 2},   {4, 6, 1},   {7, 9, 1},
};

}  // namespace emu
}  // namespace ripar
