// Draws the emulated device's 320 x 240 LCD from state().display, following firmware/src/ui.cpp's layout (header 28,
// review rows 20 px from y 32, footer 24, pulse ring at (82, 136), QR on the left with its title / footer on the
// right). The firmware already wrapped and paged every row; this only paints them. Fonts are the companion's.
import { qrMatrix } from '../components/QrPlate';
import type { EmuDisplay, EmuState } from './emulator';

export const LCD_W = 320;
export const LCD_H = 240;

const C = {
  bg: '#000000',
  text: '#ffffff',
  dim: '#8c8c8c',
  faint: '#2d2d2d',
  accent: '#00c8aa',
  head: '#14283c',
  foot: '#1e1e1e',
  good: '#28d250',
  warn: '#ffb000',
  bad: '#f02828',
};

const SANS = "'Helvetica Neue', Helvetica, Arial, 'Liberation Sans', sans-serif";
const MONO = "ui-monospace, 'Cascadia Mono', Consolas, monospace";
const F_BODY = `13px ${SANS}`;
const F_BOLD = `bold 13px ${SANS}`;
const F_SMALL = `11px ${SANS}`;
const F_MID = `bold 16px ${SANS}`;
const F_BIG = `bold 32px ${SANS}`;

function readableOn(hex: string): string {
  const m = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex);
  if (!m) return C.text;
  const [r, g, b] = [parseInt(m[1]!, 16), parseInt(m[2]!, 16), parseInt(m[3]!, 16)];
  return (r * 299 + g * 587 + b * 114) / 1000 > 140 ? '#000000' : '#ffffff';
}

function text(
  g: CanvasRenderingContext2D,
  s: string,
  x: number,
  y: number,
  color: string,
  font: string,
  align: CanvasTextAlign = 'left',
  baseline: CanvasTextBaseline = 'top',
) {
  g.font = font;
  g.fillStyle = color;
  g.textAlign = align;
  g.textBaseline = baseline;
  g.fillText(s, x, y);
}

function fitText(g: CanvasRenderingContext2D, s: string, maxW: number, fonts: string[]): string {
  for (const f of fonts) {
    g.font = f;
    if (g.measureText(s).width <= maxW) return f;
  }
  return fonts[fonts.length - 1]!;
}

function wrap(g: CanvasRenderingContext2D, s: string, maxW: number): string[] {
  const words = s.split(/\s+/).filter(Boolean);
  const out: string[] = [];
  let line = '';
  for (const w of words) {
    const t = line ? `${line} ${w}` : w;
    if (g.measureText(t).width <= maxW || !line) line = t;
    else {
      out.push(line);
      line = w;
    }
  }
  if (line) out.push(line);
  return out;
}

function header(g: CanvasRenderingContext2D, title: string, bg: string) {
  g.fillStyle = bg;
  g.fillRect(0, 0, LCD_W, 28);
  const f = fitText(g, title, LCD_W - 16, [F_BOLD, F_SMALL]);
  text(g, title, 8, 14, readableOn(bg), f, 'left', 'middle');
}

function footer(g: CanvasRenderingContext2D, s: string, h = 24) {
  g.fillStyle = C.foot;
  g.fillRect(0, LCD_H - h, LCD_W, h);
  const f = fitText(g, s, LCD_W - 12, [F_BODY, F_SMALL, `9px ${SANS}`]);
  text(g, s, LCD_W / 2, LCD_H - h / 2, C.text, f, 'center', 'middle');
}

function heart(g: CanvasRenderingContext2D, cx: number, cy: number, r: number, color: string) {
  g.fillStyle = color;
  g.beginPath();
  g.moveTo(cx, cy + r * 0.9);
  g.bezierCurveTo(cx - r * 1.4, cy - r * 0.1, cx - r * 0.7, cy - r * 1.2, cx, cy - r * 0.45);
  g.bezierCurveTo(cx + r * 0.7, cy - r * 1.2, cx + r * 1.4, cy - r * 0.1, cx, cy + r * 0.9);
  g.fill();
}

/**
 * The rows of the review page on screen. The emulator's `display.rows` already IS the visible page (firmware/emu
 * README: "exactly as ui_review() pages them"; rows.length <= rowsShown) and `firstRow` is the page's absolute index
 * into the whole review, used only for the scrollbar. Slicing again with firstRow blanked every page after the first.
 * A display that carries every row (rows.length > rowsShown) is paged here.
 */
export function visibleReviewRows(d: Extract<EmuDisplay, { kind: 'review' }>): Extract<EmuDisplay, { kind: 'review' }>['rows'] {
  if (d.rows.length > d.rowsShown) return d.rows.slice(d.firstRow, d.firstRow + d.rowsShown);
  return d.rows;
}

export function drawLcd(g: CanvasRenderingContext2D, d: EmuDisplay, s: EmuState, beatOn = false): void {
  g.save();
  g.fillStyle = C.bg;
  g.fillRect(0, 0, LCD_W, LCD_H);
  switch (d.kind) {
    case 'boot': {
      text(g, 'RIPAR', LCD_W / 2, 92, C.accent, F_BIG, 'center', 'middle');
      text(g, 'air-gapped signer', LCD_W / 2, 132, C.dim, F_BODY, 'center', 'middle');
      d.lines.slice(0, 2).forEach((l, i) => text(g, l, LCD_W / 2, 180 + 22 * i, C.text, F_BODY, 'center', 'middle'));
      break;
    }
    case 'home': {
      text(g, 'AIR-GAPPED', 8, 6, C.accent, F_SMALL);
      const pct = `${Math.min(100, d.battery)}%`;
      g.strokeStyle = C.dim;
      g.lineWidth = 1;
      g.strokeRect(LCD_W - 33.5, 6.5, 24, 12);
      g.fillStyle = C.dim;
      g.fillRect(LCD_W - 10, 9, 2, 6);
      g.fillStyle = d.battery < 20 ? C.bad : d.battery < 50 ? C.warn : C.good;
      g.fillRect(LCD_W - 32, 8, Math.round((20 * Math.min(100, d.battery) + 50) / 100), 8);
      text(g, pct, LCD_W - 40, 6, C.dim, F_SMALL, 'right');
      g.fillStyle = C.faint;
      g.fillRect(0, 26, LCD_W, 1);
      text(g, 'RIPAR', LCD_W / 2, 72, C.accent, F_BIG, 'center', 'middle');
      text(g, 'K1', LCD_W / 2, 112, C.dim, F_SMALL, 'center', 'middle');
      if (d.k1Short) text(g, d.k1Short, LCD_W / 2, 138, C.text, `15px ${MONO}`, 'center', 'middle');
      else text(g, 'no keys yet', LCD_W / 2, 138, C.warn, F_MID, 'center', 'middle');
      g.font = F_BOLD;
      const bw = g.measureText(d.badge).width + 20;
      g.strokeStyle = d.badgeColorHex;
      g.lineWidth = 1;
      g.beginPath();
      g.roundRect(LCD_W / 2 - bw / 2 + 0.5, 160.5, bw, 24, 6);
      g.stroke();
      text(g, d.badge, LCD_W / 2, 172, d.badgeColorHex, F_BOLD, 'center', 'middle');
      g.fillStyle = C.foot;
      g.fillRect(0, LCD_H - 30, LCD_W, 30);
      const [h0, h1, h2] = d.hints;
      if (h0) text(g, h0, 8, LCD_H - 15, C.text, F_BODY, 'left', 'middle');
      if (h1) text(g, h1, LCD_W / 2 + 12, LCD_H - 15, C.dim, F_BODY, 'center', 'middle');
      if (h2) text(g, h2, LCD_W - 8, LCD_H - 15, C.bad, F_BODY, 'right', 'middle');
      break;
    }
    case 'scan': {
      // no camera image in the emulator: the frame the companion shows is handed over as text
      text(g, 'camera: companion QR frames', LCD_W / 2, LCD_H / 2 + 4, C.dim, F_BODY, 'center', 'middle');
      const sz = 180;
      const x0 = (LCD_W - sz) / 2;
      const y0 = (LCD_H - sz) / 2 + 4;
      const L = 22;
      g.fillStyle = C.accent;
      for (const [x, y, w, h] of [
        [x0, y0, L, 3],
        [x0, y0, 3, L],
        [x0 + sz - L, y0, L, 3],
        [x0 + sz - 3, y0, 3, L],
        [x0, y0 + sz - 3, L, 3],
        [x0, y0 + sz - L, 3, L],
        [x0 + sz - L, y0 + sz - 3, L, 3],
        [x0 + sz - 3, y0 + sz - L, 3, L],
      ] as const)
        g.fillRect(x, y, w, h);
      if (d.hint) {
        g.fillStyle = C.bg;
        g.fillRect(0, 0, LCD_W, 22);
        const f = fitText(g, d.hint, LCD_W - 8, [F_BODY, F_SMALL]);
        text(g, d.hint, LCD_W / 2, 11, C.text, f, 'center', 'middle');
      }
      if (d.progress > 0) {
        const p = Math.min(1, d.progress);
        g.fillStyle = C.bg;
        g.fillRect(0, LCD_H - 18, LCD_W, 18);
        g.strokeStyle = C.dim;
        g.strokeRect(8.5, LCD_H - 12.5, LCD_W - 64, 8);
        g.fillStyle = C.accent;
        g.fillRect(10, LCD_H - 11, Math.round((LCD_W - 68) * p), 4);
        text(g, `${Math.round(p * 100)}%`, LCD_W - 8, LCD_H - 9, C.text, F_SMALL, 'right', 'middle');
      }
      break;
    }
    case 'review': {
      header(g, d.title, C.head);
      const kTop = 32;
      const kRow = 20;
      const bottom = LCD_H - 24 - 2;
      visibleReviewRows(d).forEach((row, i) => {
        const y = kTop + i * kRow;
        if (row.label) text(g, row.label, 6, y + 2, C.dim, F_BODY);
        if (row.value) text(g, row.value, row.full ? 6 : 98, y + 2, row.colorHex, F_BODY);
        if (row.last && i + 1 < d.rowsShown) {
          g.fillStyle = C.faint;
          g.fillRect(6, y + kRow - 2, LCD_W - 18, 1);
        }
      });
      if (d.moreAbove || d.moreBelow) {
        const trackH = bottom - kTop;
        g.fillStyle = C.faint;
        g.fillRect(LCD_W - 5, kTop, 3, trackH);
        const total = Math.max(1, d.totalRows);
        const thumbH = Math.max(10, Math.floor((trackH * d.rowsShown) / total));
        let thumbY = kTop + Math.floor((trackH * d.firstRow) / total);
        if (thumbY + thumbH > bottom) thumbY = bottom - thumbH;
        g.fillStyle = C.accent;
        g.fillRect(LCD_W - 5, thumbY, 3, thumbH);
      }
      g.fillStyle = C.accent;
      if (d.moreAbove) {
        g.beginPath();
        g.moveTo(LCD_W - 22, kTop + 8);
        g.lineTo(LCD_W - 12, kTop + 8);
        g.lineTo(LCD_W - 17, kTop + 2);
        g.fill();
      }
      if (d.moreBelow) {
        g.beginPath();
        g.moveTo(LCD_W - 22, bottom - 8);
        g.lineTo(LCD_W - 12, bottom - 8);
        g.lineTo(LCD_W - 17, bottom - 2);
        g.fill();
      }
      footer(g, d.footer);
      break;
    }
    case 'pulse': {
      header(g, d.title, C.head);
      const cx = 82;
      const cy = 136;
      g.lineWidth = 8;
      g.strokeStyle = C.faint;
      g.beginPath();
      g.arc(cx, cy, 62, 0, Math.PI * 2);
      g.stroke();
      g.strokeStyle = d.ringColorHex;
      g.beginPath();
      g.arc(cx, cy, 62, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * Math.min(1, d.progress));
      g.stroke();
      heart(g, cx, cy, d.heartBig || beatOn ? 34 : 27, d.finger ? C.bad : C.faint);
      const tx = 170;
      text(g, d.bpmText, tx, 34, C.text, F_BIG);
      g.font = F_BIG;
      text(g, 'BPM', tx + g.measureText(d.bpmText).width + 8, 58, C.dim, F_BODY);
      text(g, d.beatsText, tx, 100, C.dim, F_BODY);
      text(g, d.elapsedText, tx, 122, C.dim, F_BODY);
      g.font = F_BOLD;
      wrap(g, d.status, LCD_W - tx - 6)
        .slice(0, 3)
        .forEach((l, i) => text(g, l, tx, 154 + 22 * i, d.statusColorHex, F_BOLD));
      break;
    }
    case 'qr': {
      let m;
      try {
        m = qrMatrix(d.text, d.ecc, d.version);
      } catch {
        m = qrMatrix(d.text, d.ecc);
      }
      const scale = Math.max(1, Math.min(d.scale, Math.floor(LCD_H / (m.size + 8))));
      const side = (m.size + 8) * scale;
      const y0 = Math.floor((LCD_H - side) / 2);
      g.fillStyle = '#ffffff';
      g.fillRect(0, y0, side, side);
      g.save();
      g.translate(4 * scale, y0 + 4 * scale);
      g.scale(scale, scale);
      g.fillStyle = '#000000';
      g.fill(new Path2D(m.path));
      g.restore();
      const px = side + 8;
      const pw = LCD_W - px - 4;
      if (pw >= 40) {
        const tf = pw >= 110 ? F_BOLD : F_SMALL;
        const ff = pw >= 110 ? F_BODY : `10px ${SANS}`;
        const trow = pw >= 110 ? 20 : 16;
        const frow = pw >= 110 ? 20 : 12;
        g.font = tf;
        wrap(g, d.title, pw)
          .slice(0, Math.floor((LCD_H / 2 - 8) / trow))
          .forEach((l, i) => text(g, l, px, 8 + i * trow, C.accent, tf));
        g.font = ff;
        const fl = wrap(g, d.footer, pw);
        let y = Math.max(LCD_H / 2, LCD_H - 6 - fl.length * frow);
        for (const l of fl) {
          if (y + frow > LCD_H) break;
          text(g, l, px, y, C.text, ff);
          y += frow;
        }
        text(g, `v${d.version}-${d.ecc}`, px, LCD_H / 2 - 14, '#555555', `9px ${SANS}`);
      }
      break;
    }
    case 'message': {
      header(g, d.title, d.colorHex);
      g.font = F_BODY;
      d.lines.slice(0, 9).forEach((l, i) => text(g, l, 10, 40 + i * 22, C.text, F_BODY));
      break;
    }
  }
  if (s.screen === 'fail') {
    g.fillStyle = 'rgba(240,40,40,0.12)';
    g.fillRect(0, 0, LCD_W, LCD_H);
  }
  g.restore();
}

/** one sentence describing the screen, for assistive technology */
export function describeLcd(d: EmuDisplay): string {
  switch (d.kind) {
    case 'home':
      return `Home screen. ${d.badge}. K1 ${d.k1Short}. ${d.hints.join(', ')}.`;
    case 'scan':
      return `Scanning. ${d.hint} ${d.progress > 0 ? `${Math.round(d.progress * 100)} percent received.` : ''}`;
    case 'review': {
      const rows = visibleReviewRows(d).map((r) => `${r.label} ${r.value}`.trim());
      const page = d.totalRows > d.rowsShown ? ` Rows ${d.firstRow + 1} to ${Math.min(d.totalRows, d.firstRow + rows.length)} of ${d.totalRows}.` : '';
      return `${d.title}.${page} ${rows.join('. ')}. ${d.footer}`;
    }
    case 'pulse':
      return `${d.title}. ${d.bpmText} BPM, ${d.beatsText}. ${d.status}`;
    case 'qr':
      return `${d.title}. Showing a QR code. ${d.footer}`;
    case 'message':
      return `${d.title}. ${d.lines.join(' ')}`;
    case 'boot':
      return `Starting. ${d.lines.join(' ')}`;
  }
}
