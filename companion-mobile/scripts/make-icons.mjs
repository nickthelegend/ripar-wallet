// Draws the app icons (no image dependencies: a tiny PNG encoder over node:zlib). The mark is the record light: a
// signal-orange disc with a soft glow inside a thin ring, on graphite. Writes assets/icon.png (1024, full bleed),
// assets/android-icon-foreground.png (1024, transparent, inside the adaptive-icon safe zone), assets/splash-icon.png.
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateSync } from 'node:zlib';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
mkdirSync(join(root, 'assets'), { recursive: true });

const CRC = new Int32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});
const crc32 = (buf) => {
  let c = -1;
  for (const b of buf) c = CRC[(c ^ b) & 255] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
};
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
function png(w, h, rgba) {
  const raw = Buffer.alloc((w * 4 + 1) * h);
  for (let y = 0; y < h; y++) {
    raw[y * (w * 4 + 1)] = 0;
    rgba.copy(raw, y * (w * 4 + 1) + 1, y * w * 4, (y + 1) * w * 4);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0))]);
}

const hex = (h) => [parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16)];
const BG = hex('#0D0E10');
const ORANGE = hex('#FF6B1A');
const GLOW = hex('#FF7A2E');
const CREAM = hex('#F2ECE1');

/** composites `src` (rgb, alpha 0..1) over `dst` (rgba 0..255 floats) */
function over(dst, rgb, a) {
  const da = dst[3] / 255;
  const oa = a + da * (1 - a);
  if (oa <= 0) return;
  for (let i = 0; i < 3; i++) dst[i] = (rgb[i] * a + dst[i] * da * (1 - a)) / oa;
  dst[3] = oa * 255;
}

function draw(size, { background, scale }) {
  const buf = Buffer.alloc(size * size * 4);
  const c = size / 2;
  const disc = size * 0.2 * scale;
  const ring = size * 0.33 * scale;
  const ringW = size * 0.018 * scale;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const px = [0, 0, 0, 0];
      if (background) {
        px[0] = BG[0];
        px[1] = BG[1];
        px[2] = BG[2];
        px[3] = 255;
        // a faint top light on the graphite
        over(px, CREAM, 0.035 * Math.max(0, 1 - y / size));
      }
      const d = Math.hypot(x + 0.5 - c, y + 0.5 - c);
      // glow
      const g = Math.max(0, 1 - (d - disc) / (disc * 1.6));
      if (d > disc && g > 0) over(px, GLOW, 0.32 * g * g);
      // ring
      const rd = Math.abs(d - ring) - ringW / 2;
      if (rd < 1) over(px, CREAM, 0.55 * Math.min(1, Math.max(0, 1 - rd)));
      // disc, lit from the top left
      const cov = Math.min(1, Math.max(0, disc - d + 0.5));
      if (cov > 0) {
        const lx = (x - (c - disc * 0.35)) / disc;
        const ly = (y - (c - disc * 0.35)) / disc;
        const hi = Math.max(0, 1 - Math.hypot(lx, ly));
        over(px, [Math.min(255, ORANGE[0] + 30 * hi), Math.min(255, ORANGE[1] + 70 * hi), Math.min(255, ORANGE[2] + 60 * hi)], cov);
      }
      const o = (y * size + x) * 4;
      buf[o] = Math.round(px[0]);
      buf[o + 1] = Math.round(px[1]);
      buf[o + 2] = Math.round(px[2]);
      buf[o + 3] = Math.round(px[3]);
    }
  }
  return png(size, size, buf);
}

writeFileSync(join(root, 'assets/icon.png'), draw(1024, { background: true, scale: 1 }));
writeFileSync(join(root, 'assets/android-icon-foreground.png'), draw(1024, { background: false, scale: 0.72 }));
writeFileSync(join(root, 'assets/splash-icon.png'), draw(512, { background: false, scale: 1 }));
console.log('icons written to assets/');
