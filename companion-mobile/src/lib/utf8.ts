// Strict UTF-8 encode / decode (WHATWG semantics for the subset the app needs), used as the TextEncoder / TextDecoder
// polyfill on Hermes and by the BLE line framing. Pure: unit-tested in test/link.test.ts.

export class Utf8Error extends TypeError {
  override name = 'Utf8Error';
}

export function utf8Encode(s: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
        i++;
      } else c = 0xfffd;
    } else if (c >= 0xd800 && c <= 0xdfff) c = 0xfffd;
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return Uint8Array.from(out);
}

/** decodes UTF-8; fatal = throw Utf8Error on any invalid sequence, else U+FFFD. A leading BOM is kept (ignoreBOM). */
export function utf8Decode(b: Uint8Array, fatal = true): string {
  let s = '';
  const bad = (): void => {
    if (fatal) throw new Utf8Error('invalid UTF-8');
    s += '�';
  };
  let i = 0;
  while (i < b.length) {
    const x = b[i]!;
    if (x < 0x80) {
      s += String.fromCharCode(x);
      i++;
      continue;
    }
    let n: number;
    let cp: number;
    let min: number;
    if (x >= 0xc2 && x <= 0xdf) [n, cp, min] = [1, x & 0x1f, 0x80];
    else if (x >= 0xe0 && x <= 0xef) [n, cp, min] = [2, x & 0x0f, 0x800];
    else if (x >= 0xf0 && x <= 0xf4) [n, cp, min] = [3, x & 0x07, 0x10000];
    else {
      bad();
      i++;
      continue;
    }
    if (i + n >= b.length) {
      // truncated sequence at the end of the input
      bad();
      break;
    }
    let ok = true;
    for (let k = 1; k <= n; k++) {
      const y = b[i + k];
      if (y === undefined || (y & 0xc0) !== 0x80) {
        ok = false;
        break;
      }
      cp = (cp << 6) | (y & 0x3f);
    }
    if (!ok || cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) {
      bad();
      i++;
      continue;
    }
    if (cp >= 0x10000) {
      const v = cp - 0x10000;
      s += String.fromCharCode(0xd800 + (v >> 10), 0xdc00 + (v & 0x3ff));
    } else s += String.fromCharCode(cp);
    i += n + 1;
  }
  return s;
}

class StrictTextDecoder {
  readonly encoding = 'utf-8';
  readonly fatal: boolean;
  readonly ignoreBOM: boolean;
  constructor(label = 'utf-8', opts: { fatal?: boolean; ignoreBOM?: boolean } = {}) {
    if (!/^utf-?8$/i.test(label)) throw new RangeError(`TextDecoder: only utf-8 is supported, not ${label}`);
    this.fatal = !!opts.fatal;
    this.ignoreBOM = !!opts.ignoreBOM;
  }
  decode(input?: ArrayBuffer | ArrayBufferView): string {
    if (!input) return '';
    const b =
      input instanceof Uint8Array
        ? input
        : ArrayBuffer.isView(input)
          ? new Uint8Array(input.buffer, input.byteOffset, input.byteLength)
          : new Uint8Array(input);
    const s = utf8Decode(b, this.fatal);
    return !this.ignoreBOM && s.charCodeAt(0) === 0xfeff ? s.slice(1) : s;
  }
}

class SimpleTextEncoder {
  readonly encoding = 'utf-8';
  encode(s = ''): Uint8Array {
    return utf8Encode(s);
  }
}

/** installs TextEncoder / a strict TextDecoder on `g` where the native ones are missing or do not honour `fatal` */
export function installTextCodec(g: Record<string, unknown>): void {
  if (typeof g.TextEncoder !== 'function') g.TextEncoder = SimpleTextEncoder;
  let nativeOk = false;
  try {
    const TD = g.TextDecoder as (new (l?: string, o?: { fatal?: boolean }) => { decode(b: Uint8Array): string }) | undefined;
    if (typeof TD === 'function') {
      const ok = new TD('utf-8', { fatal: true }).decode(Uint8Array.of(0xe2, 0x82, 0xac)) === '€';
      let refused = false;
      try {
        new TD('utf-8', { fatal: true }).decode(Uint8Array.of(0xff));
      } catch {
        refused = true;
      }
      nativeOk = ok && refused;
    }
  } catch {
    nativeOk = false;
  }
  if (!nativeOk) g.TextDecoder = StrictTextDecoder;
}
