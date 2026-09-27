// The request QR as the device's camera sees it: black modules on a white plate (both themes), a 4-module quiet
// zone, and one fixed cell per multipart part (lit = on screen now, grey = already shown this loop).
import QRCode from 'qrcode';
import { useMemo } from 'react';

export interface QrMatrix {
  size: number;
  path: string;
}

const cache = new Map<string, QrMatrix>();

/** QR modules as one SVG path of horizontal runs (alphanumeric mode for upper-case URs, ECC M) */
export function qrMatrix(text: string, ecc: 'L' | 'M' = 'M', version?: number): QrMatrix {
  const k = `${ecc}:${version ?? ''}:${text}`;
  const hit = cache.get(k);
  if (hit) return hit;
  const q = QRCode.create(text, { errorCorrectionLevel: ecc, ...(version ? { version } : {}) });
  const n = q.modules.size;
  const d = q.modules.data;
  let path = '';
  for (let y = 0; y < n; y++) {
    let x = 0;
    while (x < n) {
      if (!d[y * n + x]) {
        x++;
        continue;
      }
      let e = x + 1;
      while (e < n && d[y * n + e]) e++;
      path += `M${x} ${y}h${e - x}v1h${x - e}z`;
      x = e;
    }
  }
  const m = { size: n, path };
  if (cache.size > 400) cache.clear();
  cache.set(k, m);
  return m;
}

export function QrSvg({ text, label }: { text: string; label: string }) {
  const m = useMemo(() => qrMatrix(text), [text]);
  const v = m.size + 8;
  return (
    <svg className="qr" viewBox={`-4 -4 ${v} ${v}`} role="img" aria-label={label}>
      <rect x={-4} y={-4} width={v} height={v} fill="#fff" />
      <path d={m.path} fill="#000" />
    </svg>
  );
}

export function QrPlate({
  frame,
  index,
  total,
  seen,
  frameMs,
  idleText,
}: {
  frame: string | null;
  index: number;
  total: number;
  seen: Set<number>;
  frameMs: number;
  idleText: string;
}) {
  return (
    <div className="qr-plate">
      {frame ? (
        <QrSvg text={frame} label={total > 1 ? `Request QR code, part ${index + 1} of ${total}` : 'Request QR code'} />
      ) : (
        <div className="qr-empty">{idleText}</div>
      )}
      {frame && total > 1 && (
        <div className="cells" aria-hidden="true">
          {Array.from({ length: total }, (_, i) => (
            <i key={i} className={i === index ? 'on' : seen.has(i) ? 'seen' : undefined} />
          ))}
        </div>
      )}
      {frame && (
        <div className="qr-meta">
          <span>{total > 1 ? `Part ${index + 1} of ${total}` : 'Single part'}</span>
          <span>{total > 1 ? `${frameMs} ms per frame, looping` : 'Hold it in front of the camera'}</span>
        </div>
      )}
    </div>
  );
}
