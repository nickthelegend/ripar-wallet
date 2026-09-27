import { useEffect, useMemo, useState } from 'react';
import { StyleSheet, View } from 'react-native';
import Svg, { Path, Rect } from 'react-native-svg';
// the encoder core only (the package's main entry pulls in Node renderers)
import QRCodeCore from 'qrcode/lib/core/qrcode';
import type { QrFrames } from '../device/qr-link';
import { ink, palette, radius, space } from '../theme';
import { Text } from './Text';

export interface QrMatrix {
  size: number;
  path: string;
}

const cache = new Map<string, QrMatrix>();

/** QR modules as one SVG path of horizontal runs (alphanumeric mode for upper-case URs, ECC M) */
export function qrMatrix(text: string, ecc: 'L' | 'M' = 'M'): QrMatrix {
  const k = `${ecc}:${text}`;
  const hit = cache.get(k);
  if (hit) return hit;
  const q = QRCodeCore.create(text, { errorCorrectionLevel: ecc });
  const n: number = q.modules.size;
  const d: Uint8Array = q.modules.data;
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
  if (cache.size > 300) cache.clear();
  cache.set(k, m);
  return m;
}

/** black modules on a white plate with a 4-module quiet zone, whatever the theme: what a camera reads best */
export function QrCode({ text, size, label }: { text: string; size: number; label: string }) {
  const m = useMemo(() => qrMatrix(text), [text]);
  const v = m.size + 8;
  return (
    <View style={[styles.plate, { width: size, height: size }]} accessible accessibilityRole="image" accessibilityLabel={label}>
      <Svg width={size} height={size} viewBox={`-4 -4 ${v} ${v}`}>
        <Rect x={-4} y={-4} width={v} height={v} fill={palette.qrPaper} />
        <Path d={m.path} fill={palette.qrInk} />
      </Svg>
    </View>
  );
}

/**
 * The request as the device's camera sees it: the UR parts looped at `frameMs`, with one cell per part below (lit =
 * on screen now). The loop restarts at part 1 on every new request.
 */
export function AnimatedQr({ frames, size }: { frames: QrFrames; size: number }) {
  const [i, setI] = useState(0);
  useEffect(() => {
    setI(0);
    if (frames.parts.length < 2) return;
    const t = setInterval(() => setI((x) => (x + 1) % frames.parts.length), frames.frameMs);
    return () => clearInterval(t);
  }, [frames]);
  const part = frames.parts[i % frames.parts.length] ?? frames.parts[0]!;
  return (
    <View style={{ alignItems: 'center', gap: space.md }}>
      <QrCode text={part} size={size} label={`Request QR, part ${i + 1} of ${frames.parts.length}`} />
      {frames.parts.length > 1 && (
        <View style={styles.cells} accessibilityElementsHidden importantForAccessibility="no-hide-descendants">
          {frames.parts.map((p, k) => (
            <View key={p} style={[styles.cell, { backgroundColor: k === i ? palette.primary : ink.hairlineStrong }]} />
          ))}
        </View>
      )}
      <Text variant="monoSmall" tone="faint">
        {frames.parts.length > 1 ? `part ${i + 1} / ${frames.parts.length} · ${frames.frameMs} ms per frame` : 'single part'}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  plate: { borderRadius: radius.md, overflow: 'hidden', backgroundColor: palette.qrPaper },
  cells: { flexDirection: 'row', flexWrap: 'wrap', gap: 4, justifyContent: 'center', maxWidth: 280 },
  cell: { width: 14, height: 4, borderRadius: 2 },
});
