import Svg, { Defs, LinearGradient, Path, Stop } from 'react-native-svg';
import { palette } from '../theme';

/** a small line with a soft fill under it; values are drawn left (oldest) to right (newest) */
export function Sparkline({ values, width, height, color = palette.primary }: { values: number[]; width: number; height: number; color?: string }) {
  const n = values.length;
  if (n < 2) return null;
  const max = Math.max(...values, 1e-9);
  const min = Math.min(...values, 0);
  const span = max - min || 1;
  const pts = values.map((v, i) => [(i / (n - 1)) * width, height - 3 - ((v - min) / span) * (height - 6)] as const);
  const line = pts.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)} ${y.toFixed(1)}`).join(' ');
  const area = `${line} L${width} ${height} L0 ${height} Z`;
  return (
    <Svg width={width} height={height}>
      <Defs>
        <LinearGradient id="spark" x1="0" y1="0" x2="0" y2="1">
          <Stop offset="0" stopColor={color} stopOpacity="0.28" />
          <Stop offset="1" stopColor={color} stopOpacity="0" />
        </LinearGradient>
      </Defs>
      <Path d={area} fill="url(#spark)" />
      <Path d={line} stroke={color} strokeWidth={2} fill="none" strokeLinejoin="round" strokeLinecap="round" />
    </Svg>
  );
}
