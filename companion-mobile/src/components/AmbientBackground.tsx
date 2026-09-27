import { StyleSheet, useWindowDimensions, View } from 'react-native';
import Svg, { Defs, LinearGradient, Mask, Path, Pattern, RadialGradient, Rect, Stop } from 'react-native-svg';
import { palette } from '../theme';

/**
 * The ground. A raised plane needs something behind it to read as raised, and near-black gives it nothing. Two
 * layers, both far below the content and under 5 % opacity: a 64 px hairline grid faded out downward, and one warm
 * bloom in the upper right (the record light, out of focus).
 */
export function AmbientBackground() {
  const { width, height } = useWindowDimensions();
  const h = height * 1.1;
  return (
    <View style={[StyleSheet.absoluteFill, { pointerEvents: 'none' }]}>
      <Svg width={width} height={h} style={StyleSheet.absoluteFill}>
        <Defs>
          <Pattern id="grid" width={64} height={64} patternUnits="userSpaceOnUse">
            <Path d="M 64 0 L 0 0 0 64" fill="none" stroke={palette.foreground} strokeOpacity={0.035} strokeWidth={1} />
          </Pattern>
          <LinearGradient id="fade" x1="0" y1="0" x2="0" y2="1">
            <Stop offset="0" stopColor="#fff" stopOpacity="1" />
            <Stop offset="0.35" stopColor="#fff" stopOpacity="0.8" />
            <Stop offset="0.72" stopColor="#fff" stopOpacity="0" />
          </LinearGradient>
          <Mask id="gridMask">
            <Rect x="0" y="0" width={width} height={h} fill="url(#fade)" />
          </Mask>
          <RadialGradient id="bloom" cx="0.85" cy="0.02" rx="0.8" ry="0.5">
            <Stop offset="0" stopColor={palette.glow} stopOpacity="0.11" />
            <Stop offset="0.55" stopColor={palette.glow} stopOpacity="0.035" />
            <Stop offset="1" stopColor={palette.glow} stopOpacity="0" />
          </RadialGradient>
        </Defs>
        <Rect x="0" y="0" width={width} height={h} fill={palette.background} />
        <Rect x="0" y="0" width={width} height={h} fill="url(#grid)" mask="url(#gridMask)" />
        <Rect x="0" y="0" width={width} height={h} fill="url(#bloom)" />
      </Svg>
    </View>
  );
}
