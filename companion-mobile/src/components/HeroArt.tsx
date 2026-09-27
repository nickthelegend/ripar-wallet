import type { ReactNode } from 'react';
import Svg, { Circle, Defs, Ellipse, G, Line, LinearGradient, Path, RadialGradient, Rect, Stop, Text as SvgText } from 'react-native-svg';
import { View } from 'react-native';
import { palette } from '../theme';

/**
 * The onboarding hero art: the Ripar device drawn as an object (thickness, a lit top edge, a soft floor shadow), in
 * three scenes. Vector, so it is sharp at any density and costs nothing to ship.
 */
export type HeroScene = 'airgap' | 'shows' | 'pulse';

function DeviceBody({ screen }: { screen: ReactNode }) {
  return (
    <G>
      {/* thickness: the back layer, offset down-right */}
      <Rect x={62} y={46} width={176} height={250} rx={30} fill="url(#side)" />
      {/* the front face */}
      <Rect x={50} y={34} width={176} height={250} rx={30} fill="url(#face)" />
      {/* top edge light */}
      <Path d="M80 35 H196" stroke="rgba(255,255,255,0.35)" strokeWidth={1.5} strokeLinecap="round" />
      {/* bezel + LCD */}
      <Rect x={66} y={52} width={144} height={112} rx={12} fill="#07090C" />
      <Rect x={72} y={58} width={132} height={100} rx={8} fill="url(#lcd)" />
      {screen}
      {/* the pulse pad with its record-light ring */}
      <Circle cx={138} cy={216} r={34} fill="url(#pad)" />
      <Circle cx={138} cy={216} r={34} fill="none" stroke={palette.primary} strokeOpacity={0.9} strokeWidth={3} />
      <Circle cx={138} cy={216} r={22} fill="#0B0D10" />
      <Circle cx={130} cy={208} r={7} fill="rgba(255,255,255,0.08)" />
      {/* the SIGN key */}
      <Rect x={186} y={258} width={28} height={12} rx={6} fill="#2A2E34" />
      <SvgText fontFamily="JetBrainsMono_500Medium, monospace" x={70} y={270} fontSize={10} fill="rgba(242,236,225,0.55)" fontWeight="600" letterSpacing={1.4}>
        RIPAR
      </SvgText>
    </G>
  );
}

function Common() {
  return (
    <Defs>
      <LinearGradient id="face" x1="0" y1="0" x2="1" y2="1">
        <Stop offset="0" stopColor="#3A3E45" />
        <Stop offset="0.45" stopColor="#23262B" />
        <Stop offset="1" stopColor="#15171A" />
      </LinearGradient>
      <LinearGradient id="side" x1="0" y1="0" x2="1" y2="1">
        <Stop offset="0" stopColor="#101114" />
        <Stop offset="1" stopColor="#050506" />
      </LinearGradient>
      <LinearGradient id="lcd" x1="0" y1="0" x2="0" y2="1">
        <Stop offset="0" stopColor="#10151B" />
        <Stop offset="1" stopColor="#07090C" />
      </LinearGradient>
      <RadialGradient id="pad" cx="0.4" cy="0.35" r="0.8">
        <Stop offset="0" stopColor="#3B2A20" />
        <Stop offset="1" stopColor="#141210" />
      </RadialGradient>
      <RadialGradient id="glow" cx="0.5" cy="0.5" r="0.5">
        <Stop offset="0" stopColor={palette.glow} stopOpacity="0.42" />
        <Stop offset="1" stopColor={palette.glow} stopOpacity="0" />
      </RadialGradient>
      <RadialGradient id="floor" cx="0.5" cy="0.5" r="0.5">
        <Stop offset="0" stopColor="#000" stopOpacity="0.7" />
        <Stop offset="1" stopColor="#000" stopOpacity="0" />
      </RadialGradient>
    </Defs>
  );
}

export function HeroArt({ scene, size }: { scene: HeroScene; size: number }) {
  return (
    <View accessibilityElementsHidden importantForAccessibility="no-hide-descendants">
    <Svg width={size} height={size * 1.1} viewBox="0 0 300 330">
      <Common />
      <Ellipse cx={150} cy={165} rx={150} ry={150} fill="url(#glow)" />
      <Ellipse cx={150} cy={312} rx={110} ry={14} fill="url(#floor)" />
      <G transform="rotate(-7 150 165)">
        {scene === 'airgap' && (
          <DeviceBody
            screen={
              <G>
                <SvgText fontFamily="JetBrainsMono_500Medium, monospace" x={82} y={80} fontSize={9} fill="#8FA3B8" letterSpacing={1}>
                  RIPAR · K1 0x7534…24Eb
                </SvgText>
                <SvgText fontFamily="JetBrainsMono_500Medium, monospace" x={82} y={104} fontSize={15} fill="#E8EEF4" fontWeight="700">
                  PAIRED
                </SvgText>
                <Rect x={82} y={116} width={70} height={16} rx={8} fill="rgba(107,212,154,0.18)" />
                <SvgText fontFamily="JetBrainsMono_500Medium, monospace" x={90} y={128} fontSize={9} fill={palette.success} fontWeight="700" letterSpacing={0.8}>
                  NO RADIO
                </SvgText>
                <SvgText fontFamily="JetBrainsMono_500Medium, monospace" x={82} y={148} fontSize={8} fill="#8FA3B8">
                  press SIGN = scan
                </SvgText>
              </G>
            }
          />
        )}
        {scene === 'shows' && (
          <DeviceBody
            screen={
              <G>
                <SvgText fontFamily="JetBrainsMono_500Medium, monospace" x={80} y={74} fontSize={9} fill="#E8EEF4" fontWeight="700" letterSpacing={0.8}>
                  CO-SIGN PAYMENT
                </SvgText>
                {[
                  ['Pay', '25 mUSD', '#E8EEF4'],
                  ['To', '0x9f3C…71aD', '#E8EEF4'],
                  ['Vault', 'this device', palette.success],
                  ['Expires', '09:21 UTC', '#E8EEF4'],
                ].map(([k, v, c], i) => (
                  <G key={k}>
                    <SvgText fontFamily="JetBrainsMono_500Medium, monospace" x={80} y={92 + i * 15} fontSize={8} fill="#8FA3B8">
                      {k}
                    </SvgText>
                    <SvgText fontFamily="JetBrainsMono_500Medium, monospace" x={118} y={92 + i * 15} fontSize={8.5} fill={c} fontWeight="600">
                      {v}
                    </SvgText>
                  </G>
                ))}
                <SvgText fontFamily="JetBrainsMono_500Medium, monospace" x={80} y={152} fontSize={8} fill="#FFB067">
                  press = PULSE + SIGN
                </SvgText>
              </G>
            }
          />
        )}
        {scene === 'pulse' && (
          <DeviceBody
            screen={
              <G>
                <Path d="M126 92c0-9 12-12 16-3 4-9 16-6 16 3 0 10-16 18-16 18s-16-8-16-18z" fill={palette.danger} />
                <SvgText fontFamily="JetBrainsMono_500Medium, monospace" x={116} y={132} fontSize={16} fill="#E8EEF4" fontWeight="700">
                  72 bpm
                </SvgText>
                <SvgText fontFamily="JetBrainsMono_500Medium, monospace" x={104} y={150} fontSize={8.5} fill={palette.success} fontWeight="700" letterSpacing={0.6}>
                  PULSE OK · press SIGN
                </SvgText>
              </G>
            }
          />
        )}
      </G>
      {scene === 'airgap' && (
        <G>
          {/* radio waves, struck through */}
          <Path d="M246 62a34 34 0 0 1 0 48M258 50a52 52 0 0 1 0 72" stroke={palette.steel} strokeWidth={4} strokeLinecap="round" fill="none" opacity={0.55} />
          <Line x1={238} y1={40} x2={282} y2={134} stroke={palette.danger} strokeWidth={5} strokeLinecap="round" />
          {/* a padlock badge */}
          <Circle cx={52} cy={250} r={26} fill={palette.primary} />
          <Rect x={41} y={248} width={22} height={17} rx={3} fill={palette.primaryForeground} />
          <Path d="M45 248v-5a7 7 0 0 1 14 0v5" stroke={palette.primaryForeground} strokeWidth={3} fill="none" />
        </G>
      )}
      {scene === 'shows' && (
        <G>
          <Circle cx={250} cy={236} r={30} fill={palette.success} />
          <Path d="M236 236l10 10 18-20" stroke="#0D0E10" strokeWidth={6} strokeLinecap="round" strokeLinejoin="round" fill="none" />
        </G>
      )}
      {scene === 'pulse' && (
        <G>
          <Path d="M18 60h40l10-22 16 48 12-30 8 14h40" stroke={palette.primary} strokeWidth={4} fill="none" strokeLinecap="round" strokeLinejoin="round" />
          <Circle cx={250} cy={250} r={28} fill={palette.primary} />
          <SvgText fontFamily="JetBrainsMono_500Medium, monospace" x={234} y={255} fontSize={12} fill={palette.primaryForeground} fontWeight="800">
            SIGN
          </SvgText>
        </G>
      )}
    </Svg>
    </View>
  );
}
