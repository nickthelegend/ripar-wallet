import Svg, { Circle, Path } from 'react-native-svg';
import { palette } from '../theme';

/**
 * Line icons, drawn rather than imported: a 24 px stroked set small enough to own, so the weight matches the type.
 */
const PATHS = {
  home: 'M4 11l8-7 8 7v8a1 1 0 0 1-1 1h-4v-6h-6v6H5a1 1 0 0 1-1-1z',
  activity: 'M3 12h4l3-7 4 14 3-7h4',
  device: 'M8 3h8a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2zM9 6h6v6H9zM12 16.5v.01',
  agents: 'M12 3v3M8 7h8a3 3 0 0 1 3 3v5a3 3 0 0 1-3 3H8a3 3 0 0 1-3-3v-5a3 3 0 0 1 3-3zM9.5 12v.5M14.5 12v.5M3 12v2M21 12v2',
  settings: 'M4 7h10M18 7h2M4 17h4M12 17h8M16 5v4M10 15v4',
  send: 'M12 19V5M6 11l6-6 6 6',
  receive: 'M12 5v14M6 13l6 6 6-6',
  scan: 'M4 9V6a2 2 0 0 1 2-2h3M15 4h3a2 2 0 0 1 2 2v3M20 15v3a2 2 0 0 1-2 2h-3M9 20H6a2 2 0 0 1-2-2v-3M4 12h16',
  check: 'M5 12.5l4.5 4.5L19 7.5',
  close: 'M6 6l12 12M18 6L6 18',
  copy: 'M9 9h10v10H9zM5 15V5h10',
  share: 'M12 4v11M8 8l4-4 4 4M5 13v6h14v-6',
  shield: 'M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z',
  heart: 'M12 20s-7-4.5-7-10a4 4 0 0 1 7-2.5A4 4 0 0 1 19 10c0 5.5-7 10-7 10z',
  pulse: 'M3 12h4l2-4 3 9 2-6 2 3h5',
  qr: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h2v2h-2zM18 14h2M14 18h2v2M18 18h2v2h-2',
  bluetooth: 'M7 7l10 10-5 4V3l5 4L7 17',
  wifi: 'M3.5 9.5a12 12 0 0 1 17 0M6.5 12.5a7.8 7.8 0 0 1 11 0M9.4 15.4a3.7 3.7 0 0 1 5.2 0M12 19v.01',
  radio: 'M12 12v.01M8.5 8.5a5 5 0 0 0 0 7M15.5 8.5a5 5 0 0 1 0 7M5.5 5.5a9 9 0 0 0 0 13M18.5 5.5a9 9 0 0 1 0 13',
  noRadio: 'M3 3l18 18M8.5 8.5a5 5 0 0 0 0 7M15.5 15.5a5 5 0 0 0 0-7M5.5 5.5a9 9 0 0 0 0 13M18.5 18.5a9 9 0 0 0 0-13',
  chevron: 'M9 5l7 7-7 7',
  back: 'M15 5l-7 7 7 7',
  plus: 'M12 5v14M5 12h14',
  alert: 'M12 4l9 16H3zM12 10v4M12 17v.01',
  refresh: 'M4 12a8 8 0 0 1 14-5.3L20 9M20 4v5h-5M20 12a8 8 0 0 1-14 5.3L4 15M4 20v-5h5',
  key: 'M14 10a4 4 0 1 1-8 0 4 4 0 0 1 8 0zM13 12l7 7M17 16l2-2M15 18l2-2',
  lock: 'M6 11h12v9H6zM8.5 11V8a3.5 3.5 0 0 1 7 0v3',
  camera: 'M4 8h3l2-3h6l2 3h3v11H4zM12 17a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7z',
  clock: 'M12 7v5l3 2M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z',
  backspace: 'M9 6h11v12H9l-6-6zM12 10l4 4M16 10l-4 4',
  wallet: 'M4 7h15a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1zM4 7l12-3v3M16 13h2',
  bolt: 'M13 3L5 13h6l-1 8 8-10h-6z',
  deny: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM6 6l12 12',
  power: 'M12 3v8M7 6.5a7 7 0 1 0 10 0',
  link: 'M10 14a4 4 0 0 0 6 0l3-3a4 4 0 0 0-6-6l-1 1M14 10a4 4 0 0 0-6 0l-3 3a4 4 0 0 0 6 6l1-1',
  chart: 'M4 19h16M7 16V11M12 16V6M17 16v-3',
  thumb: 'M7 11v9H4v-9zM7 11l4-7a2 2 0 0 1 3 2l-1 4h5a2 2 0 0 1 2 2.3l-1.2 6A2 2 0 0 1 16.8 20H7',
  eye: 'M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12zM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z',
  sparkle: 'M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z',
} as const;

export type IconName = keyof typeof PATHS;

export function Icon({
  name,
  size = 22,
  color = palette.foreground,
  strokeWidth = 1.8,
}: {
  name: IconName;
  size?: number;
  color?: string;
  strokeWidth?: number;
}) {
  return (
    <Svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <Path d={PATHS[name]} stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round" />
    </Svg>
  );
}

/** a filled dot (status lights) */
export function Dot({ color, size = 8 }: { color: string; size?: number }) {
  return (
    <Svg width={size} height={size}>
      <Circle cx={size / 2} cy={size / 2} r={size / 2} fill={color} />
    </Svg>
  );
}
