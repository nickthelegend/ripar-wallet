// One drawn icon set: 20 x 20, 1.6 px strokes, round caps. No glyphs or emoji stand in for icons.
import type { SVGProps } from 'react';

const PATHS: Record<string, string> = {
  check: 'M4 10.5l4 4 8-9',
  cross: 'M5 5l10 10M15 5L5 15',
  alert: 'M10 3.2l7.4 13H2.6L10 3.2zM10 8.2v4M10 14.6v.2',
  info: 'M10 17.5a7.5 7.5 0 100-15 7.5 7.5 0 000 15zM10 9v5M10 6.3v.2',
  copy: 'M7 7h9v9H7zM4 13V4h9',
  camera: 'M3 6.5h3l1.5-2h5L14 6.5h3v9.5H3zM10 13.6a2.8 2.8 0 100-5.6 2.8 2.8 0 000 5.6z',
  qr: 'M3 3h5v5H3zM12 3h5v5h-5zM3 12h5v5H3zM12 12h2v2h-2zM15 15h2v2h-2zM15 12h2M12 15v2',
  device: 'M2.5 5.5h15v9h-15zM5 8h6v4H5zM14 8.5h1.5v3H14zM13 5.5V4h3v1.5',
  power: 'M10 2.8v6.4M6 5.2a6 6 0 108 0',
  refresh: 'M16 6.5A6.5 6.5 0 104.3 13M16 3v3.5h-3.5',
  external: 'M11 4h5v5M16 4l-7 7M14 11.5V16H4V6h4.5',
  chevronDown: 'M5 7.5l5 5 5-5',
  chevronRight: 'M7.5 5l5 5-5 5',
  menu: 'M3 6h14M3 10h14M3 14h14',
  sun: 'M10 13.5a3.5 3.5 0 100-7 3.5 3.5 0 000 7zM10 1.8v2M10 16.2v2M1.8 10h2M16.2 10h2M4.2 4.2l1.4 1.4M14.4 14.4l1.4 1.4M4.2 15.8l1.4-1.4M14.4 5.6l1.4-1.4',
  moon: 'M16.5 12.3A7 7 0 017.7 3.5a7 7 0 108.8 8.8z',
  play: 'M6 4l10 6-10 6z',
  pause: 'M6 4h3v12H6zM11 4h3v12h-3z',
  send: 'M3 10l14-6-5 13-2.5-5.5L3 10zM9.5 11.5L17 4',
  lock: 'M5 9h10v8H5zM7 9V6.5a3 3 0 016 0V9',
  finger: 'M7 17V9a1.5 1.5 0 013 0v3M10 11V7.5a1.5 1.5 0 013 0V12M13 10.5a1.5 1.5 0 013 0V13c0 2.5-2 4.5-4.5 4.5H10c-2 0-3-1-4-2.5L4 12a1.4 1.4 0 012.2-1.6L7 11.5',
  heart: 'M10 16.5s-6.5-4-6.5-8.4A3.4 3.4 0 0110 6.3a3.4 3.4 0 016.5 1.8c0 4.4-6.5 8.4-6.5 8.4z',
  inbox: 'M3 11l2.5-6.5h9L17 11v5H3zM3 11h4l1 2h4l1-2h4',
  pulse: 'M2 10h4l2-5 4 10 2-5h4',
  vault: 'M3 4h14v12H3zM10 12.5a2.5 2.5 0 100-5 2.5 2.5 0 000 5zM10 7.5V6M5.5 16v1.5M14.5 16v1.5',
  link: 'M8.5 11.5a3.5 3.5 0 005 0l2.5-2.5a3.5 3.5 0 00-5-5L10 5M11.5 8.5a3.5 3.5 0 00-5 0L4 11a3.5 3.5 0 005 5l1-1',
  spinner: 'M10 2.5a7.5 7.5 0 107.5 7.5',
};

export type IconName = keyof typeof PATHS;

export function Icon({ name, size = 18, ...rest }: { name: IconName; size?: number } & SVGProps<SVGSVGElement>) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 20 20"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      <path d={PATHS[name]} />
    </svg>
  );
}
