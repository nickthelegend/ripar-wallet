// What to do on the device now: the per-round step lists (docs/FIRMWARE.md §5 is the key table), the next action
// from a live STATUS (Bluetooth / emulator), and advice for the refusal reasons the device shows (ported from
// companion/src/device/guide.ts). Pure functions: tested in test/guide.test.ts.
import type { DeviceStatus, LinkKind } from './link';

export type RoundKind = 'keys' | 'pair' | 'mandate' | 'cosign' | 'kill';

export interface GuideLine {
  text: string;
  tone: 'info' | 'warn' | 'bad' | 'good';
}

/** the steps of one round on the device, for the given link */
export function roundSteps(kind: RoundKind, link: LinkKind): string[] {
  const answer = link === 'qr' ? "Point this phone's camera at the answer QR the Ripar shows." : 'The answer comes back by itself.';
  if (kind === 'keys') {
    return [
      'On Home, hold SIGN for 2 s until RELEASE = PAIRING QR appears, then let go. (Holding 5 s is PANIC.)',
      link === 'qr' ? "Point this phone's camera at the pairing QR." : 'The keys come back by themselves.',
    ];
  }
  if (kind === 'kill') {
    return [
      'PANIC: hold SIGN 5 s on Home. It kills every mandate this device signed.',
      'REVOKE or REOPEN: hold SIGN 2 s and let go, then hold 2 s again for the menu; pick the item with a 2 s hold.',
      'Read the review, thumb on the sensor until PULSE OK, press SIGN (PANIC signs at once).',
      answer,
    ];
  }
  const feed =
    link === 'qr'
      ? "Hold the Ripar's camera over the QR on this phone until the review opens."
      : link === 'ble'
        ? 'This phone sends the request over Bluetooth; the review opens by itself.'
        : link === 'wifi'
          ? 'This phone sends the request over Wi-Fi; the review opens by itself.'
          : 'The emulator receives the request; the review opens by itself.';
  return [
    'On the Ripar Home screen, press SIGN once: it starts scanning.',
    feed,
    kind === 'cosign'
      ? 'Read every page (SIGN = next page). To refuse, hold SIGN 2 s: DENY + REPORT AGENT.'
      : 'Read every page: SIGN = next page. Hold 2 s to cancel.',
    'Thumb on the pulse sensor until PULSE OK, then press SIGN.',
    answer,
  ];
}

/** which step of roundSteps() a live device screen corresponds to (for request rounds) */
export function stepOfScreen(screen: string | null | undefined, kind: RoundKind): number {
  if (kind === 'keys') return screen === 'QR' ? 1 : 0;
  if (kind === 'kill') return screen === 'QR' ? 3 : screen === 'REVIEW' || screen === 'PULSE' || screen === 'ARMED' ? 2 : screen === 'MENU' ? 1 : 0;
  switch (screen) {
    case 'SCAN':
      return 1;
    case 'REVIEW':
      return 2;
    case 'PULSE':
    case 'ARMED':
      return 3;
    case 'QR':
      return 4;
    default:
      return 0;
  }
}

/** the next action on the device from its live status (Bluetooth STATUS or the emulator) */
export function liveGuide(s: DeviceStatus | null, kind: RoundKind, hasRequest: boolean): GuideLine {
  if (!s) return { text: 'Waiting for the device status...', tone: 'info' };
  // the device says why it did not use the last line (docs/BLE_LINK.md §4.5 note)
  if (s.note && /not on SCAN/i.test(s.note) && s.screen === 'HOME' && hasRequest) {
    return { text: `The Ripar ignored the request because it is not scanning: press SIGN once on its Home screen. (${s.note})`, tone: 'warn' };
  }
  switch (s.screen) {
    case 'HOME':
      if (kind === 'keys') return { text: 'Hold SIGN 2 s, then let go at RELEASE = PAIRING QR.', tone: 'info' };
      if (kind === 'kill') return { text: 'PANIC: hold SIGN 5 s. REVOKE / REOPEN: hold 2 s, let go, hold 2 s for the menu.', tone: 'info' };
      return hasRequest
        ? { text: 'Press SIGN once on the Ripar: it starts scanning, and only then accepts the request.', tone: 'warn' }
        : { text: 'Waiting for a request.', tone: 'info' };
    case 'SCAN':
      return s.scan && s.scan.of > 1
        ? { text: `Receiving the request: ${s.scan.got} of ${s.scan.of} parts.`, tone: 'info' }
        : { text: hasRequest ? 'Scanning: sending the request.' : 'The device is scanning, but nothing is being sent: hold SIGN 2 s to cancel.', tone: 'info' };
    case 'REVIEW':
      return kind === 'cosign'
        ? { text: 'Read every page on the Ripar (SIGN = next). Hold SIGN 2 s to deny instead.', tone: 'info' }
        : { text: 'Read every page on the Ripar (SIGN = next page).', tone: 'info' };
    case 'PULSE':
      return { text: 'Thumb on the pulse sensor. Hold still until PULSE OK.', tone: 'info' };
    case 'ARMED':
      return { text: 'PULSE OK: press SIGN now.', tone: 'good' };
    case 'QR':
      return { text: 'The Ripar shows its answer. Press SIGN on it afterwards to go Home.', tone: 'good' };
    case 'MESSAGE':
      return { text: 'The Ripar shows a message (a refusal or an error). Read it, then press SIGN to go Home.', tone: 'bad' };
    case 'MENU':
      return { text: 'Device menu: SIGN = next item, hold 2 s = select.', tone: 'info' };
    case 'BLE_PAIR':
      return {
        text: 'BLE PAIRING: compare the 6-digit code on the Ripar with the one Android shows. Press SIGN on the Ripar to confirm (hold 2 s rejects), then confirm on the phone.',
        tone: 'warn',
      };
    default:
      return { text: `The Ripar is on ${s.screen}.`, tone: 'info' };
  }
}

/** advice for a refusal the device showed (its REFUSED line or message), or null when there is none to add */
export function refusalHelp(reason: string): string | null {
  const r = reason.toUpperCase();
  if (/VAULT IS NOT THIS DEVICE'?S VAULT/.test(r)) {
    return 'The device pins only the vault of its own K1. Read its keys again (Device tab > Pair), then pair: the app leaves the vault out so the device pins its own.';
  }
  if (/NOT THIS DEVICE'?S VAULT|VAULT MISMATCH/.test(r)) {
    return 'The request names another vault than the one this device derives from its K1: pair this device again, then retry.';
  }
  if (/WRONG (REGISTRY|PULSE CO-?SIGN ENFORCER|REPUTATION RELAY|DELEGATION MANAGER)/.test(r)) {
    return 'Firmware v1.2 has the registry, enforcer, relay and DelegationManager compiled in and refuses any other: load the CREATE2 deployment in Settings, then pair again.';
  }
  if (/DIFFERS FROM FIRMWARE TABLE/.test(r)) return 'The device pinned a contract from an older pairing: pair it again.';
  if (/UNSUPPORTED CHAIN/.test(r)) return 'The device knows only Monad testnet (10143) and Monad (143).';
  if (/PAIRING LOST/.test(r)) return 'The device dropped its pinned context: pair it again (the app sends the on-chain panic floor and reopen nonce).';
  if (/PANIC FIRST/.test(r)) {
    return 'Mandates this device signed may still be live: hold SIGN 5 s on Home (PANIC), relay it from the Device tab, then pair again.';
  }
  if (/STALE|EPOCH/.test(r)) return "The mandate's epoch is below the device's panic floor: relay the last PANIC, then sign the mandate again.";
  if (/NOT PAIRED|UNPAIRED/.test(r)) return 'The device is not paired yet: pair it from the Device tab.';
  if (/EXPIRED|EXPIRY/.test(r)) return "The device's clock is behind or the request expired: pair again (it updates the device time) or build a new request.";
  if (/UNKNOWN CALLDATA/.test(r)) return 'The device only signs native sends and ERC-20 transfer / approve / transferFrom.';
  if (/CHAIN/.test(r)) return 'The request names another chain than the one the device pinned.';
  if (/NOT PINNED|PINNED/.test(r)) return 'The request names a contract the device did not pin: check the deployment in Settings and pair again.';
  return null;
}

/** turning the Bluetooth fallback on and pairing this phone (docs/BLE_LINK.md §2, §3, §5) */
export const BLE_SETUP_STEPS: readonly string[] = [
  'On the Ripar Home screen, hold SIGN 2 s and let go (pairing QR), then hold 2 s again: DEVICE ACTIONS.',
  'Press SIGN until BLE LINK is selected, hold 2 s. The review says the radio turns ON and names RIPAR-XXXX.',
  'Thumb on the pulse sensor, then SIGN. The Ripar shows BLE PAIRING RIPAR-XXXX: pairing works only on that screen.',
  'Here: scan and pick the RIPAR-XXXX with the same name.',
  'Android shows a 6-digit code. If it matches the Ripar, press SIGN on the Ripar (hold 2 s rejects) and confirm on the phone.',
];

/** what the radio-on state means, said the way the device says it */
export const RADIO_ON_TEXT =
  'NOT AIR-GAPPED: the Ripar radio is on while BLE LINK runs (RADIO ON badge on every screen). It turns off with BLE OFF in the device menu, after 5 min without traffic, on PANIC and at power-off.';

// ------------------------------------------------------------------------------------------------ Wi-Fi (TEMPORARY)
/** what the Wi-Fi link means, said plainly (TEMPORARY: for testing) */
export const WIFI_ON_TEXT =
  "Turns the device's Wi-Fi on - Ripar is NOT air-gapped while it is on. For testing. It stays on (also after a restart) until WI-FI OFF, FORGET WI-FI or PANIC on the device. QR stays the default and the recommended link.";

/** from sending the network over Bluetooth to a working Wi-Fi link: what happens on the device (firmware flows.cpp) */
export function wifiDeviceSteps(ssid: string | null): string[] {
  return [
    `The Ripar opens JOIN WI-FI ${ssid ? ssid : '<network>'}? Read it (SIGN = next page) and press SIGN on the last page to store the network. No pulse; hold 2 s to refuse. It says WI-FI SAVED.`,
    'Turn Wi-Fi on: on Home hold SIGN 2 s and let go (pairing QR), hold 2 s again (DEVICE ACTIONS), press SIGN until WI-FI ON, hold 2 s. Read WI-FI ON: TURN WI-FI ON? and press SIGN on the last page.',
    'Home now says NOT AIR-GAPPED and shows the address and CODE 1234 5678 (a new code after every restart of the Ripar).',
    'Here: type the code (the address is filled in when the device reports it) and test the link.',
  ];
}

export interface LinkMeta {
  title: string;
  /** short label for pills */
  short: string;
  icon: 'qr' | 'bluetooth' | 'device' | 'wifi';
  tone: 'signal' | 'warn' | 'info';
  /** the device has a radio on while this link is used */
  radio: boolean;
}

/** how each link is named and marked across the app */
export function linkMeta(choice: 'qr' | 'ble' | 'emulator' | 'wifi'): LinkMeta {
  switch (choice) {
    case 'qr':
      return { title: 'QR codes (air-gapped)', short: 'QR · air-gapped', icon: 'qr', tone: 'signal', radio: false };
    case 'ble':
      return { title: 'Bluetooth fallback', short: 'Bluetooth', icon: 'bluetooth', tone: 'warn', radio: true };
    case 'wifi':
      return { title: 'Wi-Fi (testing)', short: 'Wi-Fi · testing', icon: 'wifi', tone: 'warn', radio: true };
    default:
      return { title: 'Emulator', short: 'Emulator', icon: 'device', tone: 'info', radio: false };
  }
}
