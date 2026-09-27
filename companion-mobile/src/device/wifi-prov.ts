// Wi-Fi provisioning over Bluetooth: TEMPORARY, for testing the Wi-Fi link (wifi-link.ts) only.
//
// The phone writes the network's credentials to the PROV characteristic of the RIPAR LINK service
// (52495041-5200-4c49-4e4b-000000000005, write, needs the bonded / authenticated BLE link) as ONE UTF-8 JSON value
//
//   {"v":1,"ssid":"<1..32 bytes, no control characters>","pass":"<empty, or 8..63 printable ASCII>"}
//
// The firmware takes one write as one whole value (firmware/src/ble_link.cpp, at most 512 bytes): the value is never
// cut into separate writes. With these limits it is at most 217 bytes, so at the MTU the app asks for (247) it is one
// ATT write; on a link that stayed at a smaller MTU, Android sends a value longer than MTU-3 as a GATT long write
// (prepare + execute), which the firmware reassembles. The device takes it only while it shows HOME (or BLE PAIRING),
// opens the JOIN WI-FI <ssid>? review and stores the network only after SIGN; Wi-Fi itself is turned on from the
// device menu (WI-FI ON). A refused value shows up as the STATUS note ("wifi setup refused: ..." / "... ignored ...").
//
// The password is only ever in the encoded bytes handed to the BLE write: never logged, never stored, never part of an
// error message. Pure module (no React Native imports): unit-tested in test/wifi.test.ts.
import { utf8Encode } from '../lib/utf8';
import { attPayload } from './ble-framing';

export interface WifiCredentials {
  ssid: string;
  /** WPA2/WPA3 passphrase; empty for an open network */
  pass: string;
}

export const WIFI_PROV = {
  version: 1,
  ssidMaxBytes: 32,
  passMinBytes: 8,
  passMaxBytes: 63,
  /** the longest PROV value the firmware takes (one write or one long write) */
  maxValueBytes: 512,
} as const;

export class WifiProvisioningError extends RangeError {
  override name = 'WifiProvisioningError';
}

// C0 controls and DEL (the firmware refuses them in an SSID)
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f]/;
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?:^|[^\ud800-\udbff])[\udc00-\udfff]/;
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;

/**
 * Why these credentials cannot be sent, or null when they can (the firmware's parse_prov rules). The messages name
 * lengths and rules only, never the password itself.
 */
export function credentialsProblem(c: WifiCredentials): string | null {
  const ssidBytes = utf8Encode(c.ssid).length;
  if (ssidBytes === 0) return 'Enter the network name (SSID).';
  if (ssidBytes > WIFI_PROV.ssidMaxBytes) return `The network name is ${ssidBytes} bytes: Wi-Fi allows at most ${WIFI_PROV.ssidMaxBytes}.`;
  if (CONTROL.test(c.ssid) || LONE_SURROGATE.test(c.ssid)) return 'The network name contains characters the Ripar cannot take.';
  if (!PRINTABLE_ASCII.test(c.pass)) return 'The password must be plain ASCII letters, digits, spaces and symbols (WPA passphrase).';
  if (c.pass.length > 0 && c.pass.length < WIFI_PROV.passMinBytes) return `The password is too short: WPA needs ${WIFI_PROV.passMinBytes} to ${WIFI_PROV.passMaxBytes} characters (empty for an open network).`;
  if (c.pass.length > WIFI_PROV.passMaxBytes) return `The password is too long: WPA allows at most ${WIFI_PROV.passMaxBytes} characters.`;
  return null;
}

/** true when the device will show this SSID with '?' in place of bytes that are not printable ASCII */
export function ssidShownAltered(ssid: string): boolean {
  return !PRINTABLE_ASCII.test(ssid);
}

/** the PROV value: UTF-8 JSON {"v":1,"ssid","pass"}. Throws WifiProvisioningError when the credentials break a rule. */
export function encodeProvisioning(c: WifiCredentials): Uint8Array {
  const problem = credentialsProblem(c);
  if (problem) throw new WifiProvisioningError(problem);
  const value = utf8Encode(JSON.stringify({ v: WIFI_PROV.version, ssid: c.ssid, pass: c.pass }));
  if (value.length > WIFI_PROV.maxValueBytes) throw new WifiProvisioningError('The Wi-Fi settings are too long for the Ripar.');
  return value;
}

/** how the value goes out at a negotiated MTU: one ATT write, or one GATT long write when it exceeds MTU-3 */
export function provWriteKind(value: Uint8Array, mtu: number): 'single' | 'long' {
  return value.length <= attPayload(mtu) ? 'single' : 'long';
}
