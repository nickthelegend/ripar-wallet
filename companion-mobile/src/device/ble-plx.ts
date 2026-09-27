// react-native-ble-plx adapter: Android permissions, scanning for RIPAR-xxxx, connecting (MTU 247), and a BleTransport
// over the Ripar GATT service. Pairing is Android system bonding with numeric comparison: the device's characteristics
// require an encrypted, authenticated link, so the first access makes Android show its pairing dialog with a 6-digit
// code; the user checks it against the code on the Ripar screen (BLE_PAIR) and confirms on both.
import { PermissionsAndroid, Platform } from 'react-native';
import { BleManager, type Device, type Subscription } from 'react-native-ble-plx';
import { RIPAR_BLE, fromBase64, toBase64 } from './ble-framing';
import type { BleTransport } from './ble-link';
import type { Unsubscribe } from './link';

let manager: BleManager | null = null;

/** the process-wide BleManager (created on first use: it starts the native module) */
export function bleManager(): BleManager {
  if (!manager) manager = new BleManager();
  return manager;
}

export type BlePermission = 'granted' | 'denied' | 'blocked';

/** Android 12+: BLUETOOTH_SCAN + BLUETOOTH_CONNECT (neverForLocation); older: fine location (scan results need it) */
export async function ensureBlePermissions(): Promise<BlePermission> {
  if (Platform.OS !== 'android') return 'granted';
  const api = typeof Platform.Version === 'number' ? Platform.Version : parseInt(String(Platform.Version), 10);
  const perms =
    api >= 31
      ? [PermissionsAndroid.PERMISSIONS.BLUETOOTH_SCAN, PermissionsAndroid.PERMISSIONS.BLUETOOTH_CONNECT]
      : [PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION];
  const res = await PermissionsAndroid.requestMultiple(perms);
  const values = perms.map((p) => res[p]);
  if (values.every((v) => v === PermissionsAndroid.RESULTS.GRANTED)) return 'granted';
  if (values.some((v) => v === PermissionsAndroid.RESULTS.NEVER_ASK_AGAIN)) return 'blocked';
  return 'denied';
}

export async function bluetoothState(): Promise<string> {
  return bleManager().state();
}

export interface FoundDevice {
  id: string;
  name: string;
  rssi: number | null;
}

/** scans for Ripar devices (service UUID, or a RIPAR- name when the service is not in the advertisement) */
export function scanForRipar(onFound: (d: FoundDevice) => void, onError: (msg: string) => void, timeoutMs = 20_000): () => void {
  const m = bleManager();
  let stopped = false;
  const seen = new Set<string>();
  void m
    .startDeviceScan(null, { allowDuplicates: false }, (error, d) => {
      if (stopped) return;
      if (error) {
        onError(error.message);
        return;
      }
      if (!d) return;
      const name = d.name ?? d.localName ?? '';
      const hasService = (d.serviceUUIDs ?? []).some((u) => u.toLowerCase() === RIPAR_BLE.service);
      if (!hasService && !name.toUpperCase().startsWith(RIPAR_BLE.namePrefix)) return;
      if (seen.has(d.id)) return;
      seen.add(d.id);
      onFound({ id: d.id, name: name || 'RIPAR', rssi: d.rssi ?? null });
    })
    .catch((e: Error) => onError(e.message));
  const t = setTimeout(stop, timeoutMs);
  function stop() {
    if (stopped) return;
    stopped = true;
    clearTimeout(t);
    void m.stopDeviceScan().catch(() => {});
  }
  return stop;
}

/** connects, negotiates the MTU, discovers the Ripar service and subscribes to TX and STATUS */
export async function connectRipar(deviceId: string): Promise<BleTransport> {
  const m = bleManager();
  let d: Device = await m.connectToDevice(deviceId, { requestMTU: RIPAR_BLE.requestMtu, timeout: 15_000 });
  try {
    d = await d.requestMTU(RIPAR_BLE.requestMtu);
  } catch {
    /* keep whatever the connection negotiated */
  }
  d = await d.discoverAllServicesAndCharacteristics();
  const services = await d.services();
  if (!services.some((s) => s.uuid.toLowerCase() === RIPAR_BLE.service)) {
    await m.cancelDeviceConnection(deviceId).catch(() => {});
    throw new Error('This Bluetooth device has no Ripar link service. On the device: menu > BLE LINK.');
  }
  return new PlxTransport(m, d);
}

class PlxTransport implements BleTransport {
  private dataL = new Set<(c: Uint8Array) => void>();
  private statusL = new Set<(c: Uint8Array) => void>();
  private discL = new Set<(why: string) => void>();
  private subs: { tx: Subscription | null; status: Subscription | null; disc: Subscription | null } = { tx: null, status: null, disc: null };
  private failed = { tx: false, status: false };
  readonly mtu: number;

  constructor(
    private readonly m: BleManager,
    private readonly d: Device,
  ) {
    this.mtu = d.mtu || 23;
    this.subscribe('tx');
    this.subscribe('status');
    this.subs.disc = m.onDeviceDisconnected(d.id, (err) => {
      const why = err?.message ?? 'the device disconnected';
      for (const l of [...this.discL]) l(why);
    });
  }

  /** enables notifications (a CCCD write, which needs the authenticated link: it can fail before bonding) */
  private subscribe(which: 'tx' | 'status'): void {
    this.subs[which]?.remove();
    this.failed[which] = false;
    const uuid = which === 'tx' ? RIPAR_BLE.tx : RIPAR_BLE.status;
    const listeners = which === 'tx' ? this.dataL : this.statusL;
    this.subs[which] = this.d.monitorCharacteristicForService(RIPAR_BLE.service, uuid, (err, c) => {
      if (err) {
        this.failed[which] = true;
        return;
      }
      if (!c?.value) return;
      const b = fromBase64(c.value);
      for (const l of [...listeners]) l(b);
    });
  }

  ensureSubscribed(): void {
    if (this.failed.tx) this.subscribe('tx');
    if (this.failed.status) this.subscribe('status');
  }

  async write(chunk: Uint8Array): Promise<void> {
    await this.d.writeCharacteristicWithResponseForService(RIPAR_BLE.service, RIPAR_BLE.rx, toBase64(chunk));
  }

  onData(cb: (chunk: Uint8Array) => void): Unsubscribe {
    this.dataL.add(cb);
    return () => this.dataL.delete(cb);
  }

  onStatus(cb: (value: Uint8Array) => void): Unsubscribe {
    this.statusL.add(cb);
    return () => this.statusL.delete(cb);
  }

  async readStatus(): Promise<Uint8Array> {
    const c = await this.d.readCharacteristicForService(RIPAR_BLE.service, RIPAR_BLE.status);
    return c.value ? fromBase64(c.value) : new Uint8Array();
  }

  onDisconnect(cb: (why: string) => void): Unsubscribe {
    this.discL.add(cb);
    return () => this.discL.delete(cb);
  }

  async close(): Promise<void> {
    this.subs.tx?.remove();
    this.subs.status?.remove();
    this.subs.disc?.remove();
    this.subs = { tx: null, status: null, disc: null };
    this.dataL.clear();
    this.statusL.clear();
    this.discL.clear();
    await this.m.cancelDeviceConnection(this.d.id).catch(() => {});
  }
}
