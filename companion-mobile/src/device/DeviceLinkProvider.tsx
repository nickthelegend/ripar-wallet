// The app-wide device link: the QR link (always there: the air-gapped default), the Bluetooth link once connected,
// and the emulator link once its WebView booted. Settings.link picks the active one.
import { type ReactNode, createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react';
import { store, useStore } from '../lib/store';
import { BleLink } from './ble-link';
import type { DeviceLink, Observable } from './link';
import { QrLink } from './qr-link';

export type BleConn =
  | { state: 'idle' }
  | { state: 'connecting'; name: string }
  /** connected, but STATUS is not readable yet: Android is bonding (numeric comparison) or the link is not authenticated */
  | { state: 'pairing'; name: string }
  | { state: 'connected'; name: string; id: string }
  | { state: 'error'; message: string };

const AUTH = /authenticat|encrypt|bond|insufficient/i;

interface Ctx {
  qr: QrLink;
  ble: BleLink | null;
  bleConn: BleConn;
  connectBle(id: string, name: string): Promise<void>;
  disconnectBle(): void;
  emulator: DeviceLink | null;
  setEmulator(l: DeviceLink | null): void;
  /** the link the settings pick (null: Bluetooth not connected / emulator not booted yet) */
  link: DeviceLink | null;
}

const LinkCtx = createContext<Ctx | null>(null);

export function DeviceLinkProvider({ children }: { children: ReactNode }) {
  const settings = useStore((s) => s.settings);
  const qr = useMemo(() => new QrLink(), []);
  const [ble, setBle] = useState<BleLink | null>(null);
  const [bleConn, setBleConn] = useState<BleConn>({ state: 'idle' });
  const [emulator, setEmulator] = useState<DeviceLink | null>(null);
  const bleRef = useRef<BleLink | null>(null);

  useEffect(() => qr.configure({ frameMs: settings.frameMs, fragLen: settings.fragLen }), [qr, settings.frameMs, settings.fragLen]);

  const disconnectBle = useCallback(() => {
    bleRef.current?.close();
    bleRef.current = null;
    setBle(null);
    setBleConn({ state: 'idle' });
  }, []);

  const connectBle = useCallback(
    async (id: string, name: string) => {
      disconnectBle();
      setBleConn({ state: 'connecting', name });
      try {
        // loaded on demand: the native BLE module starts only when the user picks the Bluetooth fallback
        const { connectRipar } = await import('./ble-plx');
        const transport = await connectRipar(id);
        const link = new BleLink(transport, { fragLen: store.get().settings.fragLen });
        link.phase.subscribe((p) => {
          if (p.kind === 'disconnected' && bleRef.current === link) setBleConn({ state: 'error', message: p.why });
        });
        bleRef.current = link;
        // every characteristic needs an authenticated (LE Secure Connections, MITM, bonded) link: the first read makes
        // Android pair (numeric comparison) when this phone is not bonded yet. The device drops an unauthenticated link
        // after 30 s, and accepts pairing only while it shows BLE PAIRING (docs/BLE_LINK.md §3).
        const until = Date.now() + 45_000;
        for (;;) {
          try {
            await link.refreshStatus();
            break;
          } catch (e) {
            if (bleRef.current !== link) throw new Error('cancelled');
            const msg = (e as Error).message ?? '';
            if (Date.now() > until || link.phase.get().kind === 'disconnected') {
              throw new Error(
                AUTH.test(msg) || link.phase.get().kind === 'disconnected'
                  ? 'Not paired: the Ripar must show BLE PAIRING (device menu > BLE LINK > pulse + SIGN) while you confirm the code on both.'
                  : msg,
              );
            }
            setBleConn({ state: 'pairing', name });
            await new Promise((r) => setTimeout(r, 2000));
          }
        }
        setBle(link);
        setBleConn({ state: 'connected', name, id });
        store.setSettings({ bleDevice: { id, name } });
      } catch (e) {
        bleRef.current?.close();
        bleRef.current = null;
        setBle(null);
        setBleConn({ state: 'error', message: (e as Error).message });
        throw e;
      }
    },
    [disconnectBle],
  );

  useEffect(() => () => bleRef.current?.close(), []);

  const link: DeviceLink | null = settings.link === 'qr' ? qr : settings.link === 'ble' ? ble : emulator;
  const value: Ctx = { qr, ble, bleConn, connectBle, disconnectBle, emulator, setEmulator, link };
  return <LinkCtx.Provider value={value}>{children}</LinkCtx.Provider>;
}

export function useDeviceLink(): Ctx {
  const c = useContext(LinkCtx);
  if (!c) throw new Error('useDeviceLink outside DeviceLinkProvider');
  return c;
}

const never: Observable<null> = { get: () => null, subscribe: () => () => {} };

/** the current value of an Observable, re-rendering on change */
export function useObservable<T>(o: Observable<T> | null | undefined): T | null {
  const src = (o ?? never) as Observable<T | null>;
  return useSyncExternalStore(
    useCallback((cb: () => void) => src.subscribe(() => cb()), [src]),
    () => src.get(),
  );
}
