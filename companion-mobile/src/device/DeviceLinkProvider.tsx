// The app-wide device link: the QR link (always there: the air-gapped default), the Bluetooth link once connected,
// the emulator link once its WebView booted, and (TEMPORARY, testing) the Wi-Fi link once it answered. Settings.link
// picks the active one.
import { type ReactNode, createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react';
import { errorText } from '../lib/format';
import { store, useStore } from '../lib/store';
import { clearWifiCode, loadWifiCode, saveWifiCode } from '../lib/wifi-secret';
import { BleLink } from './ble-link';
import type { DeviceLink, DeviceStatus, Observable } from './link';
import { QrLink } from './qr-link';
import { WifiLink, WifiLinkError, normalizeWifiCode } from './wifi-link';

export type BleConn =
  | { state: 'idle' }
  | { state: 'connecting'; name: string }
  /** connected, but STATUS is not readable yet: Android is bonding (numeric comparison) or the link is not authenticated */
  | { state: 'pairing'; name: string }
  | { state: 'connected'; name: string; id: string }
  | { state: 'error'; message: string };

/** the Wi-Fi link (TEMPORARY, testing); its health while connected is WifiLink.conn */
export type WifiConnState =
  | { state: 'idle' }
  | { state: 'connecting'; host: string }
  | { state: 'connected'; host: string }
  | { state: 'error'; message: string; host?: string };

const AUTH = /authenticat|encrypt|bond|insufficient/i;

interface Ctx {
  qr: QrLink;
  ble: BleLink | null;
  bleConn: BleConn;
  connectBle(id: string, name: string): Promise<void>;
  disconnectBle(): void;
  emulator: DeviceLink | null;
  setEmulator(l: DeviceLink | null): void;
  wifi: WifiLink | null;
  wifiConn: WifiConnState;
  /** checks the address and the code (GET /status) and starts polling; saves the address and (secure store) the code */
  connectWifi(host: string, code: string): Promise<DeviceStatus>;
  /** reconnects to the saved address with the saved code (throws when there is none) */
  reconnectWifi(): Promise<DeviceStatus>;
  /** stops the Wi-Fi link and forgets its code */
  disconnectWifi(): void;
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
  const [wifi, setWifi] = useState<WifiLink | null>(null);
  const [wifiConn, setWifiConn] = useState<WifiConnState>({ state: 'idle' });
  const wifiRef = useRef<WifiLink | null>(null);

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

  // ------------------------------------------------------------------ Wi-Fi (TEMPORARY, testing)
  const dropWifi = useCallback(() => {
    wifiRef.current?.close();
    wifiRef.current = null;
    setWifi(null);
  }, []);

  const disconnectWifi = useCallback(() => {
    dropWifi();
    setWifiConn({ state: 'idle' });
    void clearWifiCode();
  }, [dropWifi]);

  const connectWifi = useCallback(
    async (host: string, code: string): Promise<DeviceStatus> => {
      dropWifi();
      setWifiConn({ state: 'connecting', host });
      let link: WifiLink | null = null;
      try {
        link = new WifiLink({ host, code, fragLen: store.get().settings.fragLen });
        wifiRef.current = link;
        const s = await link.open();
        if (wifiRef.current !== link) throw new Error('cancelled');
        const l = link;
        l.conn.subscribe((c) => {
          // a wrong code mid-session: the device turned Wi-Fi off and on (new code); polling has stopped
          if (c.state === 'unauthorized' && wifiRef.current === l) {
            dropWifi();
            setWifiConn({ state: 'error', message: c.message, host: l.host });
            void clearWifiCode();
          }
        });
        setWifi(l);
        setWifiConn({ state: 'connected', host: l.host });
        store.setSettings({ wifiHost: l.host });
        await saveWifiCode(normalizeWifiCode(code)!);
        return s;
      } catch (e) {
        // a newer connectWifi() superseded this one, or disconnectWifi() closed it: leave the state alone
        const superseded = (!!wifiRef.current && wifiRef.current !== link) || (e instanceof WifiLinkError && e.kind === 'closed');
        if (link && wifiRef.current === link) dropWifi();
        else link?.close();
        if (!superseded) {
          setWifiConn({ state: 'error', message: errorText(e), host });
          if (e instanceof WifiLinkError && e.kind === 'unauthorized') void clearWifiCode();
        }
        throw e;
      }
    },
    [dropWifi],
  );

  const reconnectWifi = useCallback(async (): Promise<DeviceStatus> => {
    const host = store.get().settings.wifiHost;
    const code = await loadWifiCode();
    if (!host || !code) throw new Error('No saved Wi-Fi code: set up the Wi-Fi link again (Device > Wi-Fi link setup).');
    return connectWifi(host, code);
  }, [connectWifi]);

  // the Wi-Fi link was the chosen link when the app last ran: try the saved address and code once
  useEffect(() => {
    const s = store.get().settings;
    if (s.link === 'wifi' && s.wifiHost) void reconnectWifi().catch(() => {});
    return () => wifiRef.current?.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const link: DeviceLink | null = settings.link === 'qr' ? qr : settings.link === 'ble' ? ble : settings.link === 'wifi' ? wifi : emulator;
  const value: Ctx = { qr, ble, bleConn, connectBle, disconnectBle, emulator, setEmulator, wifi, wifiConn, connectWifi, reconnectWifi, disconnectWifi, link };
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
