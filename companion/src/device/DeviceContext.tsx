// The app-wide device: which transport is active (hardware camera + QR, or the in-page EMULATOR), and the one
// emulated device (booted lazily, kept running across screens, NVS persisted in localStorage as DEMO KEYS).
import { type ReactNode, createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react';
import { store, useStore } from '../lib/store';
import { type EmuState, EmulatorHost } from './emulator';
import { loadEmulatorModule } from './emulator-loader';
import { nvsStore } from './nvs';
import { type DeviceTransport, HardwareQrTransport } from './transport';

interface DeviceCtx {
  mode: 'hardware' | 'emulator';
  setMode(m: 'hardware' | 'emulator'): void;
  hardware: HardwareQrTransport;
  emulator: EmulatorHost | null;
  emulatorStatus: 'idle' | 'loading' | 'ready' | 'error';
  emulatorError: string | null;
  bootEmulator(fresh?: 'demo-seed' | 'random'): Promise<void>;
  resetEmulator(fresh: 'demo-seed' | 'random'): Promise<void>;
  /** the active transport (null while the emulator is not booted) */
  transport: DeviceTransport | null;
}

const Ctx = createContext<DeviceCtx | null>(null);

export function DeviceProvider({ children }: { children: ReactNode }) {
  const mode = useStore((s) => s.deviceMode);
  const hardware = useMemo(() => new HardwareQrTransport(), []);
  const [emulator, setEmulator] = useState<EmulatorHost | null>(null);
  const [status, setStatus] = useState<DeviceCtx['emulatorStatus']>('idle');
  const [error, setError] = useState<string | null>(null);
  const booting = useRef<Promise<void> | null>(null);
  const hostRef = useRef<EmulatorHost | null>(null);

  const bootEmulator = useCallback(async (fresh?: 'demo-seed' | 'random') => {
    if (hostRef.current && !fresh) return;
    if (booting.current) return booting.current;
    const run = (async () => {
      setStatus('loading');
      setError(null);
      try {
        const { mod, moduleArg } = await loadEmulatorModule();
        if (hostRef.current) {
          hostRef.current.destroy();
          hostRef.current = null;
        }
        const host = await EmulatorHost.boot(mod, nvsStore, { moduleArg, ...(fresh ? { fresh } : {}) });
        host.start();
        hostRef.current = host;
        setEmulator(host);
        setStatus('ready');
      } catch (e) {
        setError((e as Error).message);
        setStatus('error');
      } finally {
        booting.current = null;
      }
    })();
    booting.current = run;
    return run;
  }, []);

  const resetEmulator = useCallback(
    async (fresh: 'demo-seed' | 'random') => {
      nvsStore.clear();
      await bootEmulator(fresh);
    },
    [bootEmulator],
  );

  useEffect(() => {
    if (mode === 'emulator') void bootEmulator();
  }, [mode, bootEmulator]);

  useEffect(() => () => hostRef.current?.destroy(), []);

  const value: DeviceCtx = {
    mode,
    setMode: (m) => store.set({ deviceMode: m }),
    hardware,
    emulator,
    emulatorStatus: status,
    emulatorError: error,
    bootEmulator,
    resetEmulator,
    transport: mode === 'hardware' ? hardware : (emulator?.transport ?? null),
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useDevice(): DeviceCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error('useDevice outside DeviceProvider');
  return c;
}

/**
 * The emulator's live state. Re-renders at most once per animation frame, with a 100 ms timer as a fallback for when
 * animation frames are paused (a hidden tab or pane), so the screen and status never go stale.
 */
export function useEmuState(host: EmulatorHost | null): EmuState | null {
  const snap = useRef<EmuState | null>(host?.snapshot ?? null);
  const subscribe = useCallback(
    (cb: () => void) => {
      if (!host) return () => {};
      let raf = 0;
      let timer: ReturnType<typeof setTimeout> | null = null;
      let pending = false;
      const flush = () => {
        if (!pending) return;
        pending = false;
        if (raf) cancelAnimationFrame(raf);
        if (timer) clearTimeout(timer);
        raf = 0;
        timer = null;
        cb();
      };
      const off = host.subscribe((s) => {
        snap.current = s;
        if (pending) return;
        pending = true;
        raf = requestAnimationFrame(flush);
        timer = setTimeout(flush, 100);
      });
      snap.current = host.snapshot;
      return () => {
        off();
        if (raf) cancelAnimationFrame(raf);
        if (timer) clearTimeout(timer);
      };
    },
    [host],
  );
  return useSyncExternalStore(subscribe, () => (host ? (snap.current ?? host.snapshot) : null));
}
