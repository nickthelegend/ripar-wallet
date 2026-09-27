// Test helpers: the WASM emulator in Node (test mode = the public demo seed), a manual scheduler for the exchange's
// frame loop, and a fixture deployment. Nothing here touches a network.
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect } from 'vitest';
import { type RiparDeployment, DELEGATION_MANAGER, parseDeployment } from '@ripar/protocol';
import type { EmuModule, EmuState } from '../src/device/emulator';
import { EmulatorTransport } from '../src/device/emulator';
import { type DeviceExchange, type Scheduler } from '../src/device/transport';

export const REPO = resolve(__dirname, '../..');
export const EMULATOR_PATH = resolve(REPO, 'firmware/emu/dist/ripar-emu.mjs');

/** the demo device (make_request DEMO_SEED): K1 and its canonical vault (contracts/.work/vault-derivation.md) */
export const DEMO_K1 = '0x753454832754c071704be47915d4DeC6339624Eb';
export const DEMO_VAULT = '0xc36F625D426eBa8f1e0129276B284a939CD3A57D';

export const NOW = 1790500000; // 2026-09-27 09:06:40 UTC, after the firmware time floor
export const AGENT = '0x5FC8d32690cc91D4c39d9d3abcBD16989F875707';
export const PAYEE = '0x0165878A594ca255338adfa4d48449f69242Eb8F';
/** MockUSD at its CREATE2 address: in the firmware v1.2 token table on 10143 (mUSD, 6 decimals) */
export const MOCK_USD = '0xB5b7eaffbF9bf68cbcC1Ce8B5850b2ea9d6f9a2a';

/**
 * a deployments JSON as contracts/script/Deploy.s.sol writes it for 10143: the CREATE2 addresses firmware v1.2
 * compiles in (registry, enforcer, relay, MockUSD); the sentinel is not compiled in (a stand-in address here)
 */
export const DEPLOYMENT_JSON = JSON.stringify({
  chainId: 10143,
  salt: '0x' + '00'.repeat(31) + '01',
  create2Deployer: '0x4e59b44847b379578588920cA78FbF26c0B4956C',
  RiparDeviceRegistry: '0xA08a47c9d645926615CF04D69b7a048133F68c9f',
  PulseCosignEnforcer: '0x64d61fe5438981DC803ED61250FEf024617ae7eE',
  RiparSentinel: '0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0',
  RiparReputationRelay: '0xE433dCA75CA6cd730b1006F51A26208B000eA9E2',
  MockUSD: MOCK_USD,
  creForwarder: '0x0000000000000000000000000000000000000000',
  expectedWorkflowOwner: '0x0000000000000000000000000000000000000000',
  erc8004Identity: '0x8004A818BFB912233c491871b3d84c89A494BD9e',
  erc8004Reputation: '0x8004B663056A597Dffe9eCcC1965A193B7388713',
  delegationManager: DELEGATION_MANAGER,
});

export const DEP: RiparDeployment = parseDeployment(DEPLOYMENT_JSON, 10143);

export async function loadEmu(): Promise<EmuModule> {
  return (await import(pathToFileURL(EMULATOR_PATH).href)) as EmuModule;
}

/** a scheduler whose time only moves on advance() */
export class ManualScheduler implements Scheduler {
  private timers = new Map<number, { fn: () => void; ms: number; next: number }>();
  private id = 0;
  now = 0;
  setInterval(fn: () => void, ms: number): unknown {
    const h = ++this.id;
    this.timers.set(h, { fn, ms, next: this.now + ms });
    return h;
  }
  clearInterval(h: unknown): void {
    this.timers.delete(h as number);
  }
  advance(ms: number): void {
    const end = this.now + ms;
    for (;;) {
      let due: { fn: () => void; ms: number; next: number } | null = null;
      for (const t of this.timers.values()) if (t.next <= end && (!due || t.next < due.next)) due = t;
      if (!due) break;
      this.now = due.next;
      due.next += due.ms;
      due.fn();
    }
    this.now = end;
  }
}

/** the emulated device + its transport + a manual frame clock, stepped together */
export class Rig {
  readonly transport: EmulatorTransport;
  readonly sched = new ManualScheduler();
  constructor(readonly emu: InstanceType<EmuModule['RiparEmulator']>) {
    this.transport = new EmulatorTransport(emu);
  }

  get state(): EmuState {
    return this.emu.state();
  }

  /** advance frame clock and emulated time together, in 20 ms steps, until pred or maxMs */
  run(pred: (s: EmuState) => boolean, maxMs = 20_000): EmuState {
    let s = this.transport.pump();
    for (let t = 0; t < maxMs && !pred(s); t += 20) {
      this.sched.advance(20);
      s = this.transport.tick(20);
    }
    return s;
  }

  key(kind: 'press' | 'hold2' | 'hold5' = 'press'): EmuState {
    this.emu.key(kind);
    return this.transport.pump();
  }

  /** HOME -> SCAN, then let the exchange's frames reach the camera until the review (or a message) opens */
  scanRequest(): EmuState {
    let s = this.transport.pump();
    if (s.screen !== 'scan') s = this.key('press');
    expect(s.screen).toBe('scan');
    s = this.run((x) => x.screen !== 'scan', 30_000);
    return s;
  }

  pageToEnd(): EmuState {
    let s = this.transport.pump();
    for (let i = 0; i < 80 && s.screen === 'review' && !s.review!.allSeen; i++) s = this.key('press');
    return s;
  }

  /** last review page -> PULSE -> thumb -> ARMED -> SIGN -> QR */
  pulseAndSign(): EmuState {
    let s = this.key('press');
    expect(s.screen).toBe('pulse');
    this.emu.finger({ on: true, bpm: 72 });
    s = this.run((x) => x.screen === 'armed', 20_000);
    expect(s.screen).toBe('armed');
    s = this.key('press');
    expect(s.screen).toBe('qr');
    this.emu.finger({ on: false });
    return this.transport.pump();
  }

  home(): void {
    const s = this.key('press');
    expect(s.screen).toBe('home');
  }
}

/** starts an exchange and returns a getter of its settled value (the exchange resolves synchronously on read) */
export function track(ex: DeviceExchange): { value: () => string | undefined; error: () => unknown } {
  let v: string | undefined;
  let err: unknown;
  ex.start().then(
    (x) => (v = x),
    (e) => (err = e),
  );
  return { value: () => v, error: () => err };
}

/** flushes promise callbacks */
export const tickPromises = () => new Promise((r) => setTimeout(r, 0));
