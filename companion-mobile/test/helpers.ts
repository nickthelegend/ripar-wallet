// Test fixtures: the WASM firmware emulator in Node (test mode = the public demo seed), a fixture deployment at the
// addresses firmware v1.2 compiles in, FakeRipar: a BleTransport whose far end is the emulated device, framed
// exactly as docs/BLE_LINK.md describes (RX lines only on SCAN, TX = QR text + LF in MTU-3 notifications, STATUS JSON
// notified on change and truncated to MTU-3 when it does not fit), and FakeWifiRipar: a local HTTP server that serves
// the Wi-Fi link contract (GET /status, POST /rx only on SCAN else 409, GET /tx, X-Ripar-Code) for the emulated device.
import { type IncomingMessage, type Server, type ServerResponse, createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { type RiparDeployment, DELEGATION_MANAGER, parseDeployment } from '@ripar/protocol';
import { LineAssembler, attPayload } from '../src/device/ble-framing';
import type { BleTransport } from '../src/device/ble-link';
import type { Unsubscribe } from '../src/device/link';
import { utf8Encode } from '../src/lib/utf8';

export const REPO = resolve(__dirname, '../..');
export const EMULATOR_PATH = resolve(REPO, 'firmware/emu/dist/ripar-emu.mjs');

/** the demo device (make_request DEMO_SEED): K1 and its canonical vault */
export const DEMO_K1 = '0x753454832754c071704be47915d4DeC6339624Eb';
export const DEMO_VAULT = '0xc36F625D426eBa8f1e0129276B284a939CD3A57D';
export const NOW = 1790500000; // 2026-09-27 09:06:40 UTC, after the firmware time floor
export const PAYEE = '0x0165878A594ca255338adfa4d48449f69242Eb8F';
export const MOCK_USD = '0xB5b7eaffbF9bf68cbcC1Ce8B5850b2ea9d6f9a2a';
export const HOT_KEY = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';

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

// the emulator's JS API (firmware/emu/dist/ripar-emu.d.ts), the parts the tests use
export interface Emu {
  state(): EmuState;
  tick(ms: number): EmuState;
  key(kind?: 'press' | 'hold2' | 'hold5'): EmuState;
  scan(text: string): { result: string; screen: string };
  finger(p?: { on?: boolean; bpm?: number }): unknown;
  destroy(): void;
}
export interface EmuState {
  screen: string;
  paired: boolean;
  k1: string;
  k1Short: string;
  qr: null | { text: string; signed: boolean };
  scan: { received: number; seqLen: number };
  review: null | { ok: boolean; refusal: string; allSeen: boolean };
  context: { minEpoch: string };
}

export async function newEmu(): Promise<Emu> {
  const mod = (await import(pathToFileURL(EMULATOR_PATH).href)) as { RiparEmulator: { create(o: unknown): Promise<Emu> } };
  return mod.RiparEmulator.create({ test: true });
}

const SCREEN: Record<string, string> = {
  home: 'HOME',
  homeHold: 'HOME',
  scan: 'SCAN',
  review: 'REVIEW',
  pulse: 'PULSE',
  armed: 'ARMED',
  qr: 'QR',
  pairQr: 'QR',
  message: 'MESSAGE',
  fail: 'MESSAGE',
  menu: 'MENU',
};

/** the STATUS JSON the device would report for the emulator's state (unknown keys included: clients must ignore them) */
export function statusJsonOf(emu: Emu, extra: Record<string, unknown> = {}): string {
  const s = emu.state();
  const screen = SCREEN[s.screen] ?? s.screen.toUpperCase();
  return JSON.stringify({
    v: 1,
    screen,
    paired: s.paired,
    k1: `${s.k1.slice(0, 6)}...${s.k1.slice(-4)}`,
    ...(screen === 'SCAN' ? { scan: { got: s.scan.received, of: s.scan.seqLen } } : {}),
    radio: 'on',
    fw: '7bc44601d30720f1',
    ...extra,
    future: 'ignored by clients',
  });
}

/** what approveOnDevice needs: the emulator plus key / tick helpers that publish the new state */
export interface DrivenRipar {
  readonly emu: Emu;
  key(kind?: 'press' | 'hold2' | 'hold5'): EmuState;
  tick(ms: number): void;
  sync(): void;
}

/** the emulated Ripar behind a Bluetooth link, framed per docs/BLE_LINK.md §4 */
export class FakeRipar implements BleTransport, DrivenRipar {
  private dataL = new Set<(c: Uint8Array) => void>();
  private statusL = new Set<(c: Uint8Array) => void>();
  private rx = new LineAssembler(4096);
  private lastStatus = '';
  private lastQr: string | null = null;
  private note: string | undefined;
  writes: Uint8Array[] = [];
  linesFed: string[] = [];
  statusReads = 0;
  /** writes to PROV (Wi-Fi provisioning), in order: each one a whole value (single or long write) */
  provWrites: Uint8Array[] = [];

  constructor(
    readonly emu: Emu,
    readonly mtu = 247,
  ) {}

  statusJson(): string {
    return statusJsonOf(this.emu, this.note ? { note: this.note } : {});
  }

  /** push STATUS / TX notifications for whatever changed on the device */
  sync(): void {
    const js = this.statusJson();
    if (js !== this.lastStatus) {
      this.lastStatus = js;
      const b = utf8Encode(js);
      const n = b.subarray(0, attPayload(this.mtu)); // truncated when it does not fit one notification
      for (const l of [...this.statusL]) l(n);
    }
    const s = this.emu.state();
    const qr = (s.screen === 'qr' || s.screen === 'pairQr') && s.qr ? s.qr.text : null;
    if (qr && qr !== this.lastQr) {
      const bytes = utf8Encode(`${qr}\n`);
      const size = attPayload(this.mtu);
      for (let i = 0; i < bytes.length; i += size) {
        const c = bytes.subarray(i, i + size);
        for (const l of [...this.dataL]) l(c);
      }
    }
    this.lastQr = qr;
  }

  tick(ms: number): void {
    this.emu.tick(ms);
    this.sync();
  }

  key(kind: 'press' | 'hold2' | 'hold5' = 'press'): EmuState {
    const s = this.emu.key(kind);
    this.sync();
    return s;
  }

  async write(chunk: Uint8Array): Promise<void> {
    if (chunk.length > attPayload(this.mtu)) throw new Error(`write of ${chunk.length} bytes > MTU-3`);
    this.writes.push(chunk);
    for (const line of this.rx.push(chunk)) {
      if (this.emu.state().screen === 'scan') {
        this.note = undefined;
        this.linesFed.push(line);
        this.emu.scan(line);
      } else {
        this.note = 'ignored: not on SCAN (press SIGN on the device first)';
      }
    }
    this.tick(5);
  }

  /** as firmware/src/ble_link.cpp: one write (or one long write, when longer than MTU-3) = one whole value, <= 512 B */
  async writeProvisioning(value: Uint8Array): Promise<void> {
    if (value.length === 0 || value.length > 512) throw new Error(`PROV value of ${value.length} bytes: invalid attribute length`);
    this.provWrites.push(value);
  }

  onData(cb: (c: Uint8Array) => void): Unsubscribe {
    this.dataL.add(cb);
    return () => this.dataL.delete(cb);
  }

  onStatus(cb: (c: Uint8Array) => void): Unsubscribe {
    this.statusL.add(cb);
    return () => this.statusL.delete(cb);
  }

  async readStatus(): Promise<Uint8Array> {
    this.statusReads++;
    return utf8Encode(this.statusJson());
  }

  onDisconnect(): Unsubscribe {
    return () => {};
  }

  async close(): Promise<void> {}
}

/** pages through a review, puts the synthetic thumb on, waits for ARMED and presses SIGN */
export function approveOnDevice(dev: DrivenRipar): EmuState {
  let s = dev.emu.state();
  for (let i = 0; i < 80 && s.screen === 'review' && !s.review!.allSeen; i++) s = dev.key('press');
  if (s.screen !== 'review') throw new Error(`expected the review, device on ${s.screen}`);
  if (!s.review!.ok) throw new Error(`the device refused: ${s.review!.refusal}`);
  s = dev.key('press');
  if (s.screen !== 'pulse') throw new Error(`expected PULSE, device on ${s.screen}`);
  dev.emu.finger({ on: true, bpm: 72 });
  for (let t = 0; t < 20_000 && dev.emu.state().screen !== 'armed'; t += 20) dev.tick(20);
  if (dev.emu.state().screen !== 'armed') throw new Error('the pulse never armed');
  s = dev.key('press');
  dev.emu.finger({ on: false });
  dev.sync();
  return s;
}

export const flush = () => new Promise((r) => setTimeout(r, 0));

/**
 * The emulated Ripar behind its Wi-Fi link (TEMPORARY testing link), answering as firmware/src/wifi_proto.cpp does:
 * a real HTTP server on 127.0.0.1 serving
 *   GET /status  STATUS JSON (+ "wifi":"on", "ip")
 *   POST /rx     UR lines, only on SCAN: 200 + STATUS; else 409 + STATUS with the note
 *   GET /tx      the QR on screen + LF (204: none)
 * Every request needs X-Ripar-Code (401); after 3 free wrong codes each further one locks the link (429 +
 * Retry-After) for 1 s, 2 s, 4 s, ...
 */
export class FakeWifiRipar implements DrivenRipar {
  code = '48151623';
  readonly ip = '127.0.0.1';
  linesFed: string[] = [];
  /** every POST /rx body the device got (accepted or not) */
  posts: string[] = [];
  /** method, path and the code header of every request */
  requests: { method: string; path: string; code: string | undefined }[] = [];
  /** answer the next N POST /rx with 409 even on SCAN (the device left SCAN between a poll and the POST) */
  refuseNextPosts = 0;
  /** leave "ip" out of STATUS (the firmware does when a note needs the room) */
  omitIp = false;
  private note: string | undefined;
  private server: Server | null = null;
  private fails = 0;
  private lockedUntil = 0;
  port = 0;

  constructor(readonly emu: Emu) {}

  get host(): string {
    return `${this.ip}:${this.port}`;
  }

  async start(): Promise<this> {
    this.server = createServer((req, res) => void this.handle(req, res));
    await new Promise<void>((r) => this.server!.listen(0, this.ip, r));
    this.port = (this.server.address() as AddressInfo).port;
    return this;
  }

  async stop(): Promise<void> {
    const s = this.server;
    this.server = null;
    if (!s) return;
    s.closeAllConnections();
    await new Promise<void>((r) => s.close(() => r()));
  }

  /** lock the link as after repeated wrong codes (a correct code resets the count, so a polling phone rarely sees it) */
  lock(ms: number): void {
    this.lockedUntil = Date.now() + ms;
  }

  /** the device state is read at request time: nothing to push */
  sync(): void {}

  tick(ms: number): void {
    this.emu.tick(ms);
  }

  key(kind: 'press' | 'hold2' | 'hold5' = 'press'): EmuState {
    return this.emu.key(kind);
  }

  /** as read over HTTP with Bluetooth off: "radio" is the Bluetooth link, so "off" here is normal */
  private statusBody(): string {
    return statusJsonOf(this.emu, { radio: 'off', wifi: 'on', ...(this.omitIp ? {} : { ip: this.ip }), ...(this.note ? { note: this.note } : {}) });
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = Buffer.concat(chunks).toString('utf8');
    const path = (req.url ?? '/').split('?')[0]!;
    const code = req.headers['x-ripar-code'];
    this.requests.push({ method: req.method ?? '', path, code: typeof code === 'string' ? code : undefined });
    const send = (status: number, text = '', type = 'application/json', extra: Record<string, string> = {}) => {
      res.writeHead(status, { ...(text ? { 'content-type': type } : {}), 'cache-control': 'no-store', connection: 'close', ...extra });
      res.end(text);
    };
    const now = Date.now();
    if (now < this.lockedUntil) {
      return send(429, '{"error":"too many wrong codes: wait"}', 'application/json', { 'retry-after': String(Math.ceil((this.lockedUntil - now) / 1000)) });
    }
    if (code !== this.code) {
      if (++this.fails > 3) this.lockedUntil = now + 1000 * 2 ** (this.fails - 4);
      return send(401, '{"error":"X-Ripar-Code missing or wrong: use the 8-digit link code on the device\'s Home screen"}');
    }
    this.fails = 0;
    if (req.method === 'GET' && path === '/status') return send(200, this.statusBody());
    if (req.method === 'POST' && path === '/rx') {
      this.posts.push(body);
      if (this.refuseNextPosts > 0 || this.emu.state().screen !== 'scan') {
        if (this.refuseNextPosts > 0) this.refuseNextPosts--;
        this.note = 'ignored: not on SCAN (press SIGN on the device first)';
        return send(409, this.statusBody());
      }
      this.note = undefined;
      let n = 0;
      for (const line of body.split('\n').map((l) => l.replace(/\r$/, '').trim())) {
        if (!line || this.emu.state().screen !== 'scan') continue;
        this.linesFed.push(line);
        this.emu.scan(line);
        n++;
      }
      if (!n) return send(400, '{"error":"no UR line in the body"}');
      this.tick(5);
      return send(200, this.statusBody());
    }
    if (req.method === 'GET' && path === '/tx') {
      const st = this.emu.state();
      const qr = (st.screen === 'qr' || st.screen === 'pairQr') && st.qr ? st.qr.text : null;
      return qr ? send(200, `${qr}\n`, 'text/plain') : send(204);
    }
    return send(404, '{"error":"routes: GET /status, POST /rx, GET /tx"}');
  }
}
