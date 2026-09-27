// Types for ripar-emu.mjs (the Ripar device emulator). uint64 values are decimal strings.

export type Bytes = Uint8Array | ArrayBuffer | ArrayBufferView | string; // string = hex (optional 0x)

export type Screen =
  | 'fail' | 'home' | 'homeHold' | 'scan' | 'review' | 'pulse' | 'armed' | 'qr' | 'message' | 'pairQr' | 'menu';
export type Job = 'none' | 'pair' | 'cosign' | 'mandate' | 'deny' | 'privy' | 'revoke' | 'reopen';
/** device.h UI_* colours; `*Hex` fields carry the RGB the firmware passes to ui_rgb(). */
export type UiColor = 'text' | 'dim' | 'accent' | 'good' | 'warn' | 'bad';

/** review.h Tone of a line ("accent" = the selected device-menu item) */
export type Tone = 'normal' | 'good' | 'warn' | 'bad' | 'dim' | 'accent';

export interface ReviewRow {
  label: string; value: string; tone: Tone; color: UiColor; colorHex: string;
  /** value over the full width (no label column) */
  full: boolean;
  /** last row of its review line (ui.cpp draws a separator below it) */
  last: boolean;
}

export type Display =
  | { kind: 'boot'; seq: number; drawnAtMs: number; title: string; lines: string[] }
  | { kind: 'home'; seq: number; drawnAtMs: number; k1Short: string; battery: number; paired: boolean; badge: string;
      badgeColor: UiColor; badgeColorHex: string; hints: string[] }
  | { kind: 'message'; seq: number; drawnAtMs: number; title: string; color: UiColor; colorHex: string; lines: string[] }
  | { kind: 'scan'; seq: number; drawnAtMs: number; hint: string; progress: number; progressText: string }
  | { kind: 'review'; seq: number; drawnAtMs: number; title: string; rows: ReviewRow[]; firstRow: number;
      rowsShown: number; totalRows: number; visibleRows: number; moreAbove: boolean; moreBelow: boolean; footer: string }
  | { kind: 'pulse'; seq: number; drawnAtMs: number; title: string; bpmText: string; beatsText: string;
      elapsedText: string; status: string; statusColor: UiColor; statusColorHex: string; progress: number;
      passed: boolean; finger: boolean; heartBig: boolean; ringColor: UiColor; ringColorHex: string }
  | { kind: 'qr'; seq: number; drawnAtMs: number; title: string; footer: string; text: string; version: number;
      ecc: 'M' | 'L'; scale: number };

/**
 * The pinned context (include/context.h, NVS layout v3). Since firmware v1.2 `vault` is always the vault derived from
 * K1 (EmuState.vault) once paired, and the Ripar contracts are the ones compiled in for the chain.
 */
export interface ContextView {
  paired: boolean; chainId: string; chain: string;
  delegationManager: string | null; pulseCosignEnforcer: string | null; sentinel: string | null;
  relay: string | null; registry: string | null; vault: string | null;
  lastDelegationHash: string | null; hasAgentId: boolean; agentId: string;
  minEpoch: string; reopenNonce: string; notBefore: string; notBeforeUtc: string;
  /**
   * (v3) the pulse terms of the remembered mandate (lastDelegationHash), for the co-sign review's AUTO payee line:
   * token (the zero address = the native coin, also when no mandate is remembered), caps as decimal strings (uint128),
   * period in seconds (0 = lifetime cap)
   */
  pulseToken: string; perTxAutoCap: string; periodAutoCap: string; period: number; newPayeeNeedsHuman: boolean;
  /** (v3) PANIC FIRST: set by a signed mandate, cleared by a signed panic (a revoke leaves it set) */
  unpanickedMandates: boolean;
}

export interface EmuState {
  emulator: true;
  emulatorId: 'ripar-emulator v1';
  /** first 8 bytes of sha256("ripar-emulator v1"), hex: also key 6 of every ripar-pair response */
  firmwareId: string;
  testMode: boolean;
  nowMs: number;
  /**
   * The firmware loop (app thread): busy for 31 ms after every frame it draws (the LCD push), or stalled by
   * stallApp(). The key timer and the pulse sensor run regardless. passes = loop passes run so far.
   */
  app: { busy: boolean; busyUntilMs: number; stalled: boolean; passes: number };
  hardware: { camera: boolean; pulseSensor: boolean };
  screen: Screen;
  job: Job;
  keyDown: boolean;
  keyRaw: boolean;
  battery: number;
  paired: boolean;
  k1Short: string;
  k1: string;
  /**
   * the vault derived from K1 (firmware/src/vault.cpp: MetaMask SimpleFactory CREATE2, salt 0, of the HybridDeleGator
   * proxy owned by K1, docs/PROTOCOL.md 2.1): the only vault this device pins; the companion deploys and funds it
   */
  vault: string;
  p1: string;
  selftest: { passed: boolean; report: string };
  /** the last frame drawn on the 320x240 LCD */
  display: Display;
  review: null | {
    job: Job; title: string; ok: boolean; refusal: string; allSeen: boolean; row: number;
    footerMore: string; footerEnd: string;
    lines: { label: string; value: string; tone: Tone; color: UiColor; colorHex: string }[];
  };
  menu: null | { index: number; items: string[] };
  pulse: {
    sensorOn: boolean; finger: boolean; passed: boolean; bpm: number; beats: number; minBeats: number;
    progress: number; jitter: number; elapsedMs: number; irDC: number; redDC: number;
    /**
     * The MAX30102: the injected fault, whether it samples, its FIFO fill level (0..32) and OVF counter, and what the
     * last pulse_update() read (samples, lost samples); reads = pulse_update() calls while measuring.
     */
    sensor: { fault: PulseFault; sampling: boolean; fifo: number; ovf: number; lastRead: number; lastLost: number;
      reads: number };
  };
  fingerInput: FingerParams;
  scan: { active: boolean; hint: string; progress: number; received: number; seqLen: number };
  /** the QR on screen: `text` is the upper-cased UR the device encodes */
  qr: null | { text: string; title: string; footer: string; signed: boolean; version: number; ecc: 'M' | 'L'; fits: boolean };
  message: null | { title: string; body: string; color: UiColor; colorHex: string };
  buzz: { ok: number; err: number; beat: number; last: '' | 'ok' | 'err' | 'beat'; lastAtMs: number };
  context: ContextView;
  store: { saves: number; failWrites: boolean; contextHex: string };
  signatures: number;
  lastOutput: string;
  serial: string[];
}

export interface FingerParams {
  on: boolean;
  bpm: number;
  /** pulse amplitude as a fraction of the IR DC level (perfusion index), default 0.01 */
  amplitude: number;
  /** sensor noise, counts (std), default 8 */
  noise: number;
  /** beat-to-beat variation (fraction of the interval), default 0.03 */
  hrv: number;
  shape: 'ppg' | 'sine' | 'square' | 'flat';
}

export type PulseFault = 'none' | 'stall' | 'unplug';

export interface ScanResult {
  /**
   * repeat: the same payload was delivered less than 1000 ms ago (qrscan.cpp), not handed to the firmware again;
   * empty: an empty payload (ignored by the camera handoff); pending: the firmware loop is stalled (stallApp), the QR
   * waits in the handoff slot; none: delivered, but the loop left SCAN before reading it.
   */
  result: 'accepted' | 'complete' | 'error' | 'ignored' | 'repeat' | 'empty' | 'pending' | 'camera-off' | 'none';
  progress: number;
  received: number;
  seqLen: number;
  hint: string;
  screen: Screen;
}

export interface NvsImage { emulator: true; seed: string | null; context: string | null }

export interface CreateOptions {
  /** >= 32 bytes; default 64 bytes from crypto.getRandomValues() (not needed in test mode) */
  entropy?: Bytes;
  /** restore a device: exportNvs().seed / .context */
  seed?: Bytes;
  context?: Bytes;
  /** deterministic test mode: seed = sha256("ripar demo seed") unless given, fixed TRNG + PPG noise */
  test?: boolean | { seed?: Bytes; trngSeed?: Bytes; ppgSeed?: number; selftestFault?: boolean };
  /** emulated millis() at power-on (default 1000) */
  clockMs?: number;
  battery?: number;
  /** hardware present at power-on (default both) */
  hardware?: { camera?: boolean; pulseSensor?: boolean };
  /** extra Emscripten module options for the first load (e.g. locateFile) */
  moduleArg?: Record<string, unknown>;
}

export declare const KEY_TIMING: Readonly<{ pressMs: number; settleMs: number; hold2Ms: number; hold5Ms: number }>;

export declare class RiparEmulator {
  static create(opts?: CreateOptions): Promise<RiparEmulator>;
  onContextSaved: ((nvs: NvsImage) => void) | null;
  readonly nowMs: number;
  state(): EmuState;
  tick(ms: number): EmuState;
  tickUntil(pred: (s: EmuState) => boolean, opts?: { maxMs?: number; stepMs?: number }): EmuState;
  keyDown(): EmuState;
  keyUp(): EmuState;
  hold(ms: number): EmuState;
  key(kind?: 'press' | 'hold2' | 'hold5'): EmuState;
  scan(qrText: string): ScanResult;
  finger(p?: Partial<FingerParams>): FingerParams;
  /** hex = the RAM context, stored = the emulated NVS blob (context_serialize, `version` 3, 256 bytes) */
  exportContext(): ContextView & { version: number; hex: string; stored: string | null };
  exportNvs(): NvsImage;
  addEntropy(bytes: Bytes): void;
  injectTrng(bytes: Bytes): void;
  setNvsFail(fail: boolean): EmuState;
  setBattery(pct: number): EmuState;
  setPulseFault(kind: PulseFault): EmuState;
  stallApp(ms: number): EmuState;
  destroy(): void;
}

export default RiparEmulator;
