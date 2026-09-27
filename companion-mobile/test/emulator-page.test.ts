// The emulator WebView page (scripts/build-emu-html.mjs + scripts/emu-bridge.js) run in Node with a stand-in for the
// WebView bridge: it boots the firmware, reports state, answers a keys-only pairing, and scans presented parts.
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildRequest, pairFieldsFromDeployment } from '@ripar/protocol';
import type { EmuFromPage, EmuSnapshot } from '../src/device/emulator-link';
import { EMU_HTML } from '../src/device/emulator/emu-html.generated';
import { DEMO_K1, DEP, NOW } from './helpers';

const messages: EmuFromPage[] = [];
const win: { ReactNativeWebView: { postMessage(s: string): void }; riparReceive?: (json: string) => void } = {
  ReactNativeWebView: { postMessage: (s) => messages.push(JSON.parse(s) as EmuFromPage) },
};

const send = (m: unknown) => win.riparReceive!(JSON.stringify(m));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function until<T>(f: () => T | undefined | null | false, ms = 15_000): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    const v = f();
    if (v) return v;
    if (Date.now() > end) throw new Error('timed out');
    await sleep(20);
  }
}
const lastState = (): EmuSnapshot | null => {
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i]!;
    if (m.t === 'state') return m.s;
  }
  return null;
};

describe('emulator WebView page', () => {
  beforeAll(async () => {
    const script = /<script type="module">\n([\s\S]*)\n<\/script>/.exec(EMU_HTML)?.[1];
    if (!script) throw new Error('the generated page has no module script (was firmware/emu/dist missing?)');
    const dir = mkdtempSync(join(tmpdir(), 'ripar-emu-page-'));
    const file = join(dir, 'page.mjs');
    writeFileSync(file, script);
    (globalThis as unknown as { window: unknown }).window = win;
    await import(pathToFileURL(file).href);
    await until(() => messages.some((m) => m.t === 'ready'));
  });

  afterAll(() => {
    delete (globalThis as unknown as { window?: unknown }).window;
  });

  it('boots a demo device and reports its state and NVS', async () => {
    send({ t: 'boot', nvs: null, fresh: 'demo-seed' });
    await until(() => messages.find((m) => m.t === 'booted'));
    const nvs = await until(() => messages.find((m) => m.t === 'nvs'));
    expect(nvs.t === 'nvs' && nvs.nvs.seed).toBeTruthy();
    const s = await until(() => lastState());
    expect(s.screen).toBe('home');
    expect(s.k1.toLowerCase()).toBe(DEMO_K1.toLowerCase());
  });

  it('a 2 s hold on Home shows the keys-only pairing QR, read back as a response', async () => {
    send({ t: 'keyDown' });
    await sleep(2400);
    send({ t: 'keyUp' });
    const read = await until(() => messages.find((m) => m.t === 'read'));
    expect(read.t === 'read' && read.text.startsWith('UR:RIPAR-PAIR/')).toBe(true);
    send({ t: 'keyDown' });
    await sleep(150);
    send({ t: 'keyUp' });
    await until(() => lastState()?.screen === 'home');
  });

  it('scans the presented parts once the user pressed SIGN, and opens the review', async () => {
    const req = buildRequest('pair', pairFieldsFromDeployment(DEP, { now: NOW }), { frag: 70 });
    send({ t: 'present', parts: req.parts, frameMs: 120 });
    send({ t: 'keyDown' });
    await sleep(150);
    send({ t: 'keyUp' });
    const s = await until(() => (lastState()?.screen === 'review' ? lastState() : null), 20_000);
    expect(s.review?.ok).toBe(true);
    send({ t: 'present', parts: null, frameMs: 120 });
  });
});
