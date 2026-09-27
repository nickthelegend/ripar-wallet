import { describe, expect, it } from 'vitest';
import { acceptPairing, answersRequest, isKeysOnlyPair, planPairing, readKeysOnly } from '../src/lib/flows/pairing';
import {
  LineAssembler,
  RIPAR_BLE,
  attPayload,
  chunkBytes,
  encodeLine,
  fromBase64,
  parseDeviceStatus,
  rxChunks,
  toBase64,
} from '../src/device/ble-framing';
import { BleLink } from '../src/device/ble-link';
import { requestAndVerify, verifierOf } from '../src/device/link';
import { utf8Decode, utf8Encode } from '../src/lib/utf8';
import { DEMO_K1, DEMO_VAULT, DEP, FakeRipar, NOW, approveOnDevice, flush, newEmu } from './helpers';

describe('BLE framing (docs/BLE_LINK.md §4)', () => {
  it('uses the Ripar LINK UUIDs', () => {
    expect(RIPAR_BLE.service).toBe('52495041-5200-4c49-4e4b-000000000001');
    expect([RIPAR_BLE.rx, RIPAR_BLE.tx, RIPAR_BLE.status].map((u) => u.slice(-1))).toEqual(['2', '3', '4']);
  });

  it('writes are at most MTU - 3 bytes', () => {
    expect(attPayload(23)).toBe(20);
    expect(attPayload(247)).toBe(244);
    expect(attPayload(0)).toBe(20);
    expect(attPayload(9999)).toBe(514);
  });

  it('a part is one UTF-8 line ending in LF, cut into MTU-3 chunks in order', () => {
    const part = 'UR:RIPAR-PAIR-REQ/1-3/LPADAXCFAXHLCYYNSGADSRBAHDHESEJTVTBTWPGLDIHS';
    const line = encodeLine(part);
    expect(utf8Decode(line)).toBe(`${part}\n`);
    for (const mtu of [23, 64, 247]) {
      const chunks = chunkBytes(line, attPayload(mtu));
      expect(chunks.every((c) => c.length <= attPayload(mtu))).toBe(true);
      expect(Buffer.concat(chunks.map((c) => Buffer.from(c))).equals(Buffer.from(line))).toBe(true);
    }
    expect(() => encodeLine('a\nb')).toThrow();
    const all = rxChunks([part, part], 23);
    expect(all).toHaveLength(2);
    expect(all[0]!.length).toBe(Math.ceil(line.length / 20));
  });

  it('reassembles lines across notifications (split lines, several per chunk, CRLF, empties)', () => {
    const a = new LineAssembler();
    const text = 'UR:RIPAR-PAIR/AAA\r\n\nUR:RIPAR-COSIGN/BBB\nUR:PART';
    const bytes = utf8Encode(text);
    const out: string[] = [];
    for (let i = 0; i < bytes.length; i += 7) out.push(...a.push(bytes.subarray(i, i + 7)));
    expect(out).toEqual(['UR:RIPAR-PAIR/AAA', 'UR:RIPAR-COSIGN/BBB']);
    expect(a.pending).toBe('UR:PART'.length);
    expect(a.push(utf8Encode('IAL\n'))).toEqual(['UR:PARTIAL']);
  });

  it('drops a line that is not UTF-8 or runs past the limit, and recovers at the next LF', () => {
    const bad: string[] = [];
    const a = new LineAssembler(16, (w) => bad.push(w));
    expect(a.push(Uint8Array.of(0x55, 0xff, 0x0a))).toEqual([]);
    expect(a.push(utf8Encode('x'.repeat(40) + '\nOK\n'))).toEqual(['OK']);
    expect(bad).toHaveLength(2);
  });

  it('parses STATUS strictly, keeps the note, ignores unknown keys', () => {
    const s = parseDeviceStatus(
      '{"v":1,"screen":"SCAN","paired":true,"k1":"0xAbCd...1234","scan":{"got":2,"of":5},"radio":"on","fw":"0123456789abcdef","note":"ignored: not on SCAN (press SIGN on the device first)","extra":{"x":1}}',
      42,
    );
    expect(s).toEqual({
      v: 1,
      screen: 'SCAN',
      paired: true,
      k1: '0xAbCd...1234',
      scan: { got: 2, of: 5 },
      radio: 'on',
      fw: '0123456789abcdef',
      note: 'ignored: not on SCAN (press SIGN on the device first)',
      at: 42,
    });
    expect(parseDeviceStatus('{"v":1,"screen":"FUTURE_SCREEN","paired":false}')?.screen).toBe('FUTURE_SCREEN');
    expect(parseDeviceStatus('{"v":2,"screen":"HOME"}')).toBeNull();
    expect(parseDeviceStatus('{"v":1,"screen":"HO')).toBeNull(); // a truncated notification
    expect(parseDeviceStatus('[1]')).toBeNull();
    expect(parseDeviceStatus('{"v":1,"screen":"HOME","note":"\\u0007bell"}')?.note).toBeNull();
  });

  it('base64 matches Node for every length', () => {
    for (let n = 0; n < 70; n++) {
      const b = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 255);
      const s = toBase64(b);
      expect(s).toBe(Buffer.from(b).toString('base64'));
      expect(Buffer.from(fromBase64(s)).equals(Buffer.from(b))).toBe(true);
    }
    expect(() => fromBase64('a$b')).toThrow();
  });

  it('UTF-8 matches Node and refuses invalid input when fatal', () => {
    for (const s of ['', 'ascii', 'é€𝄞', 'UR:RIPAR/ABC']) {
      expect(Buffer.from(utf8Encode(s)).equals(Buffer.from(s, 'utf8'))).toBe(true);
      expect(utf8Decode(Buffer.from(s, 'utf8'))).toBe(s);
    }
    for (const bad of [[0xff], [0xc0, 0x80], [0xe2, 0x82], [0xed, 0xa0, 0x80], [0xf4, 0x90, 0x80, 0x80]]) {
      expect(() => utf8Decode(Uint8Array.from(bad), true)).toThrow();
      expect(utf8Decode(Uint8Array.from(bad), false)).toContain('�');
    }
  });
});

describe('BleLink with the emulated Ripar behind a fake BLE transport', () => {
  /** a BleLink whose clock and sleeps drive the emulated device */
  async function rig(mtu = 247) {
    const dev = new FakeRipar(await newEmu(), mtu);
    let now = 0;
    const link = new BleLink(dev, {
      now: () => now,
      sleep: async (ms) => {
        now += ms;
        dev.tick(ms);
        await flush();
      },
      settleMs: 400,
      partPauseMs: 25,
    });
    await link.refreshStatus();
    return { dev, link };
  }

  it('reads the keys-only pairing QR from TX (split over notifications at MTU 23)', async () => {
    const { dev, link } = await rig(23);
    expect(link.status.get()?.screen).toBe('HOME');
    const round = requestAndVerify(link, null, verifierOf(['ripar-pair'], readKeysOnly, isKeysOnlyPair));
    dev.key('hold2'); // hold 2 s on Home, release: the pairing QR
    const { result } = await round;
    expect(result.k1Address).toBe(DEMO_K1);
    expect(result.emulator).toBe(true);
    dev.emu.destroy();
  });

  it('waits for SCAN, writes every part as lines, and verifies the signed pairing', async () => {
    const { dev, link } = await rig(64);
    const plan = planPairing(DEP, DEMO_K1, { now: NOW, fragLen: 70 });
    expect(plan.request.parts.length).toBeGreaterThan(1);
    const phases: string[] = [];
    link.phase.subscribe((p) => phases.push(p.kind));
    const round = requestAndVerify(link, plan.request, verifierOf(['ripar-pair'], (ur) => acceptPairing(ur, plan, null), (ur) => answersRequest(ur, plan.request)));
    await flush();
    // the device is on HOME: nothing is written until the user presses SIGN there
    expect(phases).toContain('waiting-scan');
    expect(dev.writes).toHaveLength(0);
    dev.key('press');
    for (let i = 0; i < 20_000 && dev.emu.state().screen === 'scan'; i++) await flush();
    expect(dev.emu.state().screen).toBe('review');
    // every write fit MTU-3 and the device got each part exactly as a line
    expect(dev.writes.every((w) => w.length <= 61)).toBe(true);
    expect(new Set(dev.linesFed)).toEqual(new Set(plan.request.parts));
    approveOnDevice(dev);
    const { result } = await round;
    expect(result.k1Address).toBe(DEMO_K1);
    expect(result.pinned.vault).toBe(DEMO_VAULT);
    expect(phases).toContain('sent');
    dev.emu.destroy();
  });

  it('reads the whole STATUS when a notification was truncated', async () => {
    const { dev, link } = await rig(23);
    const reads = dev.statusReads;
    dev.key('press'); // HOME -> SCAN: a status longer than 20 bytes, notified truncated
    await flush();
    await flush();
    expect(dev.statusReads).toBeGreaterThan(reads);
    expect(link.status.get()?.screen).toBe('SCAN');
    link.close();
    dev.emu.destroy();
  });

  it('shows the device note when a line arrives off SCAN', async () => {
    const { dev, link } = await rig();
    await dev.write(encodeLine('UR:RIPAR-PAIR-REQ/ABC'));
    await link.refreshStatus();
    expect(link.status.get()?.note).toMatch(/not on SCAN/);
    dev.emu.destroy();
  });
});
