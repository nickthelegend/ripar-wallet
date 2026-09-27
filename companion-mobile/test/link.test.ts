import { describe, expect, it } from 'vitest';
import { buildRequest, pairFieldsFromDeployment, urParts, urSingle } from '@ripar/protocol';
import {
  DeviceCancelledError,
  DeviceLinkError,
  DeviceTimeoutError,
  type DeviceLink,
  ResponseBus,
  awaitDeviceResponse,
  classifyResponse,
  requestAndVerify,
  requestParts,
  sendToDevice,
  verifierOf,
} from '../src/device/link';
import { QrLink } from '../src/device/qr-link';
import { DEP, NOW, approveOnDevice, FakeRipar, newEmu } from './helpers';

const pairRequest = () => buildRequest('pair', pairFieldsFromDeployment(DEP, { now: NOW }), { frag: 70 });

/** a link that records what it was sent and lets the test answer */
class TestLink implements DeviceLink {
  readonly kind = 'qr' as const;
  sent: string[][] = [];
  bus = new ResponseBus();
  async send(req: Parameters<DeviceLink['send']>[0]): Promise<void> {
    this.sent.push(requestParts(req));
  }
  onResponse(cb: (t: string) => void) {
    return this.bus.on(cb);
  }
  close(): void {}
}

describe('requestParts / sendToDevice', () => {
  it('cuts {urType, cbor} into exactly the parts @ripar/protocol builds', () => {
    const req = pairRequest();
    expect(req.parts.length).toBeGreaterThan(1);
    expect(requestParts({ urType: req.type, cbor: req.cbor })).toEqual(req.parts);
    expect(requestParts({ urType: req.type, cbor: req.cbor }, 70)).toEqual(urParts(req.type, req.cbor, 70));
    expect(requestParts(req)).toEqual(req.parts);
  });

  it('keeps ready parts, upper-cased, and refuses what is not a UR', () => {
    const req = pairRequest();
    expect(requestParts(req.parts.map((p) => p.toLowerCase()))).toEqual(req.parts);
    expect(() => requestParts([])).toThrow(DeviceLinkError);
    expect(() => requestParts(['hello'])).toThrow(DeviceLinkError);
    expect(() => requestParts({ urType: 'Bad Type', cbor: req.cbor })).toThrow(DeviceLinkError);
  });

  it('a request that fits one fragment is one part, cut as the protocol cuts it', () => {
    const cbor = Uint8Array.from({ length: 40 }, (_, i) => i);
    expect(requestParts({ urType: 'ripar-test', cbor })).toEqual(urParts('ripar-test', cbor, 70));
    expect(requestParts({ urType: 'ripar-test', cbor })).toHaveLength(1);
    // too short for the fountain encoder: a single-part UR
    const tiny = Uint8Array.of(0xa1, 0x01, 0x02);
    expect(requestParts({ urType: 'ripar-test', cbor: tiny })).toEqual([urSingle('ripar-test', tiny).toUpperCase()]);
  });

  it('sendToDevice hands the parts to the link', async () => {
    const l = new TestLink();
    const req = pairRequest();
    await sendToDevice(l, req);
    await sendToDevice(l, { urType: req.type, cbor: req.cbor });
    expect(l.sent).toEqual([req.parts, req.parts]);
  });
});

describe('classifyResponse / awaitDeviceResponse', () => {
  const answer = urSingle('ripar-pair', Uint8Array.of(0xa1, 0x02, 0x03)).toUpperCase();

  it('accepts a complete, CRC-valid single part of an expected type', () => {
    expect(classifyResponse(answer, ['ripar-pair'])).toEqual({ ok: true, type: 'ripar-pair', ur: answer });
    expect(classifyResponse(answer.toLowerCase(), ['ripar-pair'])).toMatchObject({ ok: true, ur: answer });
  });

  it('ignores other types, multipart frames, broken CRCs and garbage', () => {
    expect(classifyResponse(answer, ['ripar-cosign'])).toMatchObject({ ok: false, reason: 'unexpected ripar-pair' });
    expect(classifyResponse(pairRequest().parts[0]!, ['ripar-pair']).ok).toBe(false);
    const broken = answer.slice(0, -2) + (answer.endsWith('AA') ? 'BB' : 'AA');
    expect(classifyResponse(broken, ['ripar-pair']).ok).toBe(false);
    expect(classifyResponse('https://example.com', ['ripar-pair']).ok).toBe(false);
    expect(classifyResponse('   ', ['ripar-pair'])).toMatchObject({ ok: false, reason: 'empty' });
  });

  it('resolves with the first acceptable answer and reports the rest as ignored', async () => {
    const l = new TestLink();
    const ignored: string[] = [];
    const p = awaitDeviceResponse(l, 'ripar-pair', { onIgnored: (_t, r) => ignored.push(r), accept: (u) => u === answer });
    l.bus.emit('not a qr');
    l.bus.emit(urSingle('ripar-cosign', Uint8Array.of(1)));
    l.bus.emit(answer);
    await expect(p).resolves.toBe(answer);
    expect(ignored).toHaveLength(2);
  });

  it('times out and can be cancelled', async () => {
    const l = new TestLink();
    await expect(awaitDeviceResponse(l, ['ripar-pair'], { timeoutMs: 20 })).rejects.toBeInstanceOf(DeviceTimeoutError);
    const ctl = new AbortController();
    const p = awaitDeviceResponse(l, ['ripar-pair'], { signal: ctl.signal });
    ctl.abort();
    await expect(p).rejects.toBeInstanceOf(DeviceCancelledError);
  });
});

describe('requestAndVerify', () => {
  it('listens before sending, sends, verifies the answer', async () => {
    const l = new TestLink();
    const req = pairRequest();
    const answer = urSingle('ripar-pair', Uint8Array.of(0xa1, 0x02, 0x03)).toUpperCase();
    // the link answers synchronously inside send(): only a listener registered first sees it
    l.send = async (r) => {
      l.sent.push(requestParts(r));
      l.bus.emit(answer);
    };
    const out = await requestAndVerify(l, req, verifierOf(['ripar-pair'], (ur) => ur.length));
    expect(l.sent).toEqual([req.parts]);
    expect(out).toEqual({ ur: answer, result: answer.length });
  });

  it('rejects when the verifier refuses the answer', async () => {
    const l = new TestLink();
    const p = requestAndVerify(
      l,
      null,
      verifierOf(['ripar-pair'], () => {
        throw new Error('bad signature');
      }),
    );
    l.bus.emit(urSingle('ripar-pair', Uint8Array.of(1)));
    await expect(p).rejects.toThrow('bad signature');
  });

  it('a failed send ends the round', async () => {
    const l = new TestLink();
    l.send = async () => {
      throw new Error('radio off');
    };
    await expect(requestAndVerify(l, pairRequest(), verifierOf(['ripar-pair'], (u) => u))).rejects.toThrow('radio off');
  });
});

describe('QrLink', () => {
  it('shows the parts of the request and restarts on every send', async () => {
    const q = new QrLink(300, 70);
    const req = pairRequest();
    await q.send(req.parts);
    const f1 = q.frames.get()!;
    expect(f1.parts).toEqual(req.parts);
    expect(f1.frameMs).toBe(300);
    await q.send({ urType: req.type, cbor: req.cbor });
    expect(q.frames.get()!.parts).toEqual(req.parts);
    expect(q.frames.get()!.seq).toBe(f1.seq + 1);
    q.stopPresenting();
    expect(q.frames.get()).toBeNull();
  });

  it('reports a QR the camera keeps seeing once per second', () => {
    const q = new QrLink();
    const seen: string[] = [];
    q.onResponse((t) => seen.push(t));
    q.cameraRead('UR:X/1', 1000);
    q.cameraRead('UR:X/1', 1500);
    q.cameraRead('UR:X/2', 1600);
    q.cameraRead('UR:X/1', 2700);
    q.resetReads();
    q.cameraRead('UR:X/1', 2800);
    expect(seen).toEqual(['UR:X/1', 'UR:X/2', 'UR:X/1', 'UR:X/1']);
  });

  it('pairs the emulated Ripar through the camera path: the device scans the looped frames', async () => {
    const dev = new FakeRipar(await newEmu());
    const q = new QrLink(300, 70);
    const req = pairRequest();
    const round = requestAndVerify(q, req, verifierOf(['ripar-pair'], (ur) => ur, (ur) => ur.startsWith('UR:RIPAR-PAIR/')));
    await new Promise((r) => setTimeout(r, 0));
    // the device's camera watches the loop
    dev.key('press');
    const frames = q.frames.get()!;
    for (let i = 0; i < frames.parts.length * 3 && dev.emu.state().screen === 'scan'; i++) {
      dev.emu.scan(frames.parts[i % frames.parts.length]!);
      dev.tick(300);
    }
    expect(dev.emu.state().screen).toBe('review');
    approveOnDevice(dev);
    const s = dev.emu.state();
    expect(s.screen).toBe('qr');
    // this phone's camera reads the answer
    q.cameraRead(s.qr!.text);
    const { ur } = await round;
    expect(ur).toBe(s.qr!.text.toUpperCase());
    dev.emu.destroy();
  });
});
