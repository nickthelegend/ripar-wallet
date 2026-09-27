// The TEMPORARY Wi-Fi link: the PROV payload sent over Bluetooth, the address / code helpers, and WifiLink against a
// real local HTTP server whose far end is the emulated firmware (test/helpers.ts FakeWifiRipar).
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { attPayload, parseDeviceStatus, withKnownIp } from '../src/device/ble-framing';
import { BleLink } from '../src/device/ble-link';
import { requestAndVerify, verifierOf } from '../src/device/link';
import { WifiLink, WifiLinkError, isLanIpv4, noteOf, normalizeWifiCode, rxBatches, wifiBaseUrl } from '../src/device/wifi-link';
import { WifiProvisioningError, credentialsProblem, encodeProvisioning, provWriteKind, ssidShownAltered } from '../src/device/wifi-prov';
import { acceptPairing, answersRequest, isKeysOnlyPair, planPairing, readKeysOnly } from '../src/lib/flows/pairing';
import { utf8Decode } from '../src/lib/utf8';
import { DEMO_K1, DEMO_VAULT, DEP, FakeRipar, FakeWifiRipar, NOW, approveOnDevice, newEmu } from './helpers';

describe('Wi-Fi provisioning payload (PROV characteristic)', () => {
  it('is one UTF-8 JSON value {"v":1,"ssid","pass"}, keys in that order', () => {
    const b = encodeProvisioning({ ssid: 'Café "5" \\ net', pass: 'correct horse' });
    const text = utf8Decode(b, true);
    expect(text.startsWith('{"v":1,')).toBe(true);
    expect(text.endsWith('}')).toBe(true);
    const o = JSON.parse(text) as Record<string, unknown>;
    expect(o).toEqual({ v: 1, ssid: 'Café "5" \\ net', pass: 'correct horse' });
    expect(Object.keys(o)).toEqual(['v', 'ssid', 'pass']);
    // non-ASCII stays raw UTF-8 (no \u escapes the device would have to decode)
    expect(Buffer.from(b).includes(Buffer.from('Café', 'utf8'))).toBe(true);
    // an open network: empty password
    expect(JSON.parse(utf8Decode(encodeProvisioning({ ssid: 'open', pass: '' })))).toEqual({ v: 1, ssid: 'open', pass: '' });
  });

  it('enforces the firmware rules: SSID 1..32 bytes, password empty or 8..63 printable ASCII', () => {
    const ok = (ssid: string, pass: string) => credentialsProblem({ ssid, pass }) === null;
    expect(ok('', 'password1')).toBe(false);
    expect(ok('x'.repeat(32), '')).toBe(true);
    expect(ok('x'.repeat(33), '')).toBe(false);
    expect(ok('é'.repeat(16), '')).toBe(true); // 32 bytes
    expect(ok('é'.repeat(17), '')).toBe(false); // 34 bytes
    expect(ok('net', 'a'.repeat(7))).toBe(false);
    expect(ok('net', 'a'.repeat(8))).toBe(true);
    expect(ok('net', 'a'.repeat(63))).toBe(true);
    expect(ok('net', 'a'.repeat(64))).toBe(false); // a 64-hex PSK is not a passphrase: not in the contract
    expect(ok('net', 'pässwörd-long')).toBe(false); // WPA passphrases are ASCII (firmware parse_prov)
    expect(ok('net', ' spaces ok ~!')).toBe(true);
    expect(ok('bad\nname', '')).toBe(false);
    expect(ok('net', 'tab\there!')).toBe(false);
    expect(ok('\ud800lone', '')).toBe(false);
    expect(ssidShownAltered('Café')).toBe(true); // the device shows it as "Caf??"
    expect(ssidShownAltered('Ripar Lab')).toBe(false);
  });

  it('never puts the password in an error', () => {
    const secret = 'hunter2';
    let err: unknown;
    try {
      encodeProvisioning({ ssid: 'home', pass: secret });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(WifiProvisioningError);
    expect((err as Error).message).toMatch(/too short/);
    expect((err as Error).message).not.toContain(secret);
    const long = 'p'.repeat(70);
    expect(credentialsProblem({ ssid: 'home', pass: long })).not.toContain(long);
  });

  it('is at most 217 bytes even with every character escaped: one ATT write at MTU 247, far below the 512 B limit', () => {
    const worst = encodeProvisioning({ ssid: '"'.repeat(32), pass: '\\'.repeat(63) });
    expect(worst.length).toBe(217);
    expect(worst.length).toBeLessThanOrEqual(attPayload(247));
    expect(provWriteKind(worst, 247)).toBe('single');
    expect(provWriteKind(worst, 23)).toBe('long');
  });

  it('goes to PROV as one whole value at every MTU (never split: the firmware takes one write as one value)', async () => {
    const creds = { ssid: 'Ripar Lab 2.4G', pass: 'a long enough passphrase' };
    const want = Buffer.from(encodeProvisioning(creds));
    for (const mtu of [23, 64, 247]) {
      const dev = new FakeRipar(await newEmu(), mtu);
      const link = new BleLink(dev);
      const { bytes } = await link.provisionWifi(creds);
      expect(bytes).toBe(want.length);
      expect(dev.provWrites).toHaveLength(1);
      expect(Buffer.from(dev.provWrites[0]!).equals(want)).toBe(true);
      // beyond MTU-3 the BLE stack sends it as a long write (prepare + execute), which the firmware reassembles
      expect(provWriteKind(dev.provWrites[0]!, mtu)).toBe(want.length <= attPayload(mtu) ? 'single' : 'long');
      // what the firmware's strict parser gets: exactly v, ssid, pass
      expect(JSON.parse(utf8Decode(dev.provWrites[0]!, true))).toEqual({ v: 1, ...creds });
      // nothing went to RX: provisioning is not a request line
      expect(dev.writes).toHaveLength(0);
      link.close();
      dev.emu.destroy();
    }
  });

  it('writes nothing when the credentials break a rule', async () => {
    const dev = new FakeRipar(await newEmu(), 247);
    const link = new BleLink(dev);
    await expect(link.provisionWifi({ ssid: 'x'.repeat(40), pass: '' })).rejects.toThrow(/at most 32/);
    await expect(link.provisionWifi({ ssid: 'home', pass: 'short' })).rejects.toThrow(WifiProvisioningError);
    expect(dev.provWrites).toHaveLength(0);
    link.close();
    dev.emu.destroy();
  });
});

describe('Wi-Fi STATUS, address and code helpers', () => {
  it('parses "wifi" and "ip" from STATUS when the firmware reports them', () => {
    const s = parseDeviceStatus('{"v":1,"screen":"HOME","paired":true,"radio":"on","wifi":"ON","ip":"192.168.1.23"}', 1);
    expect(s?.wifi).toBe('on');
    expect(s?.ip).toBe('192.168.1.23');
    const t = parseDeviceStatus('{"v":1,"screen":"HOME","wifi":"connecting","ip":"999.1.1.1"}');
    expect(t?.wifi).toBe('connecting');
    expect(t?.ip).toBeUndefined();
    expect(parseDeviceStatus('{"v":1,"screen":"HOME","ip":"0.0.0.0"}')?.ip).toBeUndefined();
    // BLE-only firmware: the keys stay absent
    expect(parseDeviceStatus('{"v":1,"screen":"HOME"}')).not.toHaveProperty('wifi');
  });

  it('keeps the last known ip when a STATUS leaves it out for a note (WIFI_LINK.md 5.4)', () => {
    const a = parseDeviceStatus('{"v":1,"screen":"HOME","wifi":"on","ip":"192.168.1.23"}')!;
    const b = parseDeviceStatus('{"v":1,"screen":"HOME","wifi":"on","note":"ignored: not on SCAN (press SIGN on the device first)"}')!;
    expect(withKnownIp(a, b).ip).toBe('192.168.1.23');
    expect(withKnownIp(a, b).note).toMatch(/not on SCAN/);
    // Wi-Fi went off or is reconnecting: the old address is not kept
    expect(withKnownIp(a, parseDeviceStatus('{"v":1,"screen":"HOME","wifi":"connecting"}')!).ip).toBeUndefined();
    expect(withKnownIp(null, b).ip).toBeUndefined();
  });

  it('turns what the user typed into an http base URL, or says why not', () => {
    expect(wifiBaseUrl('192.168.1.23')).toBe('http://192.168.1.23');
    expect(wifiBaseUrl(' http://192.168.1.23:80/status ')).toBe('http://192.168.1.23');
    expect(wifiBaseUrl('10.0.0.7:8080')).toBe('http://10.0.0.7:8080');
    expect(wifiBaseUrl('RIPAR-3F9A.local')).toBe('http://ripar-3f9a.local');
    for (const bad of ['', 'https://192.168.1.23', 'ftp://x', '192.168.1.256', '192.168.1', '01.2.3.4', 'a b', '1.2.3.4:70000', '-bad-.local']) {
      expect(() => wifiBaseUrl(bad), bad).toThrow(WifiLinkError);
    }
    expect(isLanIpv4('192.168.4.1')).toBe(true);
    expect(isLanIpv4('172.20.10.3')).toBe(true);
    expect(isLanIpv4('10.1.2.3')).toBe(true);
    expect(isLanIpv4('8.8.8.8')).toBe(false);
  });

  it('accepts the code as 8 digits, with spaces or a dash', () => {
    expect(normalizeWifiCode('48151623')).toBe('48151623');
    expect(normalizeWifiCode('4815 1623')).toBe('48151623');
    expect(normalizeWifiCode('4815-1623')).toBe('48151623');
    for (const bad of ['', '1234567', '123456789', '1234abcd']) expect(normalizeWifiCode(bad)).toBeNull();
    expect(() => new WifiLink({ host: '192.168.1.23', code: '1234' })).toThrow(/8 digits/);
  });

  it('batches request lines and reads the device note of a 409', () => {
    const parts = ['A'.repeat(300), 'B'.repeat(300), 'C'.repeat(300), 'D'.repeat(10), 'E'.repeat(10), 'F'];
    const b = rxBatches(parts, 4, 1024);
    expect(b.flat()).toEqual(parts);
    expect(b.every((x) => x.length <= 4 && x.reduce((n, l) => n + l.length + 1, 0) <= 1024)).toBe(true);
    expect(rxBatches(['X'.repeat(2000)], 4, 1024)).toEqual([['X'.repeat(2000)]]);
    expect(noteOf('{"note":"ignored: not on SCAN"}')).toBe('ignored: not on SCAN');
    expect(noteOf('not on SCAN\n')).toBe('not on SCAN');
    expect(noteOf('')).toBeNull();
  });
});

describe('WifiLink with the emulated Ripar behind a local HTTP server', () => {
  /** real HTTP on 127.0.0.1, fast loops: every sleep is at most 5 ms */
  const fast = (ms: number) => new Promise<void>((r) => setTimeout(r, Math.min(ms, 5)));
  const cleanup: (() => Promise<void> | void)[] = [];
  afterEach(async () => {
    for (const c of cleanup.splice(0).reverse()) await c();
  });

  async function rig(opts: Partial<ConstructorParameters<typeof WifiLink>[0]> = {}) {
    const dev = await new FakeWifiRipar(await newEmu()).start();
    const link = new WifiLink({ host: dev.host, code: dev.code, sleep: fast, requestTimeoutMs: 3000, ...opts });
    cleanup.push(() => dev.emu.destroy(), () => dev.stop(), () => link.close());
    return { dev, link };
  }

  async function until(cond: () => boolean, what: string, ms = 10_000) {
    const end = Date.now() + ms;
    while (!cond()) {
      if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
      await fast(5);
    }
  }

  it('checks the code and reads STATUS (screen, Wi-Fi on, IP)', async () => {
    const { dev, link } = await rig();
    const s = await link.open();
    expect(s.screen).toBe('HOME');
    expect(s.wifi).toBe('on');
    expect(s.ip).toBe('127.0.0.1');
    // "radio" is the Bluetooth link: "off" over HTTP is normal, not an error
    expect(s.radio).toBe('off');
    expect(link.conn.get().state).toBe('online');
    // a STATUS without "ip" (a note needed the room) keeps the last known address
    dev.omitIp = true;
    expect((await link.refreshStatus()).ip).toBe('127.0.0.1');
    await until(() => dev.requests.some((r) => r.path === '/tx'), 'a TX poll');
    expect(dev.requests.every((r) => r.code === dev.code)).toBe(true);
  });

  it('reads the keys-only pairing QR from GET /tx', async () => {
    const { dev, link } = await rig();
    await link.open();
    const round = requestAndVerify(link, null, verifierOf(['ripar-pair'], readKeysOnly, isKeysOnlyPair), { timeoutMs: 20_000 });
    dev.key('hold2'); // hold 2 s on Home, release: the pairing QR
    const { result } = await round;
    expect(result.k1Address).toBe(DEMO_K1);
    expect(result.emulator).toBe(true);
  });

  it('pairing round trip: waits for SCAN, POSTs the parts, verifies the signed pairing', async () => {
    const { dev, link } = await rig();
    await link.open();
    // small fragments: more parts than one POST carries (4 lines), so the batching is exercised
    const plan = planPairing(DEP, DEMO_K1, { now: NOW, fragLen: 25 });
    expect(plan.request.parts.length).toBeGreaterThan(4);
    const phases: string[] = [];
    link.phase.subscribe((p) => phases.push(p.kind));
    const round = requestAndVerify(link, plan.request, verifierOf(['ripar-pair'], (ur) => acceptPairing(ur, plan, null), (ur) => answersRequest(ur, plan.request)), {
      timeoutMs: 30_000,
    });
    await until(() => phases.includes('waiting-scan'), 'waiting-scan');
    // the device is on HOME: nothing is posted until the user presses SIGN there
    await fast(50);
    expect(dev.posts).toHaveLength(0);
    dev.key('press');
    await until(() => dev.emu.state().screen !== 'scan' && dev.emu.state().screen !== 'home', 'the review');
    expect(dev.emu.state().screen).toBe('review');
    expect(new Set(dev.linesFed)).toEqual(new Set(plan.request.parts));
    // parts went in batches of at most 4 lines, each ending LF
    expect(dev.posts.every((b) => b.endsWith('\n') && b.trim().split('\n').length <= 4)).toBe(true);
    expect(dev.posts.some((b) => b.trim().split('\n').length > 1)).toBe(true);
    approveOnDevice(dev);
    const { result } = await round;
    expect(result.k1Address).toBe(DEMO_K1);
    expect(result.pinned.vault).toBe(DEMO_VAULT);
    expect(phases).toContain('sending');
    expect(phases).toContain('sent');
  });

  it('a wrong code is refused with a clear error, and nothing is polled', async () => {
    const { dev } = await rig();
    const wrong = new WifiLink({ host: dev.host, code: '0000 0000', sleep: fast });
    cleanup.push(() => wrong.close());
    const err = await wrong.open().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(WifiLinkError);
    expect((err as WifiLinkError).kind).toBe('unauthorized');
    expect((err as WifiLinkError).httpStatus).toBe(401);
    expect((err as Error).message).toMatch(/8-digit code/);
    expect(wrong.conn.get().state).toBe('unauthorized');
    expect(wrong.status.get()).toBeNull();
    await fast(30);
    expect(dev.requests).toHaveLength(1);
  });

  it('names the lock-out after repeated wrong codes (429 + Retry-After)', async () => {
    const { dev } = await rig();
    const tryCode = async (code: string) => {
      const l = new WifiLink({ host: dev.host, code, sleep: fast });
      cleanup.push(() => l.close());
      return l.open().then(
        () => null,
        (e: unknown) => e as WifiLinkError,
      );
    };
    for (let i = 0; i < 4; i++) expect((await tryCode('11111111'))?.kind).toBe('unauthorized');
    const locked = await tryCode(dev.code); // even the right code waits out the lock
    expect(locked).toBeInstanceOf(WifiLinkError);
    expect((locked as WifiLinkError).kind).toBe('locked');
    expect((locked as WifiLinkError).httpStatus).toBe(429);
    expect((locked as Error).message).toMatch(/Locked: too many wrong codes.*for 1 s/);
    expect((locked as WifiLinkError).retryAfterMs).toBe(1000);
  });

  it('a connected link backs off while the device is locked by someone else, then comes back', async () => {
    const { dev } = await rig();
    // real sleeps here: the back-off waits out Retry-After
    const link = new WifiLink({ host: dev.host, code: dev.code, pollMs: 50 });
    cleanup.push(() => link.close());
    await link.open();
    // wrong codes from another client between two of our polls (a correct code resets the device's count)
    dev.lock(1000);
    await until(() => link.conn.get().state === 'locked', 'locked');
    const c = link.conn.get() as { state: 'locked'; message: string; until: number };
    expect(c.message).toMatch(/Locked: too many wrong codes.*1 s/);
    const during = dev.requests.length;
    await until(() => link.conn.get().state === 'online', 'online again', 5000);
    // one poll after the lock ended, not one every 50 ms while it lasted
    expect(dev.requests.length - during).toBeLessThanOrEqual(4);
  });

  it('stops polling when the device changes its code (the Ripar restarted)', async () => {
    const { dev, link } = await rig();
    await link.open();
    dev.code = '11112222';
    await until(() => link.conn.get().state === 'unauthorized', 'unauthorized');
    const n = dev.requests.length;
    await fast(50);
    expect(dev.requests.length).toBe(n);
    // a request after that fails at once with the same clear error
    await expect(link.send(['UR:RIPAR-PAIR-REQ/1-2/LPADAOCFADAXHDCXAXAX'])).rejects.toMatchObject({ kind: 'unauthorized' });
  });

  it('409 off SCAN: the device note comes back; send() gives up with guidance when SIGN is never pressed', async () => {
    const { dev, link } = await rig({ scanWaitMs: 300 });
    await link.open();
    const plan = planPairing(DEP, DEMO_K1, { now: NOW, fragLen: 70 });
    const err = await link.postLines(plan.request.parts.slice(0, 2)).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(WifiLinkError);
    expect((err as WifiLinkError).kind).toBe('not-scanning');
    expect((err as WifiLinkError).httpStatus).toBe(409);
    expect((err as WifiLinkError).note).toMatch(/not on SCAN/);
    expect((err as Error).message).toMatch(/press SIGN once on its Home screen/i);
    expect(dev.linesFed).toHaveLength(0);
    // the 409 answer is the device STATUS, note included: the link publishes it at once
    expect(link.status.get()?.note).toMatch(/not on SCAN/);
    expect((await link.refreshStatus()).note).toMatch(/not on SCAN/);
    const phases: string[] = [];
    link.phase.subscribe((p) => phases.push(p.kind));
    await expect(link.send(plan.request.parts)).rejects.toThrow(/did not start scanning.*press SIGN/);
    expect(phases).toContain('waiting-scan');
    expect(dev.linesFed).toHaveLength(0);
  });

  it('a 409 mid-send (device left SCAN between polls) is retried once the device scans', async () => {
    const { dev, link } = await rig();
    await link.open();
    const plan = planPairing(DEP, DEMO_K1, { now: NOW, fragLen: 70 });
    dev.key('press');
    await until(() => link.status.get()?.screen === 'SCAN', 'SCAN in STATUS');
    dev.refuseNextPosts = 1;
    await link.send(plan.request.parts);
    expect(dev.emu.state().screen).toBe('review');
    expect(dev.posts.length).toBeGreaterThan(Math.ceil(plan.request.parts.length / 4));
    expect(new Set(dev.linesFed)).toEqual(new Set(plan.request.parts));
  });

  it('an address with no Ripar behind it fails with a clear error', async () => {
    const probe = createServer();
    await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
    const port = (probe.address() as AddressInfo).port;
    await new Promise<void>((r) => probe.close(() => r()));
    const link = new WifiLink({ host: `127.0.0.1:${port}`, code: '48151623', sleep: fast, retries: 1, retryDelayMs: 5 });
    cleanup.push(() => link.close());
    const err = await link.open().catch((e: unknown) => e);
    expect((err as WifiLinkError).kind).toBe('unreachable');
    expect((err as Error).message).toMatch(/Cannot reach 127\.0\.0\.1:\d+.*same Wi-Fi/);
    expect(link.conn.get().state).toBe('offline');
  });

  it('a web server that is not a Ripar is named as such', async () => {
    const other = createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<html>router login</html>');
    });
    await new Promise<void>((r) => other.listen(0, '127.0.0.1', r));
    cleanup.push(() => new Promise<void>((r) => (other.closeAllConnections(), other.close(() => r()))));
    const link = new WifiLink({ host: `127.0.0.1:${(other.address() as AddressInfo).port}`, code: '48151623', sleep: fast });
    cleanup.push(() => link.close());
    await expect(link.open()).rejects.toMatchObject({ kind: 'not-ripar' });
  });
});
