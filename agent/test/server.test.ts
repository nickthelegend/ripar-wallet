// The HTTP API end to end on a real socket (fake chain behind it): routes, CORS, content-type / origin / token
// guards, SSE, and the companion flow mandate -> run -> escalation -> co-sign -> executed.
import { afterEach, describe, expect, it } from 'vitest';
import { request as httpRequest } from 'node:http';
import { connect } from 'node:net';
import { createApp, type AgentApp } from '../src/app.js';
import { RELAY, makeFixture, type Fixture } from './helpers/fixture.js';
import { cosignEscalation, delegationJson, denyEscalation } from './helpers/soft-device.js';

const ORIGIN = 'http://localhost:5173';
let app: AgentApp | null = null;
afterEach(async () => {
  await app?.close();
  app = null;
});

async function start(env: Record<string, string> = {}): Promise<{ f: Fixture; url: string }> {
  const f = makeFixture({ HOST: '127.0.0.1', PORT: '0', ...env });
  app = await createApp(f.config, { chain: f.chain });
  const url = await app.listen();
  return { f, url };
}

async function call(url: string, path: string, init: { method?: string; body?: unknown; headers?: Record<string, string> } = {}) {
  const res = await fetch(url + path, {
    method: init.method ?? (init.body !== undefined ? 'POST' : 'GET'),
    headers: { ...(init.body !== undefined ? { 'content-type': 'application/json' } : {}), ...init.headers },
    ...(init.body !== undefined ? { body: typeof init.body === 'string' ? init.body : JSON.stringify(init.body) } : {}),
  });
  const text = await res.text();
  return { status: res.status, headers: res.headers, json: text ? (JSON.parse(text) as any) : null };
}

describe('HTTP API', () => {
  it('health, state, CORS and guards', async () => {
    const { url } = await start();
    const h = await call(url, '/health', { headers: { origin: ORIGIN } });
    expect(h.status).toBe(200);
    expect(h.json).toMatchObject({ ok: true, service: 'ripar-agent', planner: 'scripted', mandate: null });
    expect(h.headers.get('access-control-allow-origin')).toBe(ORIGIN);
    const evil = await call(url, '/health', { headers: { origin: 'https://evil.example' } });
    expect(evil.headers.get('access-control-allow-origin')).toBeNull();
    const pre = await fetch(url + '/mandate', { method: 'OPTIONS', headers: { origin: ORIGIN, 'access-control-request-method': 'POST' } });
    expect(pre.status).toBe(204);
    expect(pre.headers.get('access-control-allow-methods')).toContain('POST');
    // a cross-site "simple" request (text/plain) is refused, and so is a foreign origin
    expect((await call(url, '/run', { body: '{}', headers: { 'content-type': 'text/plain' } })).status).toBe(415);
    expect((await call(url, '/run', { body: {}, headers: { origin: 'https://evil.example' } })).status).toBe(403);
    expect((await call(url, '/run', { body: '{bad json' })).status).toBe(400);
    expect((await call(url, '/nope')).status).toBe(404);
    expect((await call(url, '/escalations/esc_missing')).json.error.code).toBe('unknown_escalation');
    // no mandate yet: a planner step reports it, nothing is paid
    const run = await call(url, '/run', { body: {} });
    expect(run.status).toBe(200);
    expect(JSON.stringify(run.json.actions)).toMatch(/no_mandate/);
    const st = await call(url, '/state');
    expect(st.json.mandate).toBeNull();
    expect(st.json.invoices).toHaveLength(4);
  });

  it('the companion flow: mandate -> run -> escalation -> co-sign -> executed; SSE events', async () => {
    const { f, url } = await start();
    const events: { event: string; data: any }[] = [];
    const sse = await new Promise<import('node:http').IncomingMessage>((resolve) => {
      const r = httpRequest(url + '/events', { headers: { origin: ORIGIN } }, resolve);
      r.end();
    });
    expect(sse.headers['content-type']).toMatch(/text\/event-stream/);
    expect(sse.headers['access-control-allow-origin']).toBe(ORIGIN);
    let buf = '';
    sse.on('data', (c: Buffer) => {
      buf += c.toString('utf8');
      let i;
      while ((i = buf.indexOf('\n\n')) >= 0) {
        const block = buf.slice(0, i);
        buf = buf.slice(i + 2);
        const ev = /^event: (.*)$/m.exec(block)?.[1];
        const data = /^data: (.*)$/m.exec(block)?.[1];
        if (ev && data) events.push({ event: ev, data: JSON.parse(data) });
      }
    });

    const m = await call(url, '/mandate', { body: { delegation: delegationJson(f.mandate) }, headers: { origin: ORIGIN } });
    expect(m.status).toBe(200);
    expect(m.json.mandate.vault).toBe(f.dev.vault);
    const bad = await call(url, '/mandate', { body: { delegation: { ...delegationJson(f.mandate), signature: '0x' } } });
    expect(bad.status).toBe(422);
    expect(bad.json.error.code).toBe('bad_mandate');

    const run = await call(url, '/run', { body: {} });
    expect(run.json.summary).toMatch(/sent INV-001 to the human/);
    const list = await call(url, '/escalations');
    expect(list.json.escalations).toHaveLength(1);
    const id = list.json.escalations[0].id as string;
    const esc = (await call(url, `/escalations/${id}`)).json;
    expect(esc.cosign.nonce).toMatch(/^\d+$/);
    expect(esc.request.ur).toMatch(/^UR:RIPAR-COSIGN-REQ\//);

    const sig = cosignEscalation(f.dev, esc.cosign, esc.request.reqId);
    const ok = await call(url, `/escalations/${id}/cosign`, { body: { ur: sig.ur }, headers: { origin: ORIGIN } });
    expect(ok.status).toBe(200);
    expect(ok.json.escalation.status).toBe('executed');
    expect(ok.json.payment.path).toBe('human');
    const again = await call(url, `/escalations/${id}/cosign`, { body: { ur: sig.ur } });
    expect(again.status).toBe(409);
    expect(again.json.error.code).toBe('already_executed');

    const run2 = await call(url, '/run', { body: {} });
    expect(run2.json.summary).toMatch(/INV-002/);
    const id2 = (await call(url, '/escalations')).json.escalations[0].id;
    // a deny needs the device's signed ripar-deny
    const noUr = await call(url, `/escalations/${id2}/deny`, { body: {} });
    expect(noUr.status).toBe(400);
    expect(noUr.json.error.code).toBe('deny_needs_device');
    const esc2 = (await call(url, `/escalations/${id2}`)).json;
    const d = await call(url, `/escalations/${id2}/deny`, { body: { ur: denyEscalation(f.dev, esc2, RELAY, 7n), note: 'redirect' } });
    expect(d.json.escalation.status).toBe('denied');
    expect(d.json.escalation.deny.verified).toBe(true);

    const st = (await call(url, '/state')).json;
    expect(st.budget.remaining).toBe('20000000');
    expect(st.payments).toHaveLength(1);
    expect(st.invoices.find((i: any) => i.id === 'INV-002').status).toBe('denied');

    await new Promise((r) => setTimeout(r, 100));
    sse.destroy();
    const types = events.map((e) => e.event);
    expect(types[0]).toBe('hello');
    expect(types).toEqual(expect.arrayContaining(['mandate', 'escalation', 'payment', 'invoice', 'run', 'log']));
    const payEv = events.find((e) => e.event === 'payment')!;
    expect(payEv.data.path).toBe('human');
  });

  it('AGENT_API_TOKEN protects every POST', async () => {
    const { url } = await start({ AGENT_API_TOKEN: 'secret-token-123' });
    expect((await call(url, '/run', { body: {} })).status).toBe(401);
    expect((await call(url, '/run', { body: {}, headers: { authorization: 'Bearer nope' } })).status).toBe(401);
    expect((await call(url, '/run', { body: {}, headers: { authorization: 'Bearer secret-token-123' } })).status).toBe(200);
    expect((await call(url, '/health')).status).toBe(200);
  });
});

/** a raw request with an explicit (or no) Host header: fetch() always derives Host from the URL */
function rawRequest(url: string, path: string, opts: { method?: string; host?: string | null; headers?: Record<string, string>; body?: string } = {}) {
  const u = new URL(url);
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const headers: Record<string, string> = { ...opts.headers };
    if (opts.host !== null) headers.host = opts.host ?? u.host;
    const r = httpRequest({ host: u.hostname, port: u.port, path, method: opts.method ?? 'GET', headers, setHost: opts.host !== null }, (res) => {
      if (/event-stream/.test(String(res.headers['content-type']))) {
        resolve({ status: res.statusCode ?? 0, text: '' });
        res.destroy();
        return;
      }
      let text = '';
      res.on('data', (c: Buffer) => (text += c.toString('utf8')));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, text }));
    });
    r.on('error', reject);
    r.end(opts.body);
  });
}

describe('HTTP API hardening (security review)', () => {
  it('Host allow-list on every request (DNS rebinding)', async () => {
    const { url } = await start({ AGENT_ALLOWED_HOSTS: 'agent.lan' });
    const port = new URL(url).port;
    for (const host of ['evil.example:8787', 'evil.example', `attacker.test:${port}`, 'localhost.:8787', '127.0.0.1:x']) {
      const r = await rawRequest(url, '/health', { host });
      expect(r.status, host).toBe(421);
      expect(JSON.parse(r.text).error.code).toBe('forbidden_host');
    }
    // OPTIONS, SSE and POST too
    expect((await rawRequest(url, '/run', { method: 'OPTIONS', host: 'evil.example:8787', headers: { origin: ORIGIN } })).status).toBe(421);
    expect((await rawRequest(url, '/events', { host: 'evil.example:8787' })).status).toBe(421);
    const post = await rawRequest(url, '/run', { method: 'POST', host: 'evil.example:8787', headers: { 'content-type': 'application/json' }, body: '{}' });
    expect(post.status).toBe(421);
    // no Host header at all: node refuses an HTTP/1.1 request itself (400); an HTTP/1.0 one reaches the allow-list
    expect((await rawRequest(url, '/health', { host: null })).status).toBe(400);
    const http10 = await new Promise<string>((resolve, reject) => {
      const u = new URL(url);
      const sock = connect(Number(u.port), u.hostname, () => sock.end('GET /health HTTP/1.0\r\n\r\n'));
      let buf = '';
      sock.on('data', (c: Buffer) => (buf += c.toString('utf8')));
      sock.on('end', () => resolve(buf));
      sock.on('error', reject);
    });
    expect(http10).toMatch(/^HTTP\/1\.[01] 421 /);
    expect(http10).toContain('forbidden_host');
    // loopback names, IP literals and AGENT_ALLOWED_HOSTS are served
    for (const host of [`127.0.0.1:${port}`, '127.0.0.1', `localhost:${port}`, `[::1]:${port}`, `LOCALHOST:${port}`, `192.168.1.20:${port}`, `agent.lan:${port}`]) {
      expect((await rawRequest(url, '/health', { host })).status, host).toBe(200);
    }
    expect((await rawRequest(url, '/events', { host: `127.0.0.1:${port}` })).status).toBe(200);
  });

  it('AGENT_API_TOKEN protects the GET routes; /health is reduced; /events takes ?token=', async () => {
    const TOKEN = 'secret-token-123';
    const { url } = await start({ AGENT_API_TOKEN: TOKEN, RPC_URL: 'https://rpc.example/v2/SECRETKEY?x=1' });
    const auth = { authorization: `Bearer ${TOKEN}` };
    for (const p of ['/state', '/invoices', '/escalations', '/escalations/esc_0123456789abcdef', '/events', '/nope']) {
      const r = await call(url, p);
      expect(r.status, p).toBe(401);
      expect(r.json.error.code).toBe('unauthorized');
    }
    expect((await call(url, '/state', { headers: { authorization: 'Bearer nope' } })).status).toBe(401);
    const st = await call(url, '/state', { headers: auth });
    expect(st.status).toBe(200);
    expect(st.json.invoices).toHaveLength(4);
    expect((await call(url, '/invoices', { headers: auth })).status).toBe(200);
    expect((await call(url, '/escalations', { headers: auth })).status).toBe(200);
    expect((await call(url, '/escalations/esc_0123456789abcdef', { headers: auth })).json.error.code).toBe('unknown_escalation');
    // /health: open, but only {ok, service} without the token
    const open = await call(url, '/health');
    expect(open.status).toBe(200);
    expect(open.json).toEqual({ ok: true, service: 'ripar-agent' });
    const full = await call(url, '/health', { headers: auth });
    expect(full.json).toMatchObject({ ok: true, service: 'ripar-agent', planner: 'scripted', config: { rpcUrl: 'https://rpc.example', rpcUrlRedacted: true } });
    expect(JSON.stringify(full.json)).not.toContain('SECRETKEY');
    // SSE: EventSource cannot send headers, so the token may come as ?token=
    expect((await rawRequest(url, `/events?token=${TOKEN}`)).status).toBe(200);
    expect((await rawRequest(url, '/events', { headers: auth })).status).toBe(200);
    expect((await rawRequest(url, '/events?token=wrong')).status).toBe(401);
    // ?token= is only for /events
    expect((await call(url, `/state?token=${TOKEN}`)).status).toBe(401);
  });

  it('/health without a token never echoes the RPC key', async () => {
    const { url } = await start({ RPC_URL: 'https://rpc.example/v2/SECRETKEY?x=1' });
    const h = await call(url, '/health');
    expect(h.json.config).toMatchObject({ rpcUrl: 'https://rpc.example', rpcUrlRedacted: true });
    expect(h.json.agent).toMatch(/^0x/);
    expect(JSON.stringify(h.json)).not.toContain('SECRETKEY');
  });

  it('escalation ids: __proto__ / constructor are 404 and pollute nothing', async () => {
    const { url } = await start();
    const d = await call(url, '/escalations/__proto__/deny', { body: { note: 'x', operator: true } });
    expect(d.status).toBe(404);
    expect(d.json.error.code).toBe('unknown_escalation');
    for (const p of ['/escalations/constructor', '/escalations/__proto__', '/escalations/toString']) {
      const r = await call(url, p);
      expect(r.status, p).toBe(404);
      expect(r.json.error.code).toBe('unknown_escalation');
    }
    expect((await call(url, '/escalations/constructor/cosign', { body: {} })).status).toBe(404);
    expect(({} as Record<string, unknown>).status).toBeUndefined();
    expect(({} as Record<string, unknown>).deny).toBeUndefined();
    // responses still work (a polluted Object.prototype breaks every fetch Response, i.e. every viem RPC call)
    expect((await call(url, '/state')).status).toBe(200);
  });

  it('device payloads over 16 KiB are refused (413) before decoding', async () => {
    const { url } = await start();
    const big = 'A'.repeat(16 * 1024 + 1);
    const m = await call(url, '/mandate', { body: { request: `UR:RIPAR-MANDATE-REQ/${big}`, signature: '0x00' } });
    expect(m.status).toBe(413);
    expect(m.json.error.code).toBe('field_too_large');
    expect((await call(url, '/mandate', { body: { request: 'x', signature: big } })).status).toBe(413);
    expect((await call(url, '/escalations/esc_0123456789abcdef/cosign', { body: { ur: big } })).status).toBe(413);
    expect((await call(url, '/escalations/esc_0123456789abcdef/deny', { body: { ur: big } })).status).toBe(413);
  });

  it('deny over HTTP: device ur, repeated with attestTx; operator deny only with the token', async () => {
    const TOKEN = 'secret-token-123';
    const { f, url } = await start({ AGENT_API_TOKEN: TOKEN });
    const auth = { authorization: `Bearer ${TOKEN}` };
    await call(url, '/mandate', { body: { delegation: delegationJson(f.mandate) }, headers: auth });
    await call(url, '/run', { body: {}, headers: auth }); // INV-001 -> escalation
    await call(url, '/run', { body: {}, headers: auth }); // INV-002 -> escalation
    const list = (await call(url, '/escalations', { headers: auth })).json.escalations as { id: string; invoiceId: string }[];
    const e1 = (await call(url, `/escalations/${list.find((e) => e.invoiceId === 'INV-001')!.id}`, { headers: auth })).json;
    const e2 = (await call(url, `/escalations/${list.find((e) => e.invoiceId === 'INV-002')!.id}`, { headers: auth })).json;
    const ur = denyEscalation(f.dev, e1, RELAY, 7n);
    const first = await call(url, `/escalations/${e1.id}/deny`, { body: { ur, note: 'no' }, headers: auth });
    expect(first.json.escalation.deny).toMatchObject({ verified: true, note: 'no' });
    const attestTx = `0x${'9a'.repeat(32)}`;
    const second = await call(url, `/escalations/${e1.id}/deny`, { body: { ur, note: 'no', attestTx }, headers: auth });
    expect(second.status).toBe(200);
    expect(second.json.escalation.deny).toMatchObject({ verified: true, attestTx });
    expect((await call(url, `/escalations/${e1.id}/deny`, { body: { ur, attestTx: 'nope' }, headers: auth })).status).toBe(400);
    // operator deny: {operator: true} with the token
    expect((await call(url, `/escalations/${e2.id}/deny`, { body: {}, headers: auth })).json.error.code).toBe('deny_needs_device');
    const op = await call(url, `/escalations/${e2.id}/deny`, { body: { operator: true, note: 'ops' }, headers: auth });
    expect(op.json.escalation.deny).toMatchObject({ verified: false, operator: true });
    expect((await call(url, `/escalations/${e2.id}/deny`, { body: { operator: true } })).status).toBe(401);
  });
});
