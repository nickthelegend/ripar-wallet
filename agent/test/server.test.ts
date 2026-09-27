// The HTTP API end to end on a real socket (fake chain behind it): routes, CORS, content-type / origin / token
// guards, SSE, and the companion flow mandate -> run -> escalation -> co-sign -> executed.
import { afterEach, describe, expect, it } from 'vitest';
import { request as httpRequest } from 'node:http';
import { createApp, type AgentApp } from '../src/app.js';
import { makeFixture, type Fixture } from './helpers/fixture.js';
import { cosignEscalation, delegationJson } from './helpers/soft-device.js';

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
    const d = await call(url, `/escalations/${id2}/deny`, { body: {} });
    expect(d.json.escalation.status).toBe('denied');

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
