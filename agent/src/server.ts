// HTTP API (node:http, no framework) for the companion app:
//   GET  /health                      liveness; + agent, planner, mandate, public config (with a token set: only when authenticated)
//   GET  /state                       mandate, vault balances, AUTO budget, lane, invoices, escalations, payments
//   GET  /invoices                    invoices with their status
//   GET  /escalations                 every escalation (newest first)
//   GET  /escalations/:id             one escalation: the co-sign request fields + prebuilt UR / parts
//   POST /escalations/:id/cosign      the device's ripar-cosign ({ur} or {evidence12, salt16, r, s}) -> HUMAN redemption
//   POST /escalations/:id/deny        the device's verified ripar-deny ({ur, note?, attestTx?}) or an operator deny
//                                     ({operator: true}, token required) -> marked denied; repeatable to add attestTx
//   POST /mandate                     the device-signed delegation ({delegation} or {request, signature})
//   POST /run                         one planner step ({instruction?} for the Qwen planner)
//   GET  /events                      Server-Sent Events (log, mandate, escalation, payment, invoice, run)
// Guards, in order:
//   - Host allow-list on EVERY request (DNS rebinding: a page on attacker.example whose name is re-pointed at
//     127.0.0.1 would otherwise be same-origin with this API): localhost, IP literals, HOST when it is a name, and
//     AGENT_ALLOWED_HOSTS. Anything else, or no Host header, gets 421 forbidden_host.
//   - CORS limited to the companion origins; a POST needs Content-Type: application/json (a foreign page cannot send
//     a "simple" cross-site request) and a POST from a foreign Origin gets 403.
//   - With AGENT_API_TOKEN set: Authorization: Bearer <token> on every POST and every GET except /health (which then
//     answers only {ok, service} unless authenticated). GET /events also takes ?token=<token> (EventSource cannot send
//     headers).
//   - Device payloads (ur, request, signature) longer than 16 KiB are refused (413) before any decoder sees them.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';
import { isIPv4, isIPv6 } from 'node:net';
import { ProtoError } from '@ripar/protocol';
import { publicConfig, type AgentConfig } from './config.js';
import { ApiError, capQrFields } from './errors.js';
import type { AgentEvent } from './events.js';
import type { Planner, StepResult } from './planner/index.js';
import type { MandateInput } from './mandate.js';
import { ESCALATION_ID, type AgentService, type CosignSubmission, type DenySubmission } from './service.js';
import { errorMessage, Mutex, toJson } from './util.js';

const MAX_BODY = 256 * 1024;

export interface ServerDeps {
  svc: AgentService;
  planner: Planner;
  config: AgentConfig;
  /** SSE heartbeat period (ms) */
  heartbeatMs?: number;
}

/** the host name of a Host header value, lower case ('[::1]' keeps its brackets); null when malformed */
export function hostNameOf(host: string): string | null {
  const h = host.trim().toLowerCase();
  const m = /^(\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::\d{1,5})?$/.exec(h);
  return m ? m[1]! : null;
}

/** the Host allow-list (see the header comment) */
export function hostAllowed(host: string | undefined, names: ReadonlySet<string>): boolean {
  if (typeof host !== 'string' || host === '') return false;
  const h = hostNameOf(host);
  if (h === null) return false;
  if (h.startsWith('[')) return isIPv6(h.slice(1, -1));
  // an IP literal cannot be re-pointed by DNS; localhost never leaves the machine
  if (isIPv4(h) || h === 'localhost') return true;
  return names.has(h);
}

export function createAgentServer(deps: ServerDeps): Server & { runStep: () => Promise<StepResult> } {
  const { svc, planner, config } = deps;
  const runLock = new Mutex();
  const heartbeatMs = deps.heartbeatMs ?? 15_000;
  const allowed = new Set(config.companionOrigins);
  const hostNames = new Set(config.allowedHosts.map((h) => h.toLowerCase()));
  // HOST=<name> (not an IP literal) is a name this server is meant to be reached by
  if (!isIPv4(config.host) && !isIPv6(config.host.replace(/^\[(.*)\]$/, '$1'))) hostNames.add(config.host.toLowerCase());

  const runStep = (instruction?: string): Promise<StepResult> =>
    runLock.run(async () => {
      const res = await planner.step(instruction);
      svc.events.emit('run', res);
      return res;
    });

  const cors = (req: IncomingMessage): Record<string, string> => {
    const origin = req.headers.origin;
    if (!origin) return {};
    if (allowed.has('*') || allowed.has(origin)) {
      return {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'content-type, authorization, last-event-id',
        'Access-Control-Max-Age': '600',
        Vary: 'Origin',
      };
    }
    return { Vary: 'Origin' };
  };

  const send = (req: IncomingMessage, res: ServerResponse, status: number, body: unknown): void => {
    const text = toJson(body);
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...cors(req),
    });
    res.end(text);
  };

  const readJson = async (req: IncomingMessage): Promise<Record<string, unknown>> => {
    const ct = String(req.headers['content-type'] ?? '');
    if (!/^application\/json\b/i.test(ct)) throw new ApiError(415, 'unsupported_media_type', 'POST bodies must be application/json');
    const chunks: Buffer[] = [];
    let n = 0;
    for await (const c of req) {
      const b = c as Buffer;
      n += b.length;
      if (n > MAX_BODY) throw new ApiError(413, 'too_large', `body larger than ${MAX_BODY} bytes`);
      chunks.push(b);
    }
    const text = Buffer.concat(chunks).toString('utf8');
    if (!text.trim()) return {};
    let v: unknown;
    try {
      v = JSON.parse(text);
    } catch {
      throw new ApiError(400, 'bad_json', 'the body is not valid JSON');
    }
    if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new ApiError(400, 'bad_json', 'expected a JSON object');
    return v as Record<string, unknown>;
  };

  // sha256 first: equal lengths for timingSafeEqual, and the token's length does not leak through timing either
  const digest = (s: string): Buffer => createHash('sha256').update(s, 'utf8').digest();
  const wantBearer = config.apiToken ? digest(`Bearer ${config.apiToken}`) : null;
  const wantToken = config.apiToken ? digest(config.apiToken) : null;

  /** no token configured, or the request carries it (Authorization header; ?token= only where allowed) */
  const authenticated = (req: IncomingMessage, url: URL, queryToken = false): boolean => {
    if (!wantBearer || !wantToken) return true;
    const auth = req.headers.authorization;
    if (typeof auth === 'string' && timingSafeEqual(digest(auth), wantBearer)) return true;
    const q = queryToken ? url.searchParams.get('token') : null;
    return q !== null && timingSafeEqual(digest(q), wantToken);
  };

  const requireAuth = (req: IncomingMessage, url: URL, queryToken = false): void => {
    if (!authenticated(req, url, queryToken)) throw new ApiError(401, 'unauthorized', 'missing or wrong bearer token');
  };

  const checkPost = (req: IncomingMessage, url: URL): void => {
    const origin = req.headers.origin;
    if (origin && !allowed.has('*') && !allowed.has(origin)) throw new ApiError(403, 'forbidden_origin', `origin ${origin} is not allowed`);
    requireAuth(req, url);
  };

  const events = (req: IncomingMessage, res: ServerResponse): void => {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
      ...cors(req),
    });
    const write = (ev: AgentEvent): void => {
      res.write(`id: ${ev.seq}\nevent: ${ev.type}\ndata: ${toJson({ at: ev.at, ...((ev.data as object) ?? {}) })}\n\n`);
    };
    res.write('retry: 3000\n\n');
    const last = Number(req.headers['last-event-id'] ?? NaN);
    if (Number.isFinite(last)) for (const ev of svc.events.recent) if (ev.seq > last) write(ev);
    res.write(`event: hello\ndata: ${toJson({ agent: svc.agent, chainId: config.chainId, planner: planner.kind })}\n\n`);
    const unsubscribe = svc.events.subscribe(write);
    const hb = setInterval(() => res.write(': ping\n\n'), heartbeatMs);
    hb.unref();
    const close = (): void => {
      clearInterval(hb);
      unsubscribe();
    };
    req.on('close', close);
    res.on('error', close);
  };

  const route = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    if (!hostAllowed(req.headers.host, hostNames)) {
      throw new ApiError(421, 'forbidden_host', 'this Host is not served here (set AGENT_ALLOWED_HOSTS to add a name)');
    }
    const url = new URL(req.url ?? '/', 'http://agent.local');
    const path = url.pathname.replace(/\/+$/, '') || '/';
    const method = req.method ?? 'GET';
    if (method === 'OPTIONS') {
      res.writeHead(204, cors(req));
      res.end();
      return;
    }
    const escMatch = /^\/escalations\/([^/]+)(?:\/(cosign|deny))?$/.exec(path);
    // escalation ids are randomId('esc'); anything else ('__proto__', 'constructor', ...) never reaches a lookup
    const escId = (): string => {
      const id = escMatch![1]!;
      if (!ESCALATION_ID.test(id)) throw new ApiError(404, 'unknown_escalation', 'no such escalation');
      return id;
    };

    if (method === 'GET') {
      if (path === '/health') {
        if (!authenticated(req, url)) return send(req, res, 200, { ok: true, service: 'ripar-agent' });
        const m = svc.mandate();
        return send(req, res, 200, {
          ok: true,
          service: 'ripar-agent',
          agent: svc.agent,
          planner: planner.kind,
          mandate: m ? { delegationHash: m.delegationHash, status: m.status } : null,
          config: publicConfig(config),
        });
      }
      if (path === '/events') {
        requireAuth(req, url, true);
        return events(req, res);
      }
      requireAuth(req, url);
      if (path === '/state') return send(req, res, 200, await svc.state());
      if (path === '/invoices') return send(req, res, 200, { invoices: svc.invoiceViews() });
      if (path === '/escalations') return send(req, res, 200, { escalations: svc.escalations() });
      if (escMatch && !escMatch[2]) return send(req, res, 200, svc.escalation(escId()));
      throw new ApiError(404, 'not_found', `no route GET ${path}`);
    }
    if (method === 'POST') {
      checkPost(req, url);
      const body = await readJson(req);
      capQrFields(body);
      if (path === '/mandate') return send(req, res, 200, { mandate: svc.mandateSummary(await svc.acceptMandate(body as MandateInput)) });
      if (path === '/run') {
        const instruction = typeof body.instruction === 'string' ? body.instruction : undefined;
        return send(req, res, 200, await runStep(instruction));
      }
      if (escMatch && escMatch[2] === 'cosign') return send(req, res, 200, await svc.submitCosign(escId(), body as CosignSubmission));
      if (escMatch && escMatch[2] === 'deny') return send(req, res, 200, { escalation: await svc.deny(escId(), body as DenySubmission) });
      throw new ApiError(404, 'not_found', `no route POST ${path}`);
    }
    throw new ApiError(405, 'method_not_allowed', `${method} is not supported`);
  };

  const server = createServer((req, res) => {
    route(req, res).catch((e: unknown) => {
      if (res.headersSent) {
        res.end();
        return;
      }
      if (e instanceof ApiError) return send(req, res, e.status, { error: { code: e.code, message: e.message, ...(e.details !== undefined ? { details: e.details } : {}) } });
      if (e instanceof ProtoError) return send(req, res, 400, { error: { code: 'protocol', message: e.message } });
      send(req, res, 500, { error: { code: 'internal', message: errorMessage(e) } });
    });
  }) as Server & { runStep: (instruction?: string) => Promise<StepResult> };
  server.runStep = runStep;
  return server;
}
