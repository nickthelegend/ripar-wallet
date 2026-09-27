// Ported from companion/src/lib/agent.ts.
// HTTP client of the agent service (agent/, `npm start -w @ripar/agent`). The agent is an UNTRUSTED courier like this
// companion: everything it sends is validated here, and the device checks it again before it signs anything.
//
// The agent's API (agent/src/server.ts):
//   GET  /health                   -> { ok, agent: <address>, mandate, config: { chainId, agentId, ... } }
//   GET  /escalations              -> { escalations: Escalation[] }  (each with the prebuilt ripar-cosign-req)
//   GET  /events                   -> Server-Sent Events: `event: escalation`, `data: {at, ...escalation}`
//   POST /mandate                  <- { request: <ripar-mandate-req UR>, signature: <eth-signature UR>, agentId?, label? }
//   POST /escalations/:id/cosign   <- { ur: <the device's ripar-cosign> }  -> the agent redeems on the HUMAN path
//   POST /escalations/:id/deny     <- { ur: <the device's ripar-deny>, note?, attestTx? } (the agent verifies the
//                                     device's signature; posted at once, and again with attestTx after the relay)
//   POST /run                      <- {}  -> one planner step: { summary, actions, ... }
// Errors come back as { error: { code, message } }. With AGENT_API_TOKEN set, every request (GET too) carries a bearer
// token; the event stream, which cannot send headers, carries it as ?token=.
// A simpler escalation shape ({ call, note, claims, risk } without a prebuilt request) is accepted too: the companion
// then builds the co-sign request itself.
import { type EscalationReason, isValidAddress, toChecksumAddress } from '@ripar/protocol';
import { type JsonRecord, ShapeError, clipField, hexField, isRecord, strField, stringifyJson, uintField } from './json';

type Address = `0x${string}`;
type Hex = `0x${string}`;

const REASONS: readonly string[] = [
  'not-meterable',
  'lane-closed',
  'per-tx-cap',
  'new-payee',
  'period-cap',
  'payee-redirect',
  'chain-human-required',
  'chain-lane-closed',
];

export type EscalationWhy = EscalationReason | 'payee-redirect' | 'chain-human-required' | 'chain-lane-closed' | 'other';

export interface AgentHealth {
  ok: boolean;
  agent: { address: Address; agentId: bigint | null } | null;
  chainId: number | null;
  /** the mandate the agent holds, if any */
  mandate: { delegationHash: Hex; status: string } | null;
}

/** a payment the agent cannot make on the AUTO path, waiting for the device */
export interface Escalation {
  id: string;
  status: string;
  /** unix seconds */
  createdAt: number | null;
  reason: EscalationWhy;
  reasonText: string | null;
  chainId: bigint;
  enforcer: Address;
  delegationHash: Hex;
  delegator: Address;
  redeemer: Address;
  call: { target: Address; value: bigint; callData: Hex };
  agentId: bigint | null;
  /** the agent's explanation (the device shows it as "AI says ... (companion)") */
  note: string | null;
  /** what the agent claims the call does (the device checks it against its own decode) */
  claims: { to: Address; token: Address; amount: bigint } | null;
  risk: { src: string; category: string; label: string; ageDays: bigint } | null;
  /** the agent's prebuilt ripar-cosign-req (the agent verifies the device's answer against exactly this request) */
  request: { ur: string; reqId: Hex } | null;
  /** hashStruct(HumanApproval) with presence 0, as the agent computed it */
  requestHash: Hex | null;
  display: { payee: Address | null; amount: string | null; symbol: string | null; vendor: string | null; memo: string | null } | null;
}

/** POST /mandate: the device's own request and answer, so the agent verifies K1's signature itself */
export interface AgentMandate {
  request: string;
  signature: string;
  agentId?: string;
  label?: string;
}

export interface CosignAnswer {
  /** the device's ripar-cosign response (the agent parses and verifies it) */
  ur: string;
  reqId: Hex;
  nonce: string;
  expiry: string;
  presenceHash: Hex;
  r: Hex;
  s: Hex;
  /** abi.encode(nonce, expiry, presenceHash, r, s): the pulse caveat's args for redeemDelegations (HUMAN path) */
  caveatArgs: Hex;
  approvalDigest: Hex | null;
  emulator: boolean;
}

export interface DenyAnswer {
  /** the device's ripar-deny response */
  ur: string;
  requestHash: Hex;
  agentId: string;
  presenceHash: Hex;
  attestTx: Hex | null;
  emulator: boolean;
}

function addr(o: JsonRecord, k: string): Address {
  const v = o[k];
  if (typeof v !== 'string' || !isValidAddress(v)) throw new ShapeError(`${k}: not an address`);
  return toChecksumAddress(v);
}

function optAddr(o: JsonRecord, k: string): Address | null {
  return typeof o[k] === 'string' && isValidAddress(o[k] as string) ? toChecksumAddress(o[k] as string) : null;
}

function parseClaims(x: unknown): Escalation['claims'] {
  if (!isRecord(x)) return null;
  return {
    to: addr(x, 'to'),
    token: x.token == null ? toChecksumAddress(`0x${'00'.repeat(20)}`) : addr(x, 'token'),
    amount: uintField(x, 'amount')!,
  };
}

function parseRisk(x: unknown): Escalation['risk'] {
  if (!isRecord(x)) return null;
  return {
    src: strField(x, 'src', true, 40) ?? '',
    category: strField(x, 'category', true, 40) ?? '',
    label: strField(x, 'label', true, 64) ?? '',
    ageDays: uintField(x, 'ageDays', true) ?? 0n,
  };
}

function seconds(v: unknown): number | null {
  if (typeof v !== 'number' || !Number.isFinite(v) || v <= 0) return null;
  return v > 1e12 ? Math.floor(v / 1000) : v; // the agent stamps milliseconds
}

const RESERVED_IDS = new Set(['__proto__', 'constructor', 'prototype']);

/** POST /run: what one planner step did */
export interface RunResult {
  summary: string;
  planner: string | null;
  error: string | null;
  actions: number;
}

/** strict parse of one escalation from the agent (throws ShapeError) */
export function parseEscalation(x: unknown): Escalation {
  if (!isRecord(x)) throw new ShapeError('escalation: not an object');
  const id = strField(x, 'id', false, 128)!;
  if (!/^[A-Za-z0-9_.:-]{1,128}$/.test(id)) throw new ShapeError('id: only [A-Za-z0-9_.:-] allowed');
  // ids key the companion's records: never a name Object.prototype already has
  if (RESERVED_IDS.has(id) || id in Object.prototype) throw new ShapeError(`id: "${id}" is reserved`);
  const reasonRaw = typeof x.reason === 'string' ? x.reason : 'other';
  const reason = (REASONS.includes(reasonRaw) ? reasonRaw : 'other') as EscalationWhy;
  const status = strField(x, 'status', true, 40) ?? 'pending';
  const createdAt = seconds(x.createdAt);
  const reasonText = clipField(x, 'reasonText', 300) ?? null;

  // the agent's format: `cosign` (the request fields) + `request` (the same request, prebuilt) + `execution`
  if (isRecord(x.cosign)) {
    const c = x.cosign;
    const ai = isRecord(c.ai) ? c.ai : null;
    let request: Escalation['request'] = null;
    if (isRecord(x.request)) {
      const ur = strField(x.request, 'ur', false, 4000)!;
      if (!/^ur:ripar-cosign-req\//i.test(ur)) throw new ShapeError('request.ur: not a ripar-cosign-req UR');
      request = { ur, reqId: hexField(x.request, 'reqId', 16) };
    }
    const d = isRecord(x.display) ? x.display : null;
    return {
      id,
      status,
      createdAt,
      reason,
      reasonText,
      chainId: uintField(c, 'chainId')!,
      enforcer: addr(c, 'enforcer'),
      delegationHash: hexField(c, 'delegationHash', 32),
      delegator: addr(c, 'delegator'),
      redeemer: addr(c, 'redeemer'),
      call: { target: addr(c, 'target'), value: uintField(c, 'value', true) ?? 0n, callData: hexField(c, 'calldata') },
      agentId: uintField(x, 'agentId', true) ?? null,
      note: ai ? (strField(ai, 'text', true, 400) ?? null) : null,
      claims: ai ? parseClaims(ai.claims) : null,
      risk: parseRisk(c.risk),
      request,
      requestHash: typeof x.requestHash === 'string' ? hexField(x, 'requestHash', 32) : null,
      // display-only agent data: clipped, never a reason to drop the escalation (an injected invoice memo is long,
      // and it is exactly what the user must see next to the device's review)
      display: d
        ? {
            payee: optAddr(d, 'payee'),
            amount: clipField(d, 'amount', 80) ?? null,
            symbol: clipField(d, 'symbol', 20) ?? null,
            vendor: clipField(d, 'vendor', 80) ?? null,
            memo: clipField(d, 'memo', 1000) ?? null,
          }
        : null,
    };
  }

  // the simple format: the EscalationRequest of @ripar/protocol plus display data
  const call = x.call;
  if (!isRecord(call)) throw new ShapeError('call: missing');
  return {
    id,
    status,
    createdAt,
    reason,
    reasonText,
    chainId: uintField(x, 'chainId')!,
    enforcer: addr(x, 'enforcer'),
    delegationHash: hexField(x, 'delegationHash', 32),
    delegator: addr(x, 'delegator'),
    redeemer: addr(x, 'redeemer'),
    call: { target: addr(call, 'target'), value: uintField(call, 'value', true) ?? 0n, callData: hexField(call, 'callData') },
    agentId: uintField(x, 'agentId', true) ?? null,
    note: strField(x, 'note', true, 400) ?? null,
    claims: parseClaims(x.claims),
    risk: parseRisk(x.risk),
    request: null,
    requestHash: null,
    display: null,
  };
}

/** parses a list; malformed entries are returned separately (shown as rejected, never acted on) */
export function parseEscalations(body: unknown): { items: Escalation[]; rejected: { raw: unknown; error: string }[] } {
  const arr = Array.isArray(body) ? body : isRecord(body) && Array.isArray(body.escalations) ? body.escalations : null;
  if (!arr) throw new ShapeError('expected { escalations: [...] }');
  const items: Escalation[] = [];
  const rejected: { raw: unknown; error: string }[] = [];
  for (const raw of arr.slice(0, 200)) {
    try {
      items.push(parseEscalation(raw));
    } catch (e) {
      rejected.push({ raw, error: (e as Error).message });
    }
  }
  return { items, rejected };
}

export class AgentError extends Error {
  override name = 'AgentError';
}

function errorOf(body: unknown, status: number): string {
  if (isRecord(body)) {
    if (typeof body.error === 'string') return body.error;
    if (isRecord(body.error) && typeof body.error.message === 'string') {
      return typeof body.error.code === 'string' ? `${body.error.message} (${body.error.code})` : body.error.message;
    }
  }
  return `HTTP ${status}`;
}

/** the client for the configured agent (URL + optional API token) */
export function agentClientOf(s: { agentUrl: string; agentToken?: string }): AgentClient {
  return new AgentClient(s.agentUrl, undefined, s.agentToken?.trim() || null);
}

export class AgentClient {
  constructor(
    readonly baseUrl: string,
    private readonly fetchImpl: typeof fetch = (...a) => globalThis.fetch(...a),
    private readonly token: string | null = null,
  ) {}

  private url(path: string): string {
    return this.baseUrl.replace(/\/+$/, '') + path;
  }

  private async json(path: string, init?: RequestInit): Promise<unknown> {
    let res: Response;
    try {
      res = await this.fetchImpl(this.url(path), {
        ...init,
        headers: {
          accept: 'application/json',
          ...(init?.body ? { 'content-type': 'application/json' } : {}),
          ...(this.token ? { authorization: `Bearer ${this.token}` } : {}),
        },
      });
    } catch (e) {
      throw new AgentError(`agent unreachable at ${this.baseUrl} (${(e as Error).message}). Is it running, and reachable from this phone (a LAN address, or 127.0.0.1 after adb reverse tcp:8787 tcp:8787)?`);
    }
    const text = await res.text();
    let body: unknown = null;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      throw new AgentError(`agent ${path}: HTTP ${res.status}, not JSON`);
    }
    if (!res.ok) throw new AgentError(`agent ${path}: ${errorOf(body, res.status)}`);
    return body;
  }

  async health(): Promise<AgentHealth> {
    const b = await this.json('/health');
    if (!isRecord(b)) throw new AgentError('agent /health: not an object');
    const cfg = isRecord(b.config) ? b.config : {};
    let agent: AgentHealth['agent'] = null;
    const idOf = (o: JsonRecord): bigint | null => {
      try {
        return uintField(o, 'agentId', true) ?? null;
      } catch {
        return null;
      }
    };
    if (typeof b.agent === 'string' && isValidAddress(b.agent)) {
      agent = { address: toChecksumAddress(b.agent), agentId: idOf(cfg) };
    } else if (isRecord(b.agent) && typeof b.agent.address === 'string' && isValidAddress(b.agent.address)) {
      agent = { address: toChecksumAddress(b.agent.address), agentId: idOf(b.agent) ?? idOf(cfg) };
    }
    const chainId = typeof cfg.chainId === 'number' ? cfg.chainId : typeof b.chainId === 'number' ? b.chainId : null;
    let mandate: AgentHealth['mandate'] = null;
    if (isRecord(b.mandate) && typeof b.mandate.delegationHash === 'string' && /^0x[0-9a-fA-F]{64}$/.test(b.mandate.delegationHash)) {
      mandate = { delegationHash: b.mandate.delegationHash as Hex, status: typeof b.mandate.status === 'string' ? b.mandate.status : '' };
    }
    return { ok: b.ok !== false, agent, chainId, mandate };
  }

  async postMandate(m: AgentMandate): Promise<void> {
    await this.json('/mandate', { method: 'POST', body: stringifyJson(m) });
  }

  async escalations(): Promise<ReturnType<typeof parseEscalations>> {
    return parseEscalations(await this.json('/escalations'));
  }

  /** hands the device's co-sign to the agent, which verifies it against its request and redeems */
  async postCosign(id: string, a: CosignAnswer): Promise<{ txHash: Hex | null }> {
    const b = await this.json(`/escalations/${encodeURIComponent(id)}/cosign`, { method: 'POST', body: stringifyJson({ ur: a.ur }) });
    let tx: unknown = null;
    if (isRecord(b)) {
      tx = b.txHash;
      if (isRecord(b.payment)) tx = b.payment.txHash;
      else if (isRecord(b.escalation) && isRecord(b.escalation.result)) tx = b.escalation.result.txHash;
    }
    return { txHash: typeof tx === 'string' && /^0x[0-9a-fA-F]{64}$/.test(tx) ? (tx as Hex) : null };
  }

  /**
   * Hands the device's signed deny to the agent (it verifies the P-256 signature and the request hash itself): once at
   * once, "relay pending", and again with the attestDenial transaction once it is relayed. Idempotent on the agent.
   */
  async postDeny(id: string, a: DenyAnswer): Promise<void> {
    const note = a.attestTx ? `denial relayed on-chain: ${a.attestTx}` : 'denied on the device; on-chain relay pending';
    await this.json(`/escalations/${encodeURIComponent(id)}/deny`, {
      method: 'POST',
      body: stringifyJson({ ur: a.ur, note, ...(a.attestTx ? { attestTx: a.attestTx } : {}) }),
    });
  }

  /** asks the agent to run one planner step now (POST /run): due invoices are paid or escalated to this inbox */
  async run(): Promise<RunResult> {
    const b = await this.json('/run', { method: 'POST', body: '{}' });
    if (!isRecord(b)) throw new AgentError('agent /run: not an object');
    return {
      summary: clipField(b, 'summary', 400) ?? '(no summary)',
      planner: clipField(b, 'planner', 60) ?? null,
      error: clipField(b, 'error', 400) ?? null,
      actions: Array.isArray(b.actions) ? b.actions.length : 0,
    };
  }

  /**
   * The agent's event stream (GET /events): calls back for every escalation event. Returns a closer. EventSource
   * cannot send headers, so an API token travels as ?token= (the agent accepts it there for /events only).
   */
  stream(onEscalation: (e: Escalation) => void, onError: (msg: string) => void): () => void {
    if (typeof EventSource === 'undefined') return () => {};
    const es = new EventSource(this.url(this.token ? `/events?token=${encodeURIComponent(this.token)}` : '/events'));
    const handle = (ev: MessageEvent) => {
      try {
        onEscalation(parseEscalation(JSON.parse(String(ev.data))));
      } catch (e) {
        onError(`rejected a streamed escalation: ${(e as Error).message}`);
      }
    };
    es.addEventListener('escalation', handle as EventListener);
    es.onerror = () => {
      onError('event stream closed; polling instead');
      es.close();
    };
    return () => es.close();
  }
}
