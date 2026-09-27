// Differential tests against firmware/tools/make_request.py:
//  1. the `build --json` CLI (spawned per request, fixed --reqid) vs buildRequest(): type, req-id, CBOR, UR, parts;
//  2. an in-process corpus (test/py/oracle.py corpus: make_request's own varied generators _mk_cosign / _mk_mandate /
//     _mk_deny, pair variants, the Privy allow-list documents) -> identical CBOR, identical read_fields facts (token
//     table, ERC-20 decode, AI match, request hash, digests), identical demo-device responses, and parseResponse()
//     reaching the same checks as make_request parse_response;
//  3. TS-built requests and TS demo-device responses fed back to `make_request.py simulate` / `parse` (exit 0).
import { describe, expect, it } from 'vitest';
import {
  type RequestKind,
  REQ_TYPES,
  aiMatches,
  buildRequest,
  caveatDump,
  cborDecode,
  cborEncode,
  cosignRequestHash,
  decodeErc20,
  decodeRequest,
  firmwareRefusal,
  delegationHash,
  formatUnitsDevice,
  keccak256,
  parseResponse,
  privyDump,
  privyParse,
  canonicalJson,
  parseStrictJson,
  readRequest,
  toHex,
  tokenCheck,
  urParts,
  urRead,
  urSingle,
} from '../src/index.js';
import { simulate, simulateDenyFromCosign, DEMO_K1, DEMO_P1, DEMO_VAULT } from './helpers/demo-device.js';
import { bytesToHex, hexToBytes, makeRequest, oracle } from './helpers/env.js';

// ------------------------------------------------------------------------------------------------ 1. build CLI
const RID = (n: number): string => n.toString(16).padStart(2, '0').repeat(16);
const DM = '0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3';
const AUSD = '0xa9012a055bd4e0eDfF8Ce09f960291C09D5322dC';
const MUSD = '0xB5b7eaffbF9bf68cbcC1Ce8B5850b2ea9d6f9a2a';
// firmware v1.2 compiled-in contracts (typed from docs/PROTOCOL.md 4, independently of src/constants.ts)
const REG = '0xA08a47c9d645926615CF04D69b7a048133F68c9f';
const ENF = '0x64d61fe5438981DC803ED61250FEf024617ae7eE';
const RELAY = '0xE433dCA75CA6cd730b1006F51A26208B000eA9E2';
const VAULT = DEMO_VAULT;
const P1 = DEMO_P1.slice(2);
const ad = (n: number): string => '0x' + n.toString(16).padStart(2, '0').repeat(20);

interface CliSpec {
  kind: RequestKind;
  fields: Record<string, unknown>;
  reqid: string;
  uuidTag?: boolean;
  frag?: number;
  extra?: number;
  noNow?: boolean;
}

// firmware v1.2: mostly the compiled-in contracts and the demo device's derived vault (the demo devices answer them);
// RID(1) (pair), RID(8) (cosign) and RID(20) (mandate) name other contracts / vaults: both demo devices refuse them
const CLI_SPECS: CliSpec[] = [
  { kind: 'pair', reqid: RID(1), fields: { chainId: 10143, registry: ad(1), manager: DM, enforcer: ad(2), sentinel: ad(3), relay: ad(4), vault: ad(5), now: 1790500000 } },
  { kind: 'pair', reqid: RID(2), fields: { chainId: 143, registry: REG }, noNow: true, uuidTag: true },
  { kind: 'pair', reqid: RID(3), fields: { chainId: 10143, registry: REG, enforcer: ENF, now: 1099511627775, minEpoch: '9223372036854775807', reopenNonce: 0 }, frag: 30, extra: 4 },
  { kind: 'cosign', reqid: RID(4), fields: { chainId: 10143, enforcer: ENF, delegationHash: '0x' + '22'.repeat(32), delegator: VAULT, redeemer: ad(6), target: AUSD, value: 0, nonce: 7, expiry: 1790000000, transfer: { to: ad(8), amount: 25000000 }, decimals: 6, symbol: 'AUSD' } },
  { kind: 'cosign', reqid: RID(5), fields: { chainId: 10143, delegationHash: '0x' + '22'.repeat(32), delegator: VAULT, redeemer: ad(6), target: ad(8), value: '1500000000000000000', nonce: '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', expiry: 1790000000, ai: { text: 'send\tMON\nnow', claims: { to: ad(8), amount: '1500000000000000000' } } } },
  { kind: 'cosign', reqid: RID(6), fields: { chainId: 10143, enforcer: ENF, delegationHash: '0x' + '33'.repeat(32), delegator: VAULT, redeemer: ad(6), target: AUSD, nonce: 1, expiry: 1790000000, approve: { spender: ad(9), amount: '115792089237316195423570985008687907853269984665640564039457584007913129639935' }, risk: { src: 'Nansen', category: 'Exchange', label: 'Binance 14', ageDays: 1234 }, budgetLeft: 0 }, uuidTag: true, frag: 50 },
  { kind: 'cosign', reqid: RID(7), fields: { chainId: 10143, enforcer: ENF, delegationHash: '0x' + '44'.repeat(32), delegator: VAULT, redeemer: ad(6), target: MUSD, nonce: 2, expiry: 1790000000, transferFrom: { from: ad(5), to: ad(10), amount: 1 }, ai: { text: '€'.repeat(40) + 'é' }, risk: { label: 'x' }, decimals: 6, symbol: 'mUSD' } },
  { kind: 'cosign', reqid: RID(8), fields: { chainId: 10143, enforcer: ad(2), delegationHash: '0x' + '55'.repeat(32), delegator: ad(5), redeemer: ad(6), target: ad(11), nonce: 3, expiry: 1790000000, calldata: '0xdeadbeef00', symbol: 'S'.repeat(16), decimals: 255 }, extra: 6 },
  { kind: 'mandate', reqid: RID(9), fields: { chainId: 10143, manager: DM, delegate: ad(6), delegator: VAULT, salt: 1, agentId: 42, label: 'demo agent', caveats: [{ kind: 'pulse', p1Key: P1, token: MUSD, perTxAutoCap: 5000000, periodAutoCap: 20000000, period: 86400, epoch: 0, newPayeeNeedsHuman: true, sentinel: ad(3) }] }, frag: 60 },
  { kind: 'mandate', reqid: RID(10), fields: { chainId: 143, manager: DM, delegate: ad(6), delegator: VAULT, salt: '0x' + 'ab'.repeat(32), caveats: [
    { kind: 'timestamp', after: 1790380800, before: 1792972800 },
    { kind: 'erc20TransferAmount', token: AUSD, amount: 500000000 },
    { kind: 'erc20PeriodTransfer', token: AUSD, amount: 50000000, duration: 86400, start: 1790380800 },
    { kind: 'nativeTokenTransferAmount', amount: '1000000000000000000' },
    { kind: 'valueLte', amount: 0 },
    { kind: 'limitedCalls', amount: 100 },
    { kind: 'allowedTargets', addresses: [AUSD, ad(12)] },
    { kind: 'redeemer', addresses: [ad(6)] },
    { kind: 'pulse', enforcer: ENF, px: '0x' + P1.slice(0, 64), py: '0x' + P1.slice(64), perTxAutoCap: 1, periodAutoCap: 2, period: 0, newPayeeNeedsHuman: false },
    { enforcer: ad(13), terms: '0x0102' },
    [ad(14), '0x'],
    { kind: 'limitedCalls', enforcer: ad(15), amount: 3 },
  ] } },
  { kind: 'mandate', reqid: RID(11), fields: { chainId: 10143, manager: DM, delegate: ad(6), delegator: VAULT, salt: 0, authority: '0x' + '00'.repeat(32), caveats: [[ad(1), '0x' + 'ff'.repeat(300)]] }, uuidTag: true, extra: 3 },
  { kind: 'deny', reqid: RID(12), fields: { chainId: 10143, relay: RELAY, agentId: 42, requestHash: '0x' + '77'.repeat(32) } },
  { kind: 'deny', reqid: RID(13), fields: { chainId: '18446744073709551615', relay: ad(4), agentId: '18446744073709551615', requestHash: '0x' + '00'.repeat(32) }, uuidTag: true },
  { kind: 'privy', reqid: RID(14), fields: { json: { version: 1, method: 'PATCH', url: 'https://api.privy.io/v1/wallets/wl8yz4c2rq0q1cdz2q8a4', body: { additional_signers: [{ signer_id: 'kq7ks9z3n1v2lq4d7w0p8m3y', override_policy_ids: ['pol9x2'] }] }, headers: { 'privy-app-id': 'cm0appid1234' } } } },
  { kind: 'privy', reqid: RID(15), fields: { json: { z: 'é"\\/\u0001\u001f\t\n', a: [true, false, null, -7, 0], m: { b: {}, a: [] }, 'é': 1, 'Z': 2, '_': 3 } }, frag: 20 },
  { kind: 'privy', reqid: RID(16), fields: { json: ' {"version":1} ' } },
  // the compiled-in defaults left out: registry (pair), relay (deny); the co-sign enforcer is left out in RID(5), the pulse
  // caveat enforcer in RID(9); a manager the firmware does not pin (RID(20), refused by both demo devices)
  { kind: 'pair', reqid: RID(17), fields: { chainId: 10143, now: 1790500000 } },
  { kind: 'pair', reqid: RID(18), fields: { chainId: 143, sentinel: ad(3), vault: VAULT }, noNow: true },
  { kind: 'deny', reqid: RID(19), fields: { chainId: 143, agentId: 7, requestHash: '0x' + '78'.repeat(32) } },
  { kind: 'mandate', reqid: RID(20), fields: { chainId: 10143, manager: ad(1), delegate: ad(6), delegator: VAULT, salt: 5, caveats: [[ENF, '0x']] } },
];

function cliArgs(s: CliSpec): string[] {
  const a = ['build', s.kind, JSON.stringify(s.fields), '--reqid', s.reqid, '--json'];
  if (s.uuidTag) a.push('--uuid-tag');
  if (s.frag) a.push('--frag', String(s.frag));
  if (s.extra) a.push('--extra', String(s.extra));
  if (s.noNow) a.push('--no-now');
  return a;
}

describe('make_request.py build --json vs buildRequest()', () => {
  for (const [i, s] of CLI_SPECS.entries()) {
    it(`#${i} ${s.kind}${s.uuidTag ? ' uuid-tag' : ''}${s.frag ? ' frag ' + s.frag : ''}${s.extra ? ' extra ' + s.extra : ''}`, () => {
      const p = makeRequest(cliArgs(s));
      expect(p.status, p.stderr).toBe(0);
      const py = JSON.parse(p.stdout) as { type: string; reqId: string; cbor: string; ur: string; parts: string[] };
      const ts = buildRequest(s.kind, { ...s.fields, reqId: s.reqid, uuidTag: s.uuidTag } as never, {
        frag: s.frag,
        extra: s.extra,
        noNow: s.noNow,
      });
      expect(ts.type).toBe(py.type);
      expect(ts.reqId).toBe('0x' + py.reqId);
      expect(bytesToHex(ts.cbor)).toBe('0x' + py.cbor);
      expect(ts.ur).toBe(py.ur);
      expect(ts.parts).toEqual(py.parts);
    });
  }
  it('builder refusals match (both refuse)', () => {
    const bad: CliSpec[] = [
      { kind: 'cosign', reqid: RID(1), fields: { chainId: 10143, enforcer: ad(2), delegationHash: '0x' + '22'.repeat(32), delegator: ad(5), redeemer: ad(6), target: AUSD, nonce: 1, expiry: 1, transfer: { to: ad(8), amount: 1 }, calldata: '0x' } },
      { kind: 'cosign', reqid: RID(1), fields: { chainId: 10143, enforcer: ad(2), delegationHash: '0x' + '22'.repeat(32), delegator: ad(5), redeemer: ad(6), target: AUSD, nonce: 1, expiry: 1, symbol: 'AUSD\n' } },
      { kind: 'cosign', reqid: RID(1), fields: { chainId: 10143, enforcer: ad(2), delegationHash: '0x' + '22'.repeat(31), delegator: ad(5), redeemer: ad(6), target: AUSD, nonce: 1, expiry: 1 } },
      { kind: 'cosign', reqid: RID(1), fields: { chainId: 10143, enforcer: ad(2), delegationHash: '0x' + '22'.repeat(32), delegator: ad(5), redeemer: ad(6), target: AUSD, expiry: 1 } },
      { kind: 'mandate', reqid: RID(1), fields: { chainId: 10143, manager: DM, delegate: ad(6), delegator: ad(5), salt: 1, label: 'x'.repeat(65), caveats: [] } },
      // no PulseCosignEnforcer compiled in for chain 1: the pulse caveat needs `enforcer` there
      { kind: 'mandate', reqid: RID(1), fields: { chainId: 1, manager: DM, delegate: ad(6), delegator: ad(5), salt: 1, caveats: [{ kind: 'pulse', p1Key: P1, perTxAutoCap: 1, periodAutoCap: 1, period: 1 }] } },
      // nothing compiled in for chain 1: registry / enforcer / relay are required there
      { kind: 'pair', reqid: RID(1), fields: { chainId: 1 }, noNow: true },
      { kind: 'cosign', reqid: RID(1), fields: { chainId: 1, delegationHash: '0x' + '22'.repeat(32), delegator: ad(5), redeemer: ad(6), target: AUSD, nonce: 1, expiry: 1 } },
      { kind: 'deny', reqid: RID(1), fields: { chainId: 1, agentId: 1, requestHash: '0x' + '77'.repeat(32) } },
      { kind: 'mandate', reqid: RID(1), fields: { chainId: 10143, manager: DM, delegate: ad(6), delegator: ad(5), salt: 1, caveats: [{ kind: 'pulse', enforcer: ad(2), p1Key: P1, perTxAutoCap: '340282366920938463463374607431768211456', periodAutoCap: 1, period: 1 }] } },
      { kind: 'mandate', reqid: RID(1), fields: { chainId: 10143, manager: DM, delegate: ad(6), delegator: ad(5), salt: 1, caveats: [{ kind: 'timestamp', before: '340282366920938463463374607431768211456' }] } },
      { kind: 'pair', reqid: RID(1), fields: { chainId: 10143, registry: ad(1), minEpoch: '9223372036854775808' }, noNow: true },
      { kind: 'pair', reqid: RID(1), fields: { chainId: 10143, registry: '0x1234' }, noNow: true },
      { kind: 'deny', reqid: RID(1), fields: { chainId: 10143, relay: ad(4), agentId: 1 } },
      { kind: 'cosign', reqid: '00', fields: { chainId: 10143, enforcer: ad(2), delegationHash: '0x' + '22'.repeat(32), delegator: ad(5), redeemer: ad(6), target: AUSD, nonce: 1, expiry: 1 } },
    ];
    for (const s of bad) {
      const p = makeRequest(cliArgs(s));
      expect(p.status, JSON.stringify(s)).not.toBe(0);
      expect(() => buildRequest(s.kind, { ...s.fields, reqId: s.reqid } as never, { noNow: s.noNow }), JSON.stringify(s)).toThrow();
    }
  });
});

// ------------------------------------------------------------------------------------------------ 2. corpus
interface Report {
  fields: Record<string, unknown>;
  checks: [string, boolean][];
  unverified: string[];
  ok: boolean;
}
interface Entry {
  kind: RequestKind;
  note: string;
  fields: Record<string, unknown>;
  cbor: string;
  ur: string;
  parts: string[];
  parts40x3: string[];
  ev12: string;
  salt16: string;
  guessKind: RequestKind;
  tokenCheck?: [boolean, number, string] | { error: string };
  erc20?: { kind: string; num: number; from: string; to: string; amount: number | string };
  aiMatches?: boolean;
  requestHash?: string;
  callDataHash?: string;
  presenceHash?: string;
  digest?: string;
  delegationHash?: string;
  ctx?: { pulse: string; vault: string; sentinel: string; minEpoch: number };
  dumps?: (string | null)[];
  simulateError?: string;
  response?: string;
  responseUr?: string;
  report?: Report;
}
interface Corpus {
  entries: Entry[];
  denyFromCosign: { cosign: string; relay: string; agentId: number | string; salt16: string; response: string; responseUr: string; report: Report }[];
  deviceInitiated: { type: string; chainId: number | string; contract: string; cbor: string; ur: string; report: Report }[];
  p1: string;
  k1: string;
}

const CORPUS = oracle<Corpus>('corpus', { seed: 20260927 });

/** oracle field JSON -> builder input (privy json bytes stay bytes) */
function tsFields(e: Entry): Record<string, unknown> {
  if (e.kind === 'privy') return { ...e.fields, json: hexToBytes(e.fields.json as string) };
  return e.fields;
}

function compareReport(ts: ReturnType<typeof parseResponse>, py: Report): void {
  expect(ts.checks.map((c) => [c.name, c.ok])).toEqual(py.checks);
  expect(ts.ok).toBe(py.ok);
  expect(ts.unverified.length).toBe(py.unverified.length);
  const f = ts.fields as unknown as Record<string, unknown>;
  for (const k of ['digest', 'presenceHash', 'caveatArgs', 'delegationHash', 'bindDigest', 'requestHash', 'rsv', 'rs', 'salt16', 'evidence12', 'der']) {
    if (py.fields[k] === undefined) continue;
    const want = String(py.fields[k]);
    expect(String(f[k]).replace(/^0x/, ''), k).toBe(want.replace(/^0x/, ''));
  }
  if (py.fields.p1Key) expect(String(f.p1Key).slice(2)).toBe(py.fields.p1Key);
  if (py.fields.k1Address) expect(f.k1Address).toBe(py.fields.k1Address);
  if (py.fields.firmwareId) expect(String(f.firmwareId).slice(2)).toBe(py.fields.firmwareId);
  if (py.fields.signer) expect(f.signer).toBe(py.fields.signer);
  if (py.fields.agentId !== undefined) expect(String(f.agentId)).toBe(String(py.fields.agentId));
  if (py.fields.minEpoch !== undefined) expect(String(f.minEpoch)).toBe(String(py.fields.minEpoch));
  if (py.fields.nonce !== undefined) expect(String(f.nonce)).toBe(String(py.fields.nonce));
  if (py.fields.vault) expect(f.vault).toBe(py.fields.vault);
  if (py.fields.evidence) {
    const ev = py.fields.evidence as Record<string, number>;
    expect(f.evidence).toEqual({
      version: ev.version,
      bpm: ev.bpm,
      beats: ev.beats,
      irDC: ev.irDC,
      redDC: ev.redDC,
      jitterX1000: ev.jitter_x1000,
      durationMs: ev.duration_ms,
    });
  }
}

describe('corpus from make_request generators (oracle corpus)', () => {
  it('covers every request kind', () => {
    const kinds = new Set(CORPUS.entries.map((e) => e.kind));
    expect([...kinds].sort()).toEqual(['cosign', 'deny', 'mandate', 'pair', 'privy']);
    expect(CORPUS.entries.length).toBeGreaterThanOrEqual(40);
    expect(CORPUS.k1.toLowerCase()).toBe(DEMO_K1.toLowerCase());
    expect(CORPUS.p1).toBe(DEMO_P1);
  });
  for (const e of CORPUS.entries) {
    describe(e.note, () => {
      const built = buildRequest(e.kind, tsFields(e) as never, { noNow: true });
      it('identical CBOR, UR and multipart parts (70 bytes; 40 bytes + 3 mixed)', () => {
        expect(bytesToHex(built.cbor)).toBe(e.cbor);
        expect(built.ur).toBe(e.ur);
        expect(built.parts).toEqual(e.parts);
        expect(urParts(REQ_TYPES[e.kind], built.cbor, 40, 3)).toEqual(e.parts40x3);
        expect(bytesToHex(cborEncode(cborDecode(built.cbor)))).toBe(e.cbor);
        const rr = readRequest(built.parts.join('\n'));
        expect(rr.kind).toBe(e.kind);
        expect(bytesToHex(rr.cbor)).toBe(e.cbor);
        expect(readRequest(e.cbor).kind).toBe(e.guessKind); // guess_kind of bare CBOR hex (same quirks as make_request)
      });
      it('same read_fields facts and digests', () => {
        const q = decodeRequest(e.kind, built.cbor);
        if (q.kind === 'cosign') {
          let tc: unknown;
          try {
            const r = tokenCheck(q);
            tc = [r.listed, r.decimals, r.symbol];
          } catch (err) {
            tc = { error: (err as Error).message };
          }
          if (Array.isArray(e.tokenCheck)) expect(tc).toEqual(e.tokenCheck);
          else expect(tc).toHaveProperty('error');
          const d = decodeErc20(q.calldata);
          expect(d.kind).toBe(e.erc20!.kind);
          expect(toHex(d.from)).toBe(e.erc20!.from);
          expect(toHex(d.to)).toBe(e.erc20!.to);
          expect(String(d.amount)).toBe(String(e.erc20!.amount));
          expect(aiMatches(q)).toBe(e.aiMatches);
          expect(toHex(cosignRequestHash(q))).toBe(e.requestHash);
          expect(toHex(keccak256(q.calldata))).toBe(e.callDataHash);
        }
        if (q.kind === 'mandate') {
          expect(toHex(delegationHash(q))).toBe(e.delegationHash);
          if (e.dumps) {
            const dumps = q.caveats.map((c) => caveatDump(q.chainId, c.enforcer, c.terms, q.chainId, e.ctx!.pulse));
            expect(dumps).toEqual(e.dumps);
          }
        }
      });
      if (e.simulateError) {
        it('the demo device refuses it too', () => {
          expect(() => simulate(e.kind, built.cbor, { ev12: hexToBytes(e.ev12), salt16: hexToBytes(e.salt16) })).toThrow();
          // firmware v1.2 refusals (compiled-in contracts, derived vault): the same text as make_request firmware_refusal
          if (e.simulateError!.startsWith('device refuses: ')) {
            const q = decodeRequest(e.kind, built.cbor);
            expect('device refuses: ' + firmwareRefusal(q, CORPUS.k1)).toBe(e.simulateError);
          }
        });
        return;
      }
      it('identical demo-device response; parseResponse reaches the same checks', () => {
        const fwid = e.kind === 'pair' ? (cborDecode(hexToBytes(e.response!)) as Map<bigint, Uint8Array>).get(6n) : undefined;
        const resp = simulate(e.kind, built.cbor, { ev12: hexToBytes(e.ev12), salt16: hexToBytes(e.salt16), fwid });
        expect(bytesToHex(resp)).toBe(e.response);
        const rep = parseResponse(e.responseUr!, { request: built, p1Key: CORPUS.p1, k1Address: CORPUS.k1 });
        expect(rep.result).toBe('VERIFIED');
        compareReport(rep, e.report!);
        if (e.digest) expect((rep.fields as { digest?: string; bindDigest?: string }).digest ?? (rep.fields as { bindDigest?: string }).bindDigest).toBe(e.digest);
      });
    });
  }
  it('deny from co-sign reviews', () => {
    for (const d of CORPUS.denyFromCosign) {
      const resp = simulateDenyFromCosign(hexToBytes(d.cosign), 10143n, hexToBytes(d.relay), BigInt(d.agentId), hexToBytes(d.salt16));
      expect(bytesToHex(resp)).toBe(d.response);
      const rep = parseResponse(d.responseUr, { request: { kind: 'cosign', cbor: hexToBytes(d.cosign) }, p1Key: CORPUS.p1, contract: d.relay });
      expect(rep.result).toBe('VERIFIED');
      compareReport(rep, d.report);
    }
  });
  it('device-initiated revoke / panic / reopen', () => {
    for (const d of CORPUS.deviceInitiated) {
      const rep = parseResponse(d.ur, { chainId: d.chainId, contract: d.contract, p1Key: CORPUS.p1 });
      expect(rep.type).toBe(d.type);
      expect(rep.result).toBe('VERIFIED');
      compareReport(rep, d.report);
    }
  });
});

// ------------------------------------------------------------------------------------------------ 3. round trip
describe('TS-built requests through make_request.py simulate + parse', () => {
  const specs = CLI_SPECS;
  it('python simulate answers every TS request; TS verifies it; python verifies TS demo responses', () => {
    const items = specs.map((s) => {
      const b = buildRequest(s.kind, { ...s.fields, reqId: s.reqid, uuidTag: s.uuidTag } as never, { noNow: s.noNow });
      return { s, b };
    });
    const sims = oracle<({ response: string; ur: string } | { error: string })[]>(
      'simulate',
      items.map(({ s, b }) => ({ kind: s.kind, cbor: bytesToHex(b.cbor), salt16: '0x' + '5a'.repeat(16) })),
    );
    const toParse: unknown[] = [];
    items.forEach(({ s, b }, i) => {
      const sim = sims[i]!;
      if ('error' in sim) {
        // the demo device refuses exactly what the TS demo device refuses (token table, Privy allow-list)
        expect(() => simulate(s.kind, b.cbor, { salt16: hexToBytes('5a'.repeat(16)) })).toThrow();
        return;
      }
      const ts = simulate(s.kind, b.cbor, { salt16: hexToBytes('5a'.repeat(16)) });
      expect(bytesToHex(ts)).toBe(sim.response);
      // the pair request of a TS build via its multipart parts, answered by Python, verified by TS
      const rep = parseResponse(sim.ur, { request: b.parts.join(' '), p1Key: DEMO_P1, k1Address: DEMO_K1 });
      expect(rep.result, s.kind + ' ' + JSON.stringify(rep.checks)).toBe('VERIFIED');
      toParse.push({ response: urSingle(rep.type, ts), req: { kind: s.kind, cbor: bytesToHex(b.cbor) }, p1: DEMO_P1, k1: DEMO_K1 });
    });
    expect(toParse.length).toBeGreaterThan(8);
    const pyReports = oracle<(Report | { error: string })[]>('parse', toParse);
    for (const r of pyReports) {
      expect(r).not.toHaveProperty('error');
      expect((r as Report).ok).toBe(true);
      expect((r as Report).unverified).toEqual([]);
    }
  });
  it('`make_request.py parse` CLI exits 0 on a TS request + TS demo response', () => {
    const b = buildRequest('cosign', { ...(CLI_SPECS[3]!.fields as object), reqId: RID(3) } as never);
    const resp = urSingle('ripar-cosign', simulate('cosign', b.cbor, { salt16: hexToBytes('11'.repeat(16)) }));
    const ok = makeRequest(['parse', resp, '--req', b.ur, '--p1', DEMO_P1]);
    expect(ok.status, ok.stdout + ok.stderr).toBe(0);
    expect(JSON.parse(ok.stdout).result).toBe('VERIFIED');
    // and exit 1 for a tampered one (flip one bit of s)
    const m = cborDecode(hexToBytes(bytesToHex(simulate('cosign', b.cbor, { salt16: hexToBytes('11'.repeat(16)) })))) as Map<bigint, Uint8Array>;
    const rs = Uint8Array.from(m.get(2n)!);
    rs[40]! ^= 1;
    m.set(2n, rs);
    const bad = makeRequest(['parse', urSingle('ripar-cosign', cborEncode(m)), '--req', b.ur, '--p1', DEMO_P1]);
    expect(bad.status).toBe(1);
    expect(parseResponse(urSingle('ripar-cosign', cborEncode(m)), { request: b, p1Key: DEMO_P1 }).result).toBe('FAIL');
  });
});

// ------------------------------------------------------------------------------------------------ Privy / JSON / misc
describe('Privy allow-list and strict JSON vs make_request', () => {
  const objs = [
    { b: 1, a: 'xé\n', c: [true, null, -5] },
    { 'é': 1, e: 2, E: 3, '€': 4, '😀': 5, '～': 6, z: { y: { x: [[[]]] } } },
    { s: '\u0000\u0008\u000b\u001f"\\/\u007f ' },
  ];
  const P = oracle<{
    valid: { name: string; json: string; dump: string; path: string; kind: string }[];
    invalid: { name: string; json: string; syntax: boolean }[];
    jsonValid: string[];
    jsonInvalid: string[];
    canonical: { obj: unknown; bytes: string }[];
  }>('privy', objs);
  it('every allow-listed document parses to the same view (privy_dump)', () => {
    for (const v of P.valid) {
      const view = privyParse(hexToBytes(v.json));
      expect(privyDump(view), v.name).toBe(v.dump);
      expect(view.path).toBe(v.path);
      expect(view.kind).toBe(v.kind);
    }
  });
  it(`every refused document is refused (${P.invalid.length})`, () => {
    for (const v of P.invalid) {
      expect(() => privyParse(hexToBytes(v.json)), v.name).toThrow();
      expect(parseStrictJson(hexToBytes(v.json)) === null, v.name).toBe(v.syntax);
    }
  });
  it('strict JSON syntax vectors', () => {
    for (const j of [...P.jsonValid, ...P.valid.map((v) => v.json)]) expect(parseStrictJson(hexToBytes(j)), j).not.toBeNull();
    for (const j of P.jsonInvalid) expect(parseStrictJson(hexToBytes(j)), j).toBeNull();
  });
  it('canonical JSON = json.dumps(sort_keys, compact, ensure_ascii=False)', () => {
    expect(P.canonical.length).toBe(objs.length);
    P.canonical.forEach((c, i) => expect(bytesToHex(canonicalJson(objs[i])), JSON.stringify(c.obj)).toBe(c.bytes));
  });
});

describe('device formatting and caveat decode vs make_request', () => {
  it('format_units', () => {
    const cases: [bigint, number, number][] = [
      [0n, 18, 6], [12500000n, 6, 6], [1n, 6, 6], [1234500000n, 6, 6], [1n, 18, 6], [10n ** 18n, 18, 6],
      [1234567n, 6, 2], [1500000n, 6, 0], [1000000n, 6, 0], [123456789n, 0, 6], [1000n, 0, 6], [999n, 0, 6],
      [(1n << 256n) - 1n, 18, 6], [(1n << 256n) - 1n, 0, 0], [10n ** 30n + 7n, 6, 4], [5n, 1, 0],
    ];
    const py = oracle<string[]>('format_units', cases.map(([v, d, m]) => [v.toString(), d, m]));
    cases.forEach(([v, d, m], i) => expect(formatUnitsDevice(v, d, m)).toBe(py[i]));
  });
  it('caveat_dump of malformed / foreign caveats', () => {
    const pulse = '0x' + '22'.repeat(20);
    const w = (x: string): string => x.padStart(64, '0');
    const good = '0x' + P1 + w('00') + w('05') + w('06') + w('0100') + w('03') + w('01') + w('00');
    const cases = [
      { chain: 10143, enforcer: pulse, terms: good, pulseChain: 10143, pulseEnforcer: pulse },
      { chain: 10143, enforcer: pulse, terms: good.slice(0, -2), pulseChain: 10143, pulseEnforcer: pulse },
      { chain: 10143, enforcer: pulse, terms: good.slice(0, -2) + '02', pulseChain: 10143, pulseEnforcer: pulse },
      { chain: 10143, enforcer: pulse, terms: good, pulseChain: 143, pulseEnforcer: pulse },
      { chain: 1, enforcer: '0x1046bb45C8d673d4ea75321280DB34899413c069', terms: '0x' + w('01'), pulseChain: 1, pulseEnforcer: pulse },
      { chain: 143, enforcer: '0x1046bb45C8d673d4ea75321280DB34899413c069', terms: '0x' + w('01'), pulseChain: 1, pulseEnforcer: pulse },
      { chain: 10143, enforcer: '0xf100b0819427117EcF76Ed94B358B1A5b5C6D2Fc', terms: '0x' + '00'.repeat(52), pulseChain: 10143, pulseEnforcer: pulse },
      { chain: 10143, enforcer: '0x474e3Ae7E169e940607cC624Da8A15Eb120139aB', terms: '0x' + '11'.repeat(20) + w('05') + w('00') + w('07'), pulseChain: 10143, pulseEnforcer: pulse },
      { chain: 10143, enforcer: '0x7F20f61b1f09b08D970938F6fa563634d65c4EeB', terms: '0x' + '11'.repeat(20 * 17), pulseChain: 10143, pulseEnforcer: pulse },
      { chain: 10143, enforcer: '0xE144b0b2618071B4E56f746313528a669c7E65c5', terms: '0x' + '11'.repeat(20 * 16), pulseChain: 10143, pulseEnforcer: pulse },
      { chain: 10143, enforcer: '0xDE4f2FAC4B3D87A1d9953Ca5FC09FCa7F366254f', terms: '0x' + w('00'), pulseChain: 10143, pulseEnforcer: pulse },
      { chain: 10143, enforcer: '0x' + '00'.repeat(20), terms: '0x', pulseChain: 10143, pulseEnforcer: '0x' + '00'.repeat(20) },
    ];
    const py = oracle<(string | null)[]>('caveat_dump', cases);
    cases.forEach((c, i) => expect(caveatDump(c.chain, c.enforcer, c.terms, c.pulseChain, c.pulseEnforcer)).toBe(py[i]));
  });
});
