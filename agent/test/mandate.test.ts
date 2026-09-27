// POST /mandate validation: what the agent accepts and every refusal.
import { describe, expect, it } from 'vitest';
import {
  ANY_DELEGATE,
  DELEGATION_MANAGER,
  MM_ENFORCERS,
  SECP256K1_N,
  buildRequest,
  cborEncode,
  hashDelegation,
  mandateDigest,
  toHex,
  urSingle,
  type CborValue,
  type Delegation,
} from '@ripar/protocol';
import { keccak256, type Hex } from 'viem';
import { ApiError } from '../src/errors.js';
import { MandateError, mandateFromInput, validateMandate } from '../src/mandate.js';
import { DEP, ENFORCER, MUSD, SENTINEL, makeFixture } from './helpers/fixture.js';
import { delegationJson, newSoftDevice, signMandate } from './helpers/soft-device.js';

const f = makeFixture();
const ctx = { agent: f.agent, chainId: 10143, deployment: f.config.deployment };

function resign(d: Delegation, signer = f.dev): Delegation {
  const c = { ...d, signature: '0x' as Hex };
  c.signature = toHex(signer.signK1(mandateDigest(10143, DELEGATION_MANAGER, c)));
  return c;
}

function refused(d: Delegation | Record<string, unknown>, re: RegExp): void {
  let err: unknown;
  try {
    const { delegation, request } = mandateFromInput({ delegation: 'delegate' in d && typeof d.salt === 'bigint' ? delegationJson(d as Delegation) : d }, 10143);
    validateMandate(delegation, ctx, request);
  } catch (e) {
    err = e;
  }
  expect(err, `expected a refusal matching ${re}`).toBeInstanceOf(MandateError);
  expect((err as Error).message).toMatch(re);
}

describe('mandate validation', () => {
  it('accepts the device-signed delegation (JSON form)', () => {
    const { delegation } = mandateFromInput({ delegation: delegationJson(f.mandate) }, 10143);
    const v = validateMandate(delegation, ctx);
    expect(v.delegationHash).toBe(hashDelegation(f.mandate));
    expect(v.owner).toBe(f.dev.k1);
    expect(v.vault).toBe(f.dev.vault);
    expect(v.pulse.enforcer).toBe(ENFORCER);
    expect(v.pulse.sentinel).toBe(SENTINEL);
    expect(v.warnings).toEqual([]);
    expect(v.source).toBe('delegation');
  });

  it('accepts the device QR pair: ripar-mandate-req + eth-signature (UR), agentId from the request', () => {
    const req = buildRequest('mandate', {
      chainId: 10143,
      manager: DELEGATION_MANAGER,
      delegate: f.agent,
      delegator: f.dev.vault,
      salt: 1,
      agentId: 42,
      label: 'treasury agent',
      caveats: f.mandate.caveats.map((c) => ({ enforcer: c.enforcer, terms: c.terms })),
    });
    const sig = f.dev.signK1(mandateDigest(10143, DELEGATION_MANAGER, { ...f.mandate }));
    const ethSig = urSingle('eth-signature', cborEncode(new Map<number, CborValue>([[1, Buffer.from(req.reqId.slice(2), 'hex')], [2, sig]])));
    const { delegation, request } = mandateFromInput({ request: req.ur, signature: ethSig }, 10143);
    const v = validateMandate(delegation, ctx, request);
    expect(v.delegationHash).toBe(hashDelegation(f.mandate));
    expect(v.agentId).toBe('42');
    expect(v.label).toBe('treasury agent');
    expect(v.source).toBe('device-qr');
    // the multipart parts work too, and a raw 65-byte hex signature
    const again = mandateFromInput({ request: req.parts.join(' '), signature: toHex(sig) }, 10143);
    expect(hashDelegation(again.delegation)).toBe(v.delegationHash);
    // wrong chain
    expect(() => mandateFromInput({ request: req.ur, signature: ethSig }, 143)).toThrow(/chain/);
  });

  it('refuses a delegation to another delegate or to ANY_DELEGATE', () => {
    refused(resign({ ...f.mandate, delegate: newSoftDevice().k1 }), /not this agent/);
    refused(resign({ ...f.mandate, delegate: ANY_DELEGATE }), /ANY_DELEGATE/);
  });

  it('refuses a non-root authority', () => {
    refused(resign({ ...f.mandate, authority: `0x${'11'.repeat(32)}` }), /ROOT_AUTHORITY/);
  });

  it('requires exactly one PulseCosignEnforcer caveat', () => {
    refused(resign({ ...f.mandate, caveats: [{ enforcer: MM_ENFORCERS.LimitedCallsEnforcer, terms: toHex(new Uint8Array(32)), args: '0x' }] }), /exactly one PulseCosignEnforcer/);
    refused(resign({ ...f.mandate, caveats: [f.mandate.caveats[0]!, f.mandate.caveats[0]!] }), /exactly one PulseCosignEnforcer.*found 2/);
  });

  it('refuses caveats the device cannot decode (unknown enforcer, bad lengths)', () => {
    const extra = { enforcer: MM_ENFORCERS.NonceEnforcer, terms: toHex(new Uint8Array(32)), args: '0x' as Hex };
    refused(resign({ ...f.mandate, caveats: [...f.mandate.caveats, extra] }), /cannot decode/);
    const short = { ...f.mandate.caveats[0]!, terms: f.mandate.caveats[0]!.terms.slice(0, -2) as Hex };
    refused(resign({ ...f.mandate, caveats: [short] }), /cannot decode/);
  });

  it('refuses insane pulse terms: perTx above the period cap, a foreign sentinel', () => {
    const m1 = signMandate(f.dev, { chainId: 10143, agent: f.agent, pulse: { enforcer: ENFORCER, token: MUSD, perTxAutoCap: 30n, periodAutoCap: 20n, period: 86400, sentinel: SENTINEL } });
    refused(m1, /perTxAutoCap is above periodAutoCap/);
    const m2 = signMandate(f.dev, { chainId: 10143, agent: f.agent, pulse: { enforcer: ENFORCER, token: MUSD, perTxAutoCap: 1n, periodAutoCap: 2n, period: 86400, sentinel: DEP.RiparDeviceRegistry } });
    refused(m2, /sentinel/);
  });

  it('warns about weak but valid terms', () => {
    const m = signMandate(f.dev, {
      chainId: 10143,
      agent: f.agent,
      pulse: { enforcer: ENFORCER, token: MUSD, perTxAutoCap: 0n, periodAutoCap: 0n, period: 0, newPayeeNeedsHuman: false, sentinel: '0x0000000000000000000000000000000000000000' },
    });
    const v = validateMandate(mandateFromInput({ delegation: delegationJson(m) }, 10143).delegation, ctx);
    expect(v.warnings.join(' | ')).toMatch(/no sentinel.*newPayeeNeedsHuman.*periodAutoCap is 0/);
  });

  it('refuses missing / malformed / high-s signatures', () => {
    refused({ ...delegationJson(f.mandate), signature: '0x' }, /signature: missing/);
    refused({ ...delegationJson(f.mandate), signature: '0x1234' }, /65 bytes/);
    const sig = Buffer.from(f.mandate.signature.slice(2), 'hex');
    const s = BigInt('0x' + sig.subarray(32, 64).toString('hex'));
    const hi = Buffer.from((SECP256K1_N - s).toString(16).padStart(64, '0'), 'hex');
    const twin = Buffer.concat([sig.subarray(0, 32), hi, Buffer.from([sig[64] === 27 ? 28 : 27])]);
    refused({ ...delegationJson(f.mandate), signature: toHex(twin) }, /high-s/);
    const badV = Buffer.from(sig);
    badV[64] = 29;
    refused({ ...delegationJson(f.mandate), signature: toHex(badV) }, /v must be 27 or 28/);
  });

  it('refuses a delegator that is not the canonical vault of the signer', () => {
    // signed by another K1 for this vault
    refused(resign(f.mandate, newSoftDevice()), /not the canonical Ripar vault/);
    // a vault that is not the canonical counterfactual
    const other = newSoftDevice();
    refused(resign({ ...f.mandate, delegator: other.vault }), /not the canonical Ripar vault/);
  });

  it('refuses non-empty args and bad JSON shapes', () => {
    const j = delegationJson(f.mandate) as { caveats: { args: string }[] };
    j.caveats[0]!.args = '0x01';
    refused(j, /args: must be empty/);
    expect(() => mandateFromInput({} as never, 10143)).toThrow(MandateError);
    expect(() => mandateFromInput({ delegation: { ...delegationJson(f.mandate), salt: -1 } }, 10143)).toThrow(/salt/);
  });

  it('service: refuses a mandate whose vault owner on chain differs, or one the device revoked', async () => {
    const g = makeFixture();
    g.chain.owners.set(g.dev.vault.toLowerCase(), newSoftDevice().k1);
    await expect(g.svc.acceptMandate({ delegation: delegationJson(g.mandate) })).rejects.toThrow(/vault's owner/);
    const h = makeFixture();
    h.chain.revoked.add(`${keccak256(h.dev.p1Key)}:${hashDelegation(h.mandate)}`.toLowerCase());
    await expect(h.svc.acceptMandate({ delegation: delegationJson(h.mandate) })).rejects.toThrow(/revoked/);
    const k = makeFixture();
    k.chain.owners.clear();
    const m = await k.svc.acceptMandate({ delegation: delegationJson(k.mandate), agentId: 5 });
    expect(m.warnings.join()).toMatch(/not deployed/);
    expect(m.agentId).toBe('5');
    await expect(k.svc.acceptMandate({ delegation: delegationJson(k.mandate), agentId: 'x' as never })).rejects.toBeInstanceOf(ApiError);
  });
});
