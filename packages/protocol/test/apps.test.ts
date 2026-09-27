// Helpers the companion / agent build on: vault derivation (vs @metamask/smart-accounts-kit 2.0.0), Delegation /
// permission context / redeemDelegations encoding (vs the kit), EIP-712 typed data (vs viem), EIP-55, key ids, the
// Ripar ABIs (vs contracts/src/interfaces/*.sol), deployments JSON, the AUTO budget / escalation predictor, nonces.
import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { ERC1967Proxy as ERC1967ProxyBytecode } from '@metamask/delegation-abis/bytecode';
import { DelegationManager as DelegationManagerAbi } from '@metamask/delegation-abis';
import { Implementation, getSmartAccountsEnvironment } from '@metamask/smart-accounts-kit';
import {
  encodeDelegations as kitEncodeDelegations,
  encodeSingleExecution as kitEncodeSingleExecution,
  getCounterfactualAccountData,
  hashDelegation as kitHashDelegation,
} from '@metamask/smart-accounts-kit/utils';
import {
  type Abi,
  type AbiParameter,
  encodeAbiParameters,
  encodeFunctionData,
  getAddress,
  hashTypedData,
  keccak256 as viemKeccak,
  toHex as viemToHex,
} from 'viem';
import { describe, expect, it } from 'vitest';
import {
  type Delegation,
  DELEGATION_MANAGER,
  DELEGATION_MANAGER_ABI,
  ERC1967_PROXY_CREATION_CODE,
  ERC8004_IDENTITY_ABI,
  HYBRID_DELEGATOR_IMPL,
  CosignNonceTracker,
  PULSE_COSIGN_ENFORCER_ABI,
  RIPAR_DEVICE_REGISTRY_ABI,
  RIPAR_REPUTATION_RELAY_ABI,
  RIPAR_SENTINEL_ABI,
  SIMPLE_FACTORY,
  ENTRY_POINT_V07,
  autoPathDecision,
  computeAutoBudget,
  computeVaultAddress,
  decodePermissionContext,
  encodePermissionContext,
  encodePulseTerms,
  encodeRedeemDelegations,
  encodeSingleExecution,
  erc20Approve,
  erc20Transfer,
  erc20TransferFrom,
  hashDelegation,
  isValidAddress,
  keyIdOf,
  pairFieldsFromDeployment,
  parseAddress,
  parseDeployment,
  randomCosignNonce,
  toChecksumAddress,
  typedDataDelegation,
  mandateDigest,
  vaultFactoryData,
  vaultInitCodeHash,
  withCaveatArgs,
  cosignCaveatArgs,
} from '../src/index.js';
import { DEMO_K1, DEMO_P1, DEMO_VAULT } from './helpers/demo-device.js';
import { INTERFACES, REPO, bytesToHex, hexToBytes } from './helpers/env.js';

const rnd = (n: number, seed: number): `0x${string}` => {
  let x = BigInt(seed) * 0x9e3779b97f4a7c15n + 1n;
  let s = '0x';
  for (let i = 0; i < n; i++) {
    x = (x * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n);
    s += Number(x >> 56n).toString(16).padStart(2, '0');
  }
  return s as `0x${string}`;
};

describe('vault derivation (contracts/.work/vault-derivation.md)', () => {
  it('the verified demo example', () => {
    expect(computeVaultAddress(DEMO_K1)).toBe(DEMO_VAULT);
    expect(vaultInitCodeHash(DEMO_K1)).toBe('0x9694a6959734c65d55361f8f8d333c8534d1e808dbfbb2694fab6c7c8cbd60ce');
  });
  it('the ERC1967Proxy creation code = @metamask/delegation-abis = contracts/.work copy', () => {
    expect(ERC1967_PROXY_CREATION_CODE.toLowerCase()).toBe(ERC1967ProxyBytecode.toLowerCase());
    const work = readFileSync(resolve(REPO, 'contracts/.work/ERC1967Proxy.creation.hex'), 'utf8').trim().toLowerCase();
    expect(ERC1967_PROXY_CREATION_CODE.slice(2)).toBe(work.replace(/^0x/, ''));
    expect(hexToBytes(ERC1967_PROXY_CREATION_CODE).length).toBe(1008);
  });
  it('= smart-accounts-kit getCounterfactualAccountData(Hybrid, [K1, [], [], []], salt 0) on 10143 and 143', async () => {
    for (const chainId of [10143, 143]) {
      const env = getSmartAccountsEnvironment(chainId);
      expect(getAddress(env.SimpleFactory)).toBe(SIMPLE_FACTORY);
      expect(getAddress(env.implementations.HybridDeleGatorImpl!)).toBe(HYBRID_DELEGATOR_IMPL);
      expect(getAddress(env.DelegationManager)).toBe(DELEGATION_MANAGER);
      expect(getAddress(env.EntryPoint)).toBe(ENTRY_POINT_V07);
      for (let i = 0; i < 6; i++) {
        const owner = i === 0 ? DEMO_K1 : getAddress(rnd(20, i + chainId));
        const kit = await getCounterfactualAccountData({
          factory: env.SimpleFactory,
          implementations: env.implementations,
          implementation: Implementation.Hybrid,
          deployParams: [owner, [], [], []],
          deploySalt: '0x',
        });
        expect(computeVaultAddress(owner)).toBe(getAddress(kit.address));
        expect(vaultFactoryData(owner)).toBe(kit.factoryData);
      }
    }
  });
});

describe('Delegation for redeemDelegations (vs smart-accounts-kit)', () => {
  const pulseTerms = encodePulseTerms({
    px: DEMO_P1.slice(0, 66),
    py: '0x' + DEMO_P1.slice(66),
    token: '0xa9012a055bd4e0eDfF8Ce09f960291C09D5322dC',
    perTxAutoCap: 5_000_000,
    periodAutoCap: 20_000_000,
    period: 86400,
    epoch: 3,
    newPayeeNeedsHuman: true,
    sentinel: rnd(20, 7),
  });
  const ENF = getAddress(rnd(20, 8));
  const d: Delegation = {
    delegate: getAddress(rnd(20, 1)),
    delegator: DEMO_VAULT,
    authority: `0x${'ff'.repeat(32)}`,
    caveats: [
      { enforcer: '0x1046bb45C8d673d4ea75321280DB34899413c069', terms: `0x${'00'.repeat(16)}${'00'.repeat(12)}6adfe980`, args: '0x' },
      { enforcer: ENF, terms: bytesToHex(pulseTerms) as `0x${string}`, args: '0x' },
    ],
    salt: 20260927n,
    signature: rnd(65, 3),
  };
  const kitD = (x: Delegation) => ({ ...x, salt: viemToHex(x.salt, { size: 32 }) });
  it('hashDelegation = kit hashDelegation (= EncoderLib)', () => {
    expect(hashDelegation(d)).toBe(kitHashDelegation(kitD(d)));
    // and the DelegationManager digest = viem typed data of the same struct
    expect(bytesToHex(mandateDigest(10143, DELEGATION_MANAGER, d))).toBe(hashTypedData(typedDataDelegation(10143, DELEGATION_MANAGER, d) as never));
  });
  it('permission context = kit encodeDelegations (abi.encode(Delegation[])), round trip', () => {
    const args = cosignCaveatArgs(7n, 1790000000n, rnd(32, 4), rnd(64, 5));
    const withArgs = withCaveatArgs(d, ENF, args);
    expect(withArgs.caveats[1]!.args).toBe(args);
    expect(withArgs.caveats[0]!.args).toBe('0x');
    expect(d.caveats[1]!.args).toBe('0x'); // the original is untouched
    const leaf = { ...withArgs, delegator: getAddress(rnd(20, 9)), authority: hashDelegation(d) };
    for (const chain of [[withArgs], [leaf, withArgs]]) {
      const ctx = encodePermissionContext(chain);
      expect(ctx).toBe(kitEncodeDelegations(chain.map(kitD)));
      expect(decodePermissionContext(ctx)).toEqual(chain);
    }
    expect(() => withCaveatArgs(d, rnd(20, 99), '0x')).toThrow();
  });
  it('single execution = kit encodeSingleExecution; redeemDelegations calldata = the framework ABI', () => {
    const calls = [
      { target: '0xa9012a055bd4e0eDfF8Ce09f960291C09D5322dC', value: 0n, callData: erc20Transfer(rnd(20, 11), 25_000_000n) },
      { target: getAddress(rnd(20, 12)), value: 10n ** 18n, callData: new Uint8Array(0) },
      { target: getAddress(rnd(20, 13)), value: 0n, callData: erc20Approve(rnd(20, 14), (1n << 256n) - 1n) },
      { target: getAddress(rnd(20, 15)), value: 0n, callData: erc20TransferFrom(rnd(20, 16), rnd(20, 17), 1n) },
    ];
    for (const c of calls) {
      expect(encodeSingleExecution(c.target, c.value, c.callData)).toBe(
        kitEncodeSingleExecution({ target: c.target as `0x${string}`, value: c.value, callData: bytesToHex(c.callData) as `0x${string}` }),
      );
    }
    const data = encodeRedeemDelegations(calls.map((c) => ({ delegations: [d], ...c })));
    const want = encodeFunctionData({
      abi: DelegationManagerAbi,
      functionName: 'redeemDelegations',
      args: [
        calls.map(() => kitEncodeDelegations([kitD(d)])),
        calls.map(() => `0x${'00'.repeat(32)}` as `0x${string}`),
        calls.map((c) => encodeSingleExecution(c.target, c.value, c.callData)),
      ],
    });
    expect(data).toBe(want);
  });
});

describe('EIP-55 and key ids', () => {
  it('toChecksumAddress = viem getAddress; strict parsing of user input', () => {
    for (let i = 0; i < 50; i++) {
      const a = rnd(20, 100 + i);
      expect(toChecksumAddress(a)).toBe(getAddress(a));
      expect(isValidAddress(getAddress(a))).toBe(true);
      expect(isValidAddress(a.toLowerCase())).toBe(true);
    }
    const good = '0x753454832754c071704be47915d4DeC6339624Eb';
    expect(parseAddress(good).length).toBe(20);
    expect(() => parseAddress('0x753454832754c071704be47915d4DeC6339624EB')).toThrow(/checksum/);
    expect(isValidAddress('0x1234')).toBe(false);
  });
  it('keyIdOf = keccak256(abi.encode(bytes32 px, bytes32 py))', () => {
    const want = viemKeccak(encodeAbiParameters([{ type: 'bytes32' }, { type: 'bytes32' }], [DEMO_P1.slice(0, 66) as `0x${string}`, ('0x' + DEMO_P1.slice(66)) as `0x${string}`]));
    expect(bytesToHex(keyIdOf(DEMO_P1))).toBe(want);
  });
});

// ------------------------------------------------------------------------------------------------ ABIs vs .sol
function stripComments(s: string): string {
  return s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
}

function solSignatures(file: string): Set<string> {
  const src = stripComments(readFileSync(file, 'utf8'));
  const out = new Set<string>();
  for (const iface of src.matchAll(/interface\s+(\w+)\s*\{([\s\S]*?)\n\}/g)) {
    const body = iface[2]!;
    const structs = new Map<string, string[]>();
    for (const m of body.matchAll(/struct\s+(\w+)\s*\{([^}]*)\}/g)) {
      structs.set(m[1]!, m[2]!.split(';').map((x) => x.trim()).filter(Boolean).map((x) => x.split(/\s+/)[0]!));
    }
    const norm = (t: string): string => {
      const arr = t.endsWith('[]') ? '[]' : '';
      const base = arr ? t.slice(0, -2) : t;
      const st = structs.get(base);
      return (st ? `(${st.map(norm).join(',')})` : base) + arr;
    };
    const params = (p: string, withIndexed = false): string =>
      p
        .split(',')
        .map((x) => x.trim())
        .filter(Boolean)
        .map((x) => {
          const w = x.split(/\s+/);
          return norm(w[0]!) + (withIndexed && w.includes('indexed') ? ' indexed' : '');
        })
        .join(',');
    for (const m of body.matchAll(/function\s+(\w+)\s*\(([^)]*)\)([^;]*);/g)) {
      const ret = /returns\s*\(([^)]*)\)/.exec(m[3]!);
      out.add(`function ${m[1]}(${params(m[2]!)})->(${ret ? params(ret[1]!) : ''})`);
    }
    for (const m of body.matchAll(/event\s+(\w+)\s*\(([^)]*)\)\s*;/g)) out.add(`event ${m[1]}(${params(m[2]!, true)})`);
    for (const m of body.matchAll(/error\s+(\w+)\s*\(([^)]*)\)\s*;/g)) out.add(`error ${m[1]}(${params(m[2]!)})`);
  }
  return out;
}

function abiSignatures(abi: Abi): Set<string> {
  const t = (p: AbiParameter, withIndexed = false): string => {
    const comps = (p as { components?: readonly AbiParameter[] }).components;
    const base = p.type.startsWith('tuple') ? `(${comps!.map((c) => t(c)).join(',')})${p.type.slice(5)}` : p.type;
    return base + (withIndexed && (p as { indexed?: boolean }).indexed ? ' indexed' : '');
  };
  const out = new Set<string>();
  for (const it of abi) {
    if (it.type === 'function') out.add(`function ${it.name}(${it.inputs.map((p) => t(p)).join(',')})->(${it.outputs.map((p) => t(p)).join(',')})`);
    if (it.type === 'event') out.add(`event ${it.name}(${it.inputs.map((p) => t(p, true)).join(',')})`);
    if (it.type === 'error') out.add(`error ${it.name}(${it.inputs.map((p) => t(p)).join(',')})`);
  }
  return out;
}

describe('Ripar ABIs = contracts/src/interfaces/*.sol', () => {
  const cases: [string, Abi][] = [
    ['IPulseCosignEnforcer.sol', PULSE_COSIGN_ENFORCER_ABI],
    ['IRiparDeviceRegistry.sol', RIPAR_DEVICE_REGISTRY_ABI],
    ['IRiparSentinel.sol', RIPAR_SENTINEL_ABI],
    ['IRiparReputationRelay.sol', RIPAR_REPUTATION_RELAY_ABI],
  ];
  it('every interface file is covered', () => {
    const files = readdirSync(INTERFACES).filter((f) => f.endsWith('.sol')).sort();
    expect(files).toEqual(cases.map((c) => c[0]).sort());
  });
  for (const [file, abi] of cases) {
    it(file, () => {
      const sol = solSignatures(resolve(INTERFACES, file));
      expect(sol.size).toBeGreaterThan(8);
      expect([...abiSignatures(abi)].sort()).toEqual([...sol].sort());
    });
  }
  it('external IERC8004Identity subset', () => {
    const sol = solSignatures(resolve(INTERFACES, 'external/IERC8004.sol'));
    for (const s of abiSignatures(ERC8004_IDENTITY_ABI)) expect(sol.has(s), s).toBe(true);
  });
  it('DelegationManager subset = @metamask/delegation-abis', () => {
    const fw = abiSignatures(DelegationManagerAbi as Abi);
    for (const s of abiSignatures(DELEGATION_MANAGER_ABI)) {
      expect([...fw].some((x) => x.replace(/->.*/, '') === s.replace(/->.*/, '')), s).toBe(true);
    }
  });
});

// ------------------------------------------------------------------------------------------------ deployments
describe('deployments JSON (Deploy.s.sol format)', () => {
  const sample = {
    chainId: 10143,
    salt: '0x' + '52'.repeat(32),
    create2Deployer: '0x4e59b44847b379578588920cA78FbF26c0B4956C',
    RiparDeviceRegistry: getAddress(rnd(20, 21)),
    PulseCosignEnforcer: getAddress(rnd(20, 22)),
    RiparSentinel: getAddress(rnd(20, 23)),
    RiparReputationRelay: getAddress(rnd(20, 24)),
    MockUSD: getAddress(rnd(20, 25)),
    creForwarder: getAddress(rnd(20, 26)),
    expectedWorkflowOwner: getAddress(rnd(20, 27)),
    erc8004Identity: '0x8004A818BFB912233c491871b3d84c89A494BD9e',
    delegationManager: DELEGATION_MANAGER,
    erc8004Reputation: '0x8004B663056A597Dffe9eCcC1965A193B7388713',
  };
  it('parses and maps to the pair fields', () => {
    const d = parseDeployment(JSON.stringify(sample), 10143);
    expect(d.enforcer).toBe(sample.PulseCosignEnforcer);
    expect(d.registry).toBe(sample.RiparDeviceRegistry);
    expect(d.chainId).toBe(10143n);
    const f = pairFieldsFromDeployment(d, { vault: computeVaultAddress(DEMO_K1), now: 1790500000 });
    expect(f).toMatchObject({ chainId: 10143n, registry: d.registry, manager: DELEGATION_MANAGER, enforcer: d.enforcer, sentinel: d.sentinel, relay: d.relay, vault: DEMO_VAULT });
  });
  it('refuses wrong chains, bad addresses, a foreign DelegationManager', () => {
    expect(() => parseDeployment(sample, 143)).toThrow(/chainId/);
    expect(() => parseDeployment({ ...sample, PulseCosignEnforcer: '0x' + '00'.repeat(20) })).toThrow(/zero/);
    expect(() => parseDeployment({ ...sample, RiparSentinel: sample.RiparSentinel.toLowerCase().replace('0x', '0X') })).toThrow();
    expect(() => parseDeployment({ ...sample, RiparSentinel: '0x' + sample.RiparSentinel.slice(2, 12).toUpperCase() + sample.RiparSentinel.slice(12).toLowerCase() })).toThrow(/valid address/);
    expect(() => parseDeployment('{nope')).toThrow(/not JSON/);
    expect(() => pairFieldsFromDeployment(parseDeployment({ ...sample, chainId: 31337 }))).toThrow(/chain table/);
    expect(() => pairFieldsFromDeployment(parseDeployment({ ...sample, delegationManager: getAddress(rnd(20, 30)) }))).toThrow(/DelegationManager/);
  });
});

// ------------------------------------------------------------------------------------------------ AUTO budget
describe('AUTO budget and escalation (SPEC v1.2 AUTO path order)', () => {
  const TOKEN = '0xa9012a055bd4e0eDfF8Ce09f960291C09D5322dC';
  const PAYEE = getAddress(rnd(20, 40));
  const terms = encodePulseTerms({
    px: DEMO_P1.slice(0, 66),
    py: '0x' + DEMO_P1.slice(66),
    token: TOKEN,
    perTxAutoCap: 5_000_000,
    periodAutoCap: 20_000_000,
    period: 86400,
    epoch: 0,
    newPayeeNeedsHuman: true,
    sentinel: rnd(20, 41),
  });
  const T0 = 1_790_000_000n;
  const st = (over: Partial<Parameters<typeof autoPathDecision>[2]> = {}) => ({ payeeKnown: true, laneOpen: true, stored: { spent: 0n, start: 0n }, now: T0, ...over });
  const transfer = (amount: bigint, target = TOKEN, value = 0n) => ({ target, value, callData: erc20Transfer(PAYEE, amount) });
  it('computeAutoBudget mirrors the view (nothing spent, spent, rolled-over window, lifetime cap)', () => {
    expect(computeAutoBudget(terms, { spent: 0, start: 0 }, T0)).toEqual({ spent: 0n, remaining: 20_000_000n, periodStart: 0n, periodEnd: 0n });
    expect(computeAutoBudget(terms, { spent: 7_000_000, start: T0 - 100n }, T0)).toEqual({ spent: 7_000_000n, remaining: 13_000_000n, periodStart: T0 - 100n, periodEnd: T0 - 100n + 86400n });
    // 2.5 periods later: spent 0, window aligned to start + 2 * period
    const start = T0 - 86400n * 2n - 43200n;
    expect(computeAutoBudget(terms, { spent: 19_000_000, start }, T0)).toEqual({ spent: 0n, remaining: 20_000_000n, periodStart: start + 2n * 86400n, periodEnd: start + 3n * 86400n });
    const lifetime = encodePulseTerms({ px: DEMO_P1.slice(0, 66), py: '0x' + DEMO_P1.slice(66), token: TOKEN, perTxAutoCap: 1, periodAutoCap: 5, period: 0, epoch: 0, newPayeeNeedsHuman: false, sentinel: '0x' + '00'.repeat(20) });
    expect(computeAutoBudget(lifetime, { spent: 9, start: 1 }, T0)).toEqual({ spent: 9n, remaining: 0n, periodStart: 1n, periodEnd: 0n });
  });
  it('the decision follows meterable -> lane -> per-tx -> known payee -> period', () => {
    const ok = autoPathDecision(terms, transfer(5_000_000n), st());
    expect(ok.path).toBe('auto');
    if (ok.path === 'auto') expect(ok.budgetAfter).toEqual({ spent: 5_000_000n, remaining: 15_000_000n, periodStart: T0, periodEnd: T0 + 86400n });
    const reason = (x: ReturnType<typeof autoPathDecision>): string => (x.path === 'human' ? x.reason : 'auto');
    expect(reason(autoPathDecision(terms, { target: TOKEN, value: 0n, callData: erc20Approve(PAYEE, 1n) }, st()))).toBe('not-meterable');
    expect(reason(autoPathDecision(terms, { target: TOKEN, value: 0n, callData: erc20TransferFrom(rnd(20, 42), PAYEE, 1n) }, st()))).toBe('not-meterable');
    expect(reason(autoPathDecision(terms, transfer(1n, getAddress(rnd(20, 43))), st()))).toBe('not-meterable');
    expect(reason(autoPathDecision(terms, transfer(1n, TOKEN, 1n), st()))).toBe('not-meterable');
    expect(reason(autoPathDecision(terms, { target: PAYEE, value: 1n, callData: '0x' }, st()))).toBe('not-meterable');
    // lane closed is checked before the caps (even an over-cap payment reports lane-closed)
    expect(reason(autoPathDecision(terms, transfer(9_000_000n), st({ laneOpen: false })))).toBe('lane-closed');
    expect(reason(autoPathDecision(terms, transfer(5_000_001n), st({ payeeKnown: false })))).toBe('per-tx-cap');
    expect(reason(autoPathDecision(terms, transfer(1n), st({ payeeKnown: false })))).toBe('new-payee');
    expect(reason(autoPathDecision(terms, transfer(5_000_000n), st({ stored: { spent: 15_000_001n, start: T0 - 10n } })))).toBe('period-cap');
    // after the window elapsed the same spend is AUTO again
    expect(reason(autoPathDecision(terms, transfer(5_000_000n), st({ stored: { spent: 20_000_000n, start: T0 - 86400n } })))).toBe('auto');
    // native terms: only a native send with value > 0
    const native = encodePulseTerms({ px: DEMO_P1.slice(0, 66), py: '0x' + DEMO_P1.slice(66), token: '0x' + '00'.repeat(20), perTxAutoCap: 10n ** 18n, periodAutoCap: 10n ** 19n, period: 3600, epoch: 0, newPayeeNeedsHuman: false, sentinel: '0x' + '00'.repeat(20) });
    expect(reason(autoPathDecision(native, { target: PAYEE, value: 10n ** 17n, callData: '0x' }, st({ laneOpen: false })))).toBe('auto');
    expect(reason(autoPathDecision(native, { target: PAYEE, value: 0n, callData: '0x' }, st()))).toBe('not-meterable');
    expect(reason(autoPathDecision(native, transfer(1n), st()))).toBe('not-meterable');
  });
});

describe('co-sign nonces (v1.2: single use per mandate)', () => {
  it('random, non-zero, 64-bit by default, never repeated by the tracker', async () => {
    const seen = new Set<bigint>();
    for (let i = 0; i < 2000; i++) {
      const n = randomCosignNonce();
      expect(n > 0n && n < 1n << 64n).toBe(true);
      seen.add(n);
    }
    expect(seen.size).toBe(2000);
    expect(randomCosignNonce(32) < 1n << 256n).toBe(true);
    expect(() => randomCosignNonce(33)).toThrow();
    const tr = new CosignNonceTracker(1); // 1-byte nonces: 255 values, forces the uniqueness path
    const dh = '0x' + 'ab'.repeat(32);
    const got = new Set<bigint>();
    for (let i = 0; i < 255; i++) got.add(tr.next(dh));
    expect(got.size).toBe(255);
    expect(tr.has(dh.toUpperCase().replace('0X', '0x'), [...got][0]!)).toBe(true);
    const t2 = new CosignNonceTracker(1);
    const used = new Set<bigint>(Array.from({ length: 250 }, (_, i) => BigInt(i + 1)));
    const n = await t2.nextUnused(dh, async (x) => used.has(x));
    expect(n > 250n).toBe(true);
  });
});
