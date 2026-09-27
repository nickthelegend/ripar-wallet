// Integration: a local anvil fork of Monad testnet (chain 10143), the Ripar contracts deployed to it by `forge script`
// from a private copy of contracts/, the canonical vault of an EMULATED device (firmware WASM emulator, test mode,
// random seed) deployed through the canonical SimpleFactory and funded from the MockUSD faucet, the agent registered in
// the (forked) ERC-8004 IdentityRegistry, a mandate signed on the emulator, and the agent service driven over HTTP:
//   new payee -> escalation -> emulator co-sign -> HUMAN redemption (+ attestApproval), replay rejected,
//   AUTO payment to the now-approved payee, a prompt-injected redirect revealed on the device and denied there.
// Skips cleanly when the fork cannot start (no anvil, no network). Every transaction goes to the local anvil only,
// from keys generated here. Anvil is killed afterwards.
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  DELEGATION_MANAGER,
  PULSE_COSIGN_ENFORCER_ABI,
  RIPAR_DEVICE_REGISTRY_ABI,
  RIPAR_REPUTATION_RELAY_ABI,
  SIMPLE_FACTORY,
  ERC173_OWNER_ABI,
  buildRequest,
  computeVaultAddress,
  cosignCaveatArgs,
  erc20Transfer,
  pairFieldsFromDeployment,
  parseDeployment,
  parseResponse,
  toChecksumAddress,
  toHex,
  vaultFactoryData,
  verifyPairing,
  type DeviceIdentity,
  type RiparDeployment,
} from '@ripar/protocol';
import { createPublicClient, createWalletClient, encodeFunctionData, erc20Abi, http, parseAbi, type Address, type Hex, type PublicClient, type WalletClient } from 'viem';
import { generatePrivateKey, privateKeyToAccount, privateKeyToAddress } from 'viem/accounts';
import { createApp, type AgentApp } from '../src/app.js';
import { ViemChain } from '../src/chain.js';
import { loadConfig } from '../src/config.js';
import { ChainRevertError } from '../src/errors.js';
import { delegationOf } from '../src/mandate.js';
import { LocalKeySigner, chainFor } from '../src/signer.js';
import type { Escalation } from '../src/types.js';
import { defaultAgentURI, registerAgent } from '../scripts/register-erc8004.js';
import { deployRipar, preparePrivateContracts, startForkedAnvil, type Anvil } from './helpers/anvil.js';
import { Device, createEmulator } from './helpers/emu.js';

const ORIGIN = 'http://localhost:5173';
const CLOUDNEST = '0xFc8Eb32DF5BD4B08E6326a3118a94f55BeCBE7e9' as Address;
const LABELWORKS = '0x6A25dF78B9c4C7022cF1A7F04a0110747Cab6e82' as Address;
const ATTACKER = '0x069ef010B46a838FeCD98ADD1E60a407Ef6E575a' as Address;
const WORK = process.env.RIPAR_WORK_DIR ?? (existsSync('F:/tmp') ? 'F:/tmp/agent-svc' : join(tmpdir(), 'ripar-agent-svc'));
const MUSD_FAUCET_ABI = parseAbi(['function faucet(address to, uint256 amount)']);

let skip: string | null = null;
let anvil: Anvil | null = null;
let dep: RiparDeployment;
let depPath: string;
let pc: PublicClient;
let companion: WalletClient;
let dev: Device;
let device: DeviceIdentity;
let vault: Address;
let agentKey: Hex;
let agent: Address;
let agentId: bigint;
let app: AgentApp | null = null;
let url: string;
let dh: Hex;
let dataDir: string | null = null;

async function rpc(method: string, params: unknown[]): Promise<unknown> {
  return pc.request({ method: method as never, params: params as never });
}

async function send(to: Address, data: Hex): Promise<void> {
  const hash = await companion.sendTransaction({ to, data, account: companion.account!, chain: companion.chain! });
  const r = await pc.waitForTransactionReceipt({ hash });
  if (r.status !== 'success') throw new Error(`tx to ${to} reverted`);
}

async function api(path: string, body?: unknown): Promise<{ status: number; json: any }> {
  const res = await fetch(url + path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { origin: ORIGIN, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: res.status, json: (await res.json()) as any };
}

async function musd(a: Address): Promise<bigint> {
  return pc.readContract({ address: dep.mockUsd, abi: erc20Abi, functionName: 'balanceOf', args: [a] });
}

async function runStep(): Promise<any> {
  const r = await api('/run', {});
  expect(r.status).toBe(200);
  return r.json;
}

beforeAll(async () => {
  const started = await startForkedAnvil();
  if (!started.anvil) {
    skip = started.reason ?? 'fork unavailable';
    console.warn(`[integration] SKIPPED: ${skip}`);
    return;
  }
  anvil = started.anvil;
  const chain = chainFor(10143, anvil.url);
  pc = createPublicClient({ chain, transport: http(anvil.url) }) as PublicClient;
  const fund = async (a: Address) => rpc('anvil_setBalance', [a, '0x3635C9ADC5DEA00000']); // 1000 MON

  // 1. the Ripar contracts, deployed by forge from a private copy of contracts/
  const deployerKey = generatePrivateKey();
  await fund(privateKeyToAddress(deployerKey));
  mkdirSync(WORK, { recursive: true });
  const contractsDir = preparePrivateContracts(WORK);
  depPath = deployRipar(contractsDir, anvil.url, deployerKey, privateKeyToAddress(generatePrivateKey()));
  dep = parseDeployment(readFileSync(depPath, 'utf8'), 10143);

  const companionKey = generatePrivateKey();
  companion = createWalletClient({ account: privateKeyToAccount(companionKey), chain, transport: http(anvil.url) });
  await fund(companion.account!.address);
  agentKey = generatePrivateKey();
  agent = privateKeyToAddress(agentKey);
  await fund(agent);

  // 2. the emulated device (random test seed) pairs with the deployment and the canonical vault of its K1
  const seed = toHex(crypto.getRandomValues(new Uint8Array(32)));
  dev = new Device(await createEmulator(seed));
  expect(dev.state().emulator).toBe(true);
  const k1 = toChecksumAddress(dev.state().k1);
  vault = computeVaultAddress(k1);
  const now = Number((await pc.getBlock()).timestamp);
  const pair = buildRequest('pair', pairFieldsFromDeployment(dep, { vault, now }));
  let s = dev.scan(pair.parts);
  expect(s.screen).toBe('review');
  expect(s.review!.ok, s.review!.refusal).toBe(true);
  device = verifyPairing(dev.pulseAndSign(), pair);
  expect(device.emulator).toBe(true); // always labelled EMULATOR
  expect(device.k1Address).toBe(k1);
  dev.home();

  // 3. device registry (BindDevice signatures from the pairing), vault via SimpleFactory, MockUSD faucet
  const ps = device.p1Signature;
  await send(dep.registry, encodeFunctionData({
    abi: RIPAR_DEVICE_REGISTRY_ABI,
    functionName: 'registerDevice',
    args: [k1, device.px, device.py, `0x${ps.slice(2, 66)}`, `0x${ps.slice(66, 130)}`, device.k1Signature],
  }));
  if (!(await pc.getCode({ address: vault }))) await send(SIMPLE_FACTORY, vaultFactoryData(k1));
  expect(await pc.readContract({ address: vault, abi: ERC173_OWNER_ABI, functionName: 'owner' })).toBe(k1);
  await send(dep.mockUsd, encodeFunctionData({ abi: MUSD_FAUCET_ABI, functionName: 'faucet', args: [vault, 1_000_000_000n] }));
  expect(await musd(vault)).toBe(1_000_000_000n);

  // 4. the agent registers itself in the (forked) ERC-8004 IdentityRegistry
  const reg = await registerAgent({
    client: pc,
    signer: new LocalKeySigner(agentKey, chain, http(anvil.url)),
    identity: dep.erc8004Identity,
    agentURI: defaultAgentURI(vault),
    vault,
    keyId: device.keyId,
    broadcast: true,
  });
  agentId = reg.agentId!;
  expect(agentId).toBe(reg.simulatedAgentId);

  // 5. the mandate, signed on the emulator
  const mandate = buildRequest('mandate', {
    chainId: 10143,
    manager: DELEGATION_MANAGER,
    delegate: agent,
    delegator: vault,
    salt: BigInt(now),
    label: 'Ripar treasury agent',
    agentId,
    caveats: [
      {
        kind: 'pulse',
        enforcer: dep.enforcer,
        p1Key: device.p1Key,
        token: dep.mockUsd,
        perTxAutoCap: 5_000_000,
        periodAutoCap: 20_000_000,
        period: 86400,
        epoch: 0,
        newPayeeNeedsHuman: true,
        sentinel: dep.sentinel,
      },
      { kind: 'redeemer', addresses: [agent] },
    ],
  });
  s = dev.scan(mandate.parts);
  expect(s.review!.title).toBe('SIGN MANDATE');
  expect(s.review!.ok, s.review!.refusal).toBe(true);
  const ethSig = dev.pulseAndSign();
  dev.home();

  // 6. the agent service on the fork; the companion hands it the mandate (device QR data)
  dataDir = mkdtempSync(join(WORK, 'agent-int-'));
  const config = loadConfig({
    RPC_URL: anvil.url,
    CHAIN_ID: '10143',
    DEPLOYMENTS: depPath,
    AGENT_PRIVATE_KEY: agentKey,
    DATA_DIR: dataDir,
    HOST: '127.0.0.1',
    PORT: '0',
    AGENT_ID: agentId.toString(),
    COMPANION_ORIGIN: ORIGIN,
  });
  app = await createApp(config);
  url = await app.listen();
  const m = await api('/mandate', { request: mandate.ur, signature: ethSig });
  expect(m.status, JSON.stringify(m.json)).toBe(200);
  expect(m.json.mandate.vault).toBe(vault);
  expect(m.json.mandate.agentId).toBe(agentId.toString());
  dh = m.json.mandate.delegationHash;
}, 900_000);

afterAll(async () => {
  await app?.close();
  try {
    dev?.emu.destroy();
  } catch {
    /* ignore */
  }
  anvil?.stop();
  if (dataDir) rmSync(dataDir, { recursive: true, force: true }); // the agent's data only (never the contracts copy)
});

describe('agent on an anvil fork of Monad testnet with the device emulator', () => {
  let esc1: Escalation;
  let cosignUr: string;

  it('new payee -> escalation -> emulator co-sign -> HUMAN redemption + attestApproval', async (ctx) => {
    if (skip) return ctx.skip();
    const step = await runStep();
    expect(step.summary).toMatch(/sent INV-001 to the human/);
    const list = await api('/escalations');
    esc1 = (await api(`/escalations/${list.json.escalations[0].id}`)).json as Escalation;
    expect(esc1.reason).toBe('new-payee');
    expect(esc1.cosign.expiry - Number((await pc.getBlock()).timestamp)).toBeLessThanOrEqual(3600);

    // the companion shows the agent's prebuilt parts; the device decides
    const s = dev.scan(esc1.request.parts);
    expect(s.review!.title).toBe('CO-SIGN PAYMENT');
    expect(s.review!.ok, s.review!.refusal + '\n' + dev.reviewText()).toBe(true);
    const text = dev.reviewText();
    if (process.env.RIPAR_SHOW_REVIEW) console.log(`--- device review of ${esc1.id}
${text}`);
    expect(text).toContain(CLOUDNEST);
    expect(text).toContain('INV-001');
    cosignUr = dev.pulseAndSign();
    dev.home();

    const before = await musd(CLOUDNEST);
    const r = await api(`/escalations/${esc1.id}/cosign`, { ur: cosignUr });
    expect(r.status, JSON.stringify(r.json)).toBe(200);
    expect(r.json.escalation.status).toBe('executed');
    expect(r.json.payment.path).toBe('human');
    expect((await musd(CLOUDNEST)) - before).toBe(2_500_000n);
    const res = r.json.escalation.result;
    expect(BigInt(res.gasLimit)).toBeGreaterThanOrEqual(BigInt(res.gasUsed));
    const known = await pc.readContract({ address: dep.enforcer, abi: PULSE_COSIGN_ENFORCER_ABI, functionName: 'isKnownPayee', args: [DELEGATION_MANAGER, dh, CLOUDNEST] });
    expect(known).toBe(true);
    const consumed = await pc.readContract({ address: dep.enforcer, abi: PULSE_COSIGN_ENFORCER_ABI, functionName: 'consumed', args: [DELEGATION_MANAGER, res.approvalDigest] });
    expect(consumed).toBe(true);
    // ERC-8004: the redeemer attested its device-co-signed approval through the relay
    expect(res.attest?.error, res.attest?.error).toBeUndefined();
    expect(res.attest.txHash).toMatch(/^0x/);
    const attested = await pc.readContract({ address: dep.relay, abi: RIPAR_REPUTATION_RELAY_ABI, functionName: 'approvalAttested', args: [res.approvalDigest] });
    expect(attested).toBe(true);
  });

  it('replay rejected: by the agent (409) and by the enforcer (CosignReplayed); a forged nonce fails BadCosign', async (ctx) => {
    if (skip) return ctx.skip();
    const again = await api(`/escalations/${esc1.id}/cosign`, { ur: cosignUr });
    expect(again.status).toBe(409);
    const rep = parseResponse(cosignUr);
    if (rep.type !== 'ripar-cosign') throw new Error(rep.type);
    const args = cosignCaveatArgs(BigInt(esc1.cosign.nonce), esc1.cosign.expiry, rep.fields.presenceHash, rep.fields.rs);
    const chain = app!.chain as ViemChain;
    const m = delegationOf(app!.svc.mandate()!);
    const exec = { target: esc1.execution.target, value: 0n, callData: esc1.execution.callData };
    const replay = await chain.redeem(m, exec, args).catch((e: unknown) => e);
    expect(replay).toBeInstanceOf(ChainRevertError);
    expect((replay as ChainRevertError).revert.name).toBe('CosignReplayed');
    expect((replay as ChainRevertError).phase).toBe('estimate');
    // v1.2: the nonce is single-use per mandate, so the same co-sign moved to another call still reads as a replay
    const moved = await chain.redeem(m, { ...exec, callData: toHex(erc20Transfer(CLOUDNEST, 3_000_000n)) }, args).catch((e: unknown) => e);
    expect((moved as ChainRevertError).revert.name).toBe('CosignReplayed');
    // and with a fresh nonce the signature simply does not verify (BadCosign)
    const fresh = cosignCaveatArgs(BigInt(esc1.cosign.nonce) + 1n, esc1.cosign.expiry, rep.fields.presenceHash, rep.fields.rs);
    const bad = await chain.redeem(m, exec, fresh).catch((e: unknown) => e);
    expect((bad as ChainRevertError).revert.name).toBe('BadCosign');
  });

  it('AUTO payment to the approved payee inside the caps; an unknown payee reverts HumanRequired', async (ctx) => {
    if (skip) return ctx.skip();
    await rpc('evm_increaseTime', [61]);
    await rpc('evm_mine', []);
    const before = await musd(CLOUDNEST);
    const step = await runStep();
    expect(step.summary, JSON.stringify(step.actions)).toMatch(/paid INV-001 .*AUTO/);
    expect((await musd(CLOUDNEST)) - before).toBe(2_500_000n);
    const st = (await api('/state')).json;
    expect(st.budget.spent).toBe('2500000');
    expect(st.budget.remaining).toBe('17500000');
    expect(st.laneOpen).toBe(true);
    expect(st.payments.map((p: { path: string }) => p.path)).toEqual(['auto', 'human']);
    // the chain layer decodes the enforcer's custom error when AUTO is not allowed
    const chain = app!.chain as ViemChain;
    const e = await chain
      .redeem(delegationOf(app!.svc.mandate()!), { target: dep.mockUsd, value: 0n, callData: toHex(erc20Transfer(LABELWORKS, 1n)) }, '0x')
      .catch((x: unknown) => x);
    expect((e as ChainRevertError).revert.name).toBe('HumanRequired');
  });

  it('prompt injection: the redirect is escalated, the device review shows the attacker address, the human denies', async (ctx) => {
    if (skip) return ctx.skip();
    const s2 = await runStep(); // INV-002: over the per-tx cap
    expect(s2.summary).toMatch(/INV-002/);
    const s3 = await runStep(); // INV-003: a new vendor
    expect(s3.summary).toMatch(/INV-003/);
    const s4 = await runStep(); // INV-004: the memo's redirect, proposed like an injected model would
    expect(s4.summary).toMatch(/INV-004/);
    const all = (await api('/escalations')).json.escalations as Escalation[];
    const esc4 = all.find((e) => e.invoiceId === 'INV-004')!;
    expect(esc4.reason).toBe('payee-redirect');
    expect(esc4.cosign.ai.claims.to).toBe(CLOUDNEST); // the invoice of record; the calldata pays the attacker
    expect(esc4.display.payee).toBe(ATTACKER);

    const s = dev.scan(esc4.request.parts);
    expect(s.review!.title).toBe('CO-SIGN PAYMENT');
    const text = dev.reviewText();
    if (process.env.RIPAR_SHOW_REVIEW) console.log(`--- device review of ${esc4.id}
${text}`);
    expect(text).toContain(ATTACKER); // the payee the device decoded from the calldata
    expect(text).toMatch(/AI claims: MISMATCH/); // differs from the agent's claim (the invoice's payee of record)
    expect(text).toMatch(/REDIRECT/);
    const denyUr = dev.denyFromReview();
    dev.home();
    const d = await api(`/escalations/${esc4.id}/deny`, { ur: denyUr });
    expect(d.status, JSON.stringify(d.json)).toBe(200);
    expect(d.json.escalation.status).toBe('denied');
    expect(d.json.escalation.deny.verified).toBe(true);

    // the companion relays the deny to the reputation relay
    const rep = parseResponse(denyUr, { request: esc4.request.ur, p1Key: device.p1Key, chainId: 10143, contract: dep.relay });
    if (rep.type !== 'ripar-deny') throw new Error(rep.type);
    expect(rep.result).toBe('VERIFIED');
    await send(dep.relay, encodeFunctionData({
      abi: RIPAR_REPUTATION_RELAY_ABI,
      functionName: 'attestDenial',
      args: [rep.fields.agentId, rep.fields.requestHash, rep.fields.presenceHash, device.px, device.py, rep.fields.r, rep.fields.s],
    }));
    const denied = await pc.readContract({ address: dep.relay, abi: RIPAR_REPUTATION_RELAY_ABI, functionName: 'denialAttested', args: [device.keyId, rep.fields.requestHash] });
    expect(denied).toBe(true);
    expect(await musd(ATTACKER)).toBe(0n);
    const inv = (await api('/state')).json.invoices.find((i: { id: string }) => i.id === 'INV-004');
    expect(inv.status).toBe('denied');
  });
});
