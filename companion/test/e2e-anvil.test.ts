// Optional end-to-end run against a LOCAL anvil fork of Monad testnet with the Ripar contracts deployed
// (contracts/script/Deploy.s.sol). Skipped unless both are set:
//   RIPAR_E2E_RPC=http://127.0.0.1:8545            (must be a local RPC; anvil's unlocked dev accounts pay)
//   RIPAR_E2E_DEPLOYMENTS=<path to deployments/10143.json>
// Every chain write goes through src/lib/chain.ts with its explicit gas limit, the device is the WASM emulator, and
// the co-sign is redeemed on-chain by an "agent" (anvil dev account #1) to prove the caveat args are right.
import { readFileSync } from 'node:fs';
import { beforeAll, describe, expect, it } from 'vitest';
import { type Address, type Hex, createWalletClient, encodeAbiParameters, encodeFunctionData, http, parseAbi, parseEventLogs } from 'viem';
import {
  DELEGATION_MANAGER,
  DELEGATION_MANAGER_ABI,
  ERC173_OWNER_ABI,
  ERC8004_IDENTITY_ABI,
  PULSE_COSIGN_ENFORCER_ABI,
  RIPAR_DEVICE_REGISTRY_ABI,
  RIPAR_REPUTATION_RELAY_ABI,
  RIPAR_SENTINEL_ABI,
  type RiparDeployment,
  encodeRedeemDelegations,
  erc20Transfer,
  parseDeployment,
  randomBytes,
  toHex,
  withCaveatArgs,
} from '@ripar/protocol';
import { parseEscalation } from '../src/lib/agent';
import { GAS_LIMITS, MOCK_USD_ABI, type WriteRequest, attestDenialWrite, deployVaultWrite, faucetWrite, registerDeviceWrite, sendWrite } from '../src/lib/chain';
import { connectCourier, publicClientFor } from '../src/lib/clients';
import { acceptCosignAnswer, answersCosign, planCosign } from '../src/lib/flows/cosign';
import { KILL_TYPES, acceptKillSwitch } from '../src/lib/flows/killswitch';
import { type MandateForm, acceptMandate, answersMandate, delegationFromJson, planMandate } from '../src/lib/flows/mandate';
import { acceptPairing, answersRequest, isKeysOnlyPair, planPairing, readKeysOnly } from '../src/lib/flows/pairing';
import { deriveVault } from '../src/lib/flows/vault';
import { isLocalRpc } from '../src/lib/networks';
import { nonceUsed, readMinEpoch } from '../src/lib/reads';
import { DEFAULT_SETTINGS, type MandateRecord, type PairedDevice, type Settings } from '../src/lib/store';
import { DeviceExchange } from '../src/device/transport';
import { Rig, loadEmu, tickPromises, track } from './helpers';

const RPC = process.env.RIPAR_E2E_RPC ?? '';
const DEP_PATH = process.env.RIPAR_E2E_DEPLOYMENTS ?? '';
const enabled = !!RPC && !!DEP_PATH && isLocalRpc(RPC);

const AGENT: Address = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8'; // anvil dev account #1 (unlocked)
const PAYEE: Address = '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC'; // anvil dev account #2
const gasLog: Record<string, bigint> = {};

describe.skipIf(!enabled)('e2e on a local anvil fork (RIPAR_E2E_RPC)', () => {
  let dep: RiparDeployment;
  let settings: Settings;
  let rig: Rig;
  let device: PairedDevice;
  let mandate: MandateRecord;
  let agentId: bigint;
  const pc = () => publicClientFor(settings);

  async function write(w: WriteRequest) {
    const courier = await connectCourier(settings);
    const r = await sendWrite(pc(), courier, w);
    gasLog[w.kind] = r.gasUsed;
    expect(r.gasUsed).toBeLessThan(w.gas);
    return r;
  }

  async function exchange(parts: string[], expect_: string[], accept: ((u: string) => boolean) | undefined, drive: () => void) {
    const ex = new DeviceExchange(rig.transport, { parts, expect: expect_, ...(accept ? { accept } : {}) }, rig.sched);
    const got = track(ex);
    drive();
    await tickPromises();
    expect(got.value(), 'the device answered').toBeTruthy();
    return got.value()!;
  }

  const holdRelease = () => {
    rig.emu.keyDown();
    rig.run((s) => s.screen === 'homeHold', 3000);
    rig.emu.keyUp();
    rig.run((s) => s.screen === 'pairQr', 1000);
  };

  beforeAll(async () => {
    dep = parseDeployment(readFileSync(DEP_PATH, 'utf8'), 10143);
    settings = { ...DEFAULT_SETTINGS, network: 'anvil-fork', rpcUrl: RPC, chainId: 10143, courier: 'anvil' };
    const mod = await loadEmu();
    // a fresh demo device per run (random seed, test mode), so the run never collides with an earlier one
    rig = new Rig(await mod.RiparEmulator.create({ test: { seed: toHex(randomBytes(32)).slice(2) } }));
  });

  it('pairs (keys-only + full), registers the device, deploys and funds the vault', async () => {
    const keysUr = await exchange([], ['ripar-pair'], isKeysOnlyPair, holdRelease);
    rig.home();
    const keys = readKeysOnly(keysUr);
    const minEpoch = await readMinEpoch(pc(), dep.enforcer, keys.keyId);
    const plan = planPairing(dep, keys.k1Address, { now: Math.floor(Date.now() / 1000), minEpoch });
    const pairUr = await exchange(plan.request.parts, ['ripar-pair'], (u) => answersRequest(u, plan.request), () => {
      rig.scanRequest();
      rig.pageToEnd();
      rig.pulseAndSign();
    });
    rig.home();
    device = acceptPairing(pairUr, plan, keys);

    await write(registerDeviceWrite(dep.registry, device));
    const keyOf = await pc().readContract({ address: dep.registry, abi: RIPAR_DEVICE_REGISTRY_ABI, functionName: 'keyOf', args: [device.keyId] });
    expect(keyOf[2]).toBe(device.k1Address);

    const v = await deriveVault(device.k1Address, 10143);
    expect(v.matches).toBe(true);
    expect(v.address).toBe(device.pinned.vault);
    await write(deployVaultWrite(v.factory, v.factoryData, v.address));
    expect(await pc().readContract({ address: v.address, abi: ERC173_OWNER_ABI, functionName: 'owner' })).toBe(device.k1Address);

    await write(faucetWrite(dep.mockUsd, v.address, 1_000_000_000n));
    expect(await pc().readContract({ address: dep.mockUsd, abi: MOCK_USD_ABI, functionName: 'balanceOf', args: [v.address] })).toBe(1_000_000_000n);
  });

  it('signs a mandate for an ERC-8004 agent', async () => {
    // the agent registers itself on the (forked) ERC-8004 identity registry; where register() reverts (it does on the
    // Monad testnet registry as of 2026-09-27, even as a plain eth_call), use an existing agent id instead
    const agentWallet = createWalletClient({ account: AGENT, transport: http(RPC) });
    try {
      const sim = await pc().simulateContract({ account: AGENT, address: dep.erc8004Identity, abi: ERC8004_IDENTITY_ABI, functionName: 'register', args: ['https://example.invalid/ripar-e2e-agent.json', []] });
      agentId = sim.result;
      const h = await agentWallet.writeContract({ ...sim.request, chain: null, gas: 600_000n });
      expect((await pc().waitForTransactionReceipt({ hash: h })).status).toBe('success');
    } catch {
      agentId = BigInt(process.env.RIPAR_E2E_AGENT_ID ?? '1');
      const owner = await pc().readContract({ address: dep.erc8004Identity, abi: ERC8004_IDENTITY_ABI, functionName: 'ownerOf', args: [agentId] });
      expect(owner).toMatch(/^0x/);
    }

    const epoch = await readMinEpoch(pc(), device.pinned.enforcer, device.keyId);
    const form: MandateForm = {
      agent: AGENT,
      agentId: agentId.toString(),
      label: 'e2e agent',
      token: dep.mockUsd,
      tokenDecimals: 6,
      tokenSymbol: 'mUSD',
      perTxAutoCap: '5',
      periodAutoCap: '20',
      period: 86400,
      newPayeeNeedsHuman: true,
      redeemerOnly: true,
      validUntil: null,
    };
    const plan = planMandate(form, device, epoch);
    const ur = await exchange(plan.request.parts, ['eth-signature'], (u) => answersMandate(u, plan.request), () => {
      const s = rig.scanRequest();
      expect(s.review!.ok, s.review!.refusal).toBe(true);
      rig.pageToEnd();
      rig.pulseAndSign();
    });
    rig.home();
    mandate = acceptMandate(ur, plan, form, device);
  });

  function escalation(id: string, amount: bigint) {
    return parseEscalation({
      id,
      chainId: 10143,
      enforcer: device.pinned.enforcer,
      delegationHash: mandate.delegationHash,
      delegator: device.pinned.vault,
      redeemer: AGENT,
      call: { target: dep.mockUsd, value: '0', callData: toHex(erc20Transfer(PAYEE, amount)) },
      reason: 'new-payee',
      agentId: agentId.toString(),
      note: 'e2e invoice',
      claims: { to: PAYEE, token: dep.mockUsd, amount: amount.toString() },
    });
  }

  it('co-signs on the device and the agent redeems it on the HUMAN path', async () => {
    const e = escalation('e2e-1', 25_000_000n);
    let nonce = 1n + BigInt(Math.floor(Math.random() * 1e9));
    while (await nonceUsed(pc(), device.pinned.enforcer, mandate.delegationHash, nonce)) nonce++;
    const plan = planCosign(e, { device, nonce, now: Math.floor(Date.now() / 1000), tokenMeta: { decimals: 6, symbol: 'mUSD' } });
    const ur = await exchange(plan.request.parts, ['ripar-cosign', 'ripar-deny'], (u) => answersCosign(u, plan.request), () => {
      rig.scanRequest();
      rig.pageToEnd();
      rig.pulseAndSign();
    });
    rig.home();
    const out = acceptCosignAnswer(ur, plan, device, mandate);
    expect(out.kind).toBe('cosign');
    if (out.kind !== 'cosign') return;
    // what the agent does with the answer: set the pulse caveat's args and redeem
    const d = withCaveatArgs(delegationFromJson(mandate.delegation), device.pinned.enforcer, out.answer.caveatArgs);
    const data = encodeRedeemDelegations([{ delegations: [d], target: dep.mockUsd, value: 0n, callData: erc20Transfer(PAYEE, 25_000_000n) }]);
    const agentWallet = createWalletClient({ account: AGENT, transport: http(RPC) });
    const before = await pc().readContract({ address: dep.mockUsd, abi: MOCK_USD_ABI, functionName: 'balanceOf', args: [PAYEE] });
    await pc().call({ account: AGENT, to: DELEGATION_MANAGER, data, gas: 1_500_000n });
    const h = await agentWallet.sendTransaction({ to: DELEGATION_MANAGER, data, gas: 1_500_000n, chain: null });
    const rc = await pc().waitForTransactionReceipt({ hash: h });
    expect(rc.status).toBe('success');
    gasLog.redeemHuman = rc.gasUsed;
    const after = await pc().readContract({ address: dep.mockUsd, abi: MOCK_USD_ABI, functionName: 'balanceOf', args: [PAYEE] });
    expect(after - before).toBe(25_000_000n);
    const ev = parseEventLogs({ abi: PULSE_COSIGN_ENFORCER_ABI, logs: rc.logs, eventName: 'HumanCosigned' });
    expect(ev.length).toBe(1);
    expect(await nonceUsed(pc(), device.pinned.enforcer, mandate.delegationHash, nonce)).toBe(true);
    void DELEGATION_MANAGER_ABI;
  });

  it('denies from the review (hold 2 s) and relays attestDenial', async () => {
    const e = escalation('e2e-2', 7_000_000n);
    const plan = planCosign(e, { device, nonce: 424242n + BigInt(Math.floor(Math.random() * 1e6)), now: Math.floor(Date.now() / 1000) });
    const ur = await exchange(plan.request.parts, ['ripar-cosign', 'ripar-deny'], (u) => answersCosign(u, plan.request), () => {
      rig.scanRequest();
      rig.key('hold2');
      rig.pageToEnd();
      rig.key('press');
    });
    rig.home();
    const out = acceptCosignAnswer(ur, plan, device, mandate);
    expect(out.kind).toBe('deny');
    if (out.kind !== 'deny') return;
    const r = await write(attestDenialWrite(device.pinned.relay, { ...out.attest, px: device.px, py: device.py }));
    const rc = await pc().getTransactionReceipt({ hash: r.hash });
    const v = parseEventLogs({ abi: RIPAR_REPUTATION_RELAY_ABI, logs: rc.logs, eventName: 'Verdict' });
    expect(v[0]?.args.approved).toBe(false);
    expect(v[0]?.args.agentId).toBe(agentId);
  });

  it('kill switch: the sentinel closes the lane, the device reopens it, revokes the mandate and PANICs', async () => {
    // close the lane as the CRE forwarder would (impersonated on the fork)
    const fwd = dep.creForwarder;
    await pc().request({ method: 'anvil_impersonateAccount' as never, params: [fwd] as never });
    await pc().request({ method: 'anvil_setBalance' as never, params: [fwd, '0x56BC75E2D63100000'] as never });
    const block = await pc().getBlockNumber();
    const metadata = `0x${'11'.repeat(32)}${'22'.repeat(10)}${dep.expectedWorkflowOwner.slice(2)}` as Hex;
    const report = encodeAbiParameters([{ type: 'address' }, { type: 'bool' }, { type: 'uint8' }, { type: 'uint64' }], [device.pinned.vault, false, 1, block]);
    const fw = createWalletClient({ account: fwd, transport: http(RPC) });
    const h = await fw.sendTransaction({
      to: dep.sentinel,
      data: encodeFunctionData({ abi: RIPAR_SENTINEL_ABI, functionName: 'onReport', args: [metadata, report] }),
      gas: 300_000n,
      chain: null,
    });
    expect((await pc().waitForTransactionReceipt({ hash: h })).status).toBe('success');
    expect(await pc().readContract({ address: dep.sentinel, abi: RIPAR_SENTINEL_ABI, functionName: 'laneOpen', args: [device.pinned.vault] })).toBe(false);

    // REOPEN from the device menu
    const reopenUr = await exchange([], [...KILL_TYPES], undefined, () => {
      holdRelease();
      rig.key('hold2');
      rig.key('press');
      rig.key('hold2');
      rig.pageToEnd();
      rig.pulseAndSign();
    });
    rig.home();
    await write(acceptKillSwitch(reopenUr, device).write);
    expect(await pc().readContract({ address: dep.sentinel, abi: RIPAR_SENTINEL_ABI, functionName: 'laneOpen', args: [device.pinned.vault] })).toBe(true);

    // REVOKE the mandate
    const revokeUr = await exchange([], [...KILL_TYPES], undefined, () => {
      holdRelease();
      rig.key('hold2');
      rig.key('hold2');
      rig.pageToEnd();
      rig.pulseAndSign();
    });
    rig.home();
    await write(acceptKillSwitch(revokeUr, device).write);
    expect(
      await pc().readContract({ address: device.pinned.enforcer, abi: PULSE_COSIGN_ENFORCER_ABI, functionName: 'isRevoked', args: [device.keyId, mandate.delegationHash] }),
    ).toBe(true);

    // PANIC
    const panicUr = await exchange([], [...KILL_TYPES], undefined, () => {
      rig.emu.keyDown();
      rig.run((s) => s.screen === 'qr', 6000);
      rig.emu.keyUp();
      rig.run(() => false, 200);
    });
    rig.home();
    await write(acceptKillSwitch(panicUr, device).write);
    expect(await readMinEpoch(pc(), device.pinned.enforcer, device.keyId)).toBe(BigInt(mandate.epoch) + 1n);

    // gas used vs the explicit limits (printed for the README)
    console.log('gas used / limit:', Object.fromEntries(Object.entries(gasLog).map(([k, v]) => [k, `${v} / ${(GAS_LIMITS as Record<string, bigint>)[k] ?? '-'}`])));
    void parseAbi;
  });
});
