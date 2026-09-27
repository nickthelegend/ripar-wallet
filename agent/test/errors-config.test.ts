// Revert decoding and configuration.
import { describe, expect, it } from 'vitest';
import { encodeErrorResult, encodeAbiParameters, parseAbi, type Hex } from 'viem';
import { generatePrivateKey } from 'viem/accounts';
import {
  ConfigError,
  DEFAULT_QWEN_BASE_URL,
  DEFAULT_QWEN_MODEL,
  configWarnings,
  loadConfig,
  publicConfig,
} from '../src/config.js';
import { ChainRevertError, RIPAR_ERRORS_ABI, decodeRevert, decodeRevertData, revertDataOf } from '../src/errors.js';
import { PrivySigner, LocalKeySigner, chainFor, createSigner } from '../src/signer.js';
import { DEP } from './helpers/fixture.js';

const enc = (name: string, args: unknown[] = []): Hex => encodeErrorResult({ abi: RIPAR_ERRORS_ABI, errorName: name, args } as never);

describe('revert decoding', () => {
  it('decodes every Ripar custom error the agent can meet', () => {
    for (const n of [
      'HumanRequired',
      'LaneClosed',
      'CosignReplayed',
      'CosignExpired',
      'BadCosign',
      'DelegationRevoked',
      'StaleEpoch',
      'InvalidArgs',
      'InvalidTerms',
      'NotRedeemer',
      'NotConsumed',
      'UnknownDevice',
      'AgentIsShielded',
      'NotAgentRedeemer',
      'AlreadyAttested',
      'CannotUseADisabledDelegation',
      'InvalidDelegate',
      'EnforcedPause',
    ]) {
      const r = decodeRevertData(enc(n));
      expect(r.name).toBe(n);
      expect(r.message.length).toBeGreaterThan(3);
    }
    const bal = decodeRevertData(enc('ERC20InsufficientBalance', ['0x1111111111111111111111111111111111111111', 1n, 2n]));
    expect(bal.name).toBe('ERC20InsufficientBalance');
    expect(bal.args[2]).toBe(2n);
  });

  it('decodes Error(string), Panic(uint256), empty and unknown reverts', () => {
    const err = ('0x08c379a0' + encodeAbiParameters([{ type: 'string' }], ['TimestampEnforcer:expired-delegation']).slice(2)) as Hex;
    expect(decodeRevertData(err)).toMatchObject({ name: 'Error', message: 'TimestampEnforcer:expired-delegation' });
    const panic = ('0x4e487b71' + encodeAbiParameters([{ type: 'uint256' }], [0x11n]).slice(2)) as Hex;
    expect(decodeRevertData(panic)).toMatchObject({ name: 'Panic', message: 'panic 0x11' });
    expect(decodeRevertData('0x').name).toBe('EmptyRevert');
    expect(decodeRevertData('0xdeadbeef').name).toBe('UnknownError');
  });

  it('finds the revert data in nested error chains (viem / JSON-RPC shapes)', () => {
    const data = enc('HumanRequired');
    expect(revertDataOf({ name: 'EstimateGasExecutionError', cause: { name: 'ExecutionRevertedError', cause: { code: 3, data } } })).toBe(data);
    expect(revertDataOf({ cause: { data: { data } } })).toBe(data);
    expect(revertDataOf({ error: { data } })).toBe(data);
    expect(revertDataOf({ name: 'ContractFunctionRevertedError', raw: data, data: { errorName: 'HumanRequired' } })).toBe(data);
    expect(decodeRevert({ message: 'x', cause: { data } })!.name).toBe('HumanRequired');
    expect(decodeRevert({ message: 'execution reverted' })!.name).toBe('EmptyRevert');
    expect(decodeRevert(new Error('fetch failed'))).toBeNull();
    const e = new ChainRevertError(decodeRevertData(enc('LaneClosed')), 'estimate');
    expect(e.escalate).toBe(true);
    expect(e.message).toMatch(/^LaneClosed:/);
  });

  it('the error ABI has no duplicate signatures and includes the interfaces\' errors', () => {
    const sigs = RIPAR_ERRORS_ABI.map((e) => `${e.name}(${e.inputs.map((i) => i.type).join(',')})`);
    expect(new Set(sigs).size).toBe(sigs.length);
    const iface = parseAbi(['error LaneNotClosed()', 'error KeyTaken()']);
    for (const e of iface) expect(sigs).toContain(`${e.name}()`);
  });
});

describe('config', () => {
  const base = (over: Record<string, string> = {}) => ({
    RPC_URL: 'http://127.0.0.1:8545',
    CHAIN_ID: '10143',
    AGENT_PRIVATE_KEY: generatePrivateKey(),
    ...over,
  });

  it('defaults', () => {
    const c = loadConfig(base(), { deploymentJson: { ...DEP } });
    expect(c.qwen.baseUrl).toBe(DEFAULT_QWEN_BASE_URL);
    expect(c.qwen.model).toBe(DEFAULT_QWEN_MODEL);
    expect(DEFAULT_QWEN_BASE_URL).toBe('https://dashscope-intl.aliyuncs.com/compatible-mode/v1');
    expect(DEFAULT_QWEN_MODEL).toBe('qwen3.8-max');
    expect(c.qwen.apiKey).toBeUndefined();
    expect(c.qwen.extraBody).toEqual({ enable_thinking: false });
    expect(c.port).toBe(8787);
    expect(c.host).toBe('127.0.0.1');
    expect(c.cosignTtlSeconds).toBe(3600);
    expect(c.gasMarginPercent).toBe(20);
    expect(c.deployment.enforcer).toBe(DEP.PulseCosignEnforcer);
    expect(c.signer.kind).toBe('local');
    expect(configWarnings(c).join()).toMatch(/scripted planner/);
    const pub = JSON.stringify(publicConfig(c));
    expect(pub).not.toContain((c.signer as { privateKey: string }).privateKey.slice(2));
  });

  it('refuses missing / bad values', () => {
    expect(() => loadConfig({}, { deploymentJson: { ...DEP } })).toThrow(ConfigError);
    expect(() => loadConfig(base({ CHAIN_ID: '143' }), { deploymentJson: { ...DEP } })).toThrow(/chainId 10143 is not 143/);
    expect(() => loadConfig(base({ AGENT_PRIVATE_KEY: '0x1234' }), { deploymentJson: { ...DEP } })).toThrow(/64 hex/);
    expect(() => loadConfig(base({ AGENT_PRIVATE_KEY: '' }), { deploymentJson: { ...DEP } })).toThrow(/AGENT_PRIVATE_KEY is required/);
    expect(() => loadConfig(base({ COSIGN_TTL_SECONDS: String(8 * 86400) }), { deploymentJson: { ...DEP } })).toThrow(/COSIGN_TTL_SECONDS/);
    expect(() => loadConfig(base({ QWEN_EXTRA_BODY: '[1]' }), { deploymentJson: { ...DEP } })).toThrow(/QWEN_EXTRA_BODY/);
    expect(() => loadConfig(base({ DEPLOYMENTS: 'does/not/exist.json' }))).toThrow(/does not exist/);
    expect(() => loadConfig(base(), { deploymentJson: { ...DEP, PulseCosignEnforcer: '0x0000000000000000000000000000000000000000' } })).toThrow(/zero address/);
    expect(() => loadConfig(base({ COMPANION_ORIGIN: 'http://x/y' }), { deploymentJson: { ...DEP } })).toThrow(/origin/);
  });

  it('Qwen settings and the Privy stub', async () => {
    const c = loadConfig(
      base({ QWEN_API_KEY: 'sk-test', QWEN_MODEL: 'qwen-plus', QWEN_EXTRA_BODY: '{"enable_thinking":true}', AGENT_SIGNER: 'privy', AGENT_PRIVATE_KEY: '' }),
      { deploymentJson: { ...DEP } },
    );
    expect(c.qwen).toMatchObject({ apiKey: 'sk-test', model: 'qwen-plus', extraBody: { enable_thinking: true } });
    expect(JSON.stringify(publicConfig(c))).not.toContain('sk-test');
    const s = createSigner(c.signer, chainFor(10143, c.rpcUrl));
    expect(s).toBeInstanceOf(PrivySigner);
    expect(() => s.address).toThrow(/not configured/);
    await expect(s.sendTransaction({ to: DEP.MockUSD, data: '0x', gas: 1n })).rejects.toThrow(/not configured/);
  });

  it('LocalKeySigner never serializes its key', () => {
    const pk = generatePrivateKey();
    const s = new LocalKeySigner(pk, chainFor(10143, 'http://127.0.0.1:9'));
    expect(JSON.stringify(s)).not.toContain(pk.slice(2));
    expect(JSON.stringify(s)).toContain(s.address);
  });
});
