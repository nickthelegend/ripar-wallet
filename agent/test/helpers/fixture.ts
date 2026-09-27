// Unit-test fixture: config from an env map + an inline deployment, the fake chain, a software device (random keys)
// that owns a funded canonical vault, and the agent service on a fresh data directory.
import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Delegation } from '@ripar/protocol';
import type { Address } from 'viem';
import { generatePrivateKey, privateKeyToAddress } from 'viem/accounts';
import { loadConfig, type AgentConfig } from '../../src/config.js';
import { EventBus } from '../../src/events.js';
import { AgentService } from '../../src/service.js';
import { AgentStore } from '../../src/store.js';
import { FakeChain } from './fake-chain.js';
import { newSoftDevice, signMandate, type PulseOpts, type SoftDevice } from './soft-device.js';

export const DEP = {
  chainId: 10143,
  salt: '0xfe592ef8bed77b10b034388e03cc0f53316089815faabfb87eddeac4eafa482b',
  create2Deployer: '0x4e59b44847b379578588920cA78FbF26c0B4956C',
  RiparDeviceRegistry: '0xA08a47c9d645926615CF04D69b7a048133F68c9f',
  PulseCosignEnforcer: '0x64d61fe5438981DC803ED61250FEf024617ae7eE',
  RiparSentinel: '0x103B0DE60166B2F57b32994fac3F927679f67902',
  RiparReputationRelay: '0xE433dCA75CA6cd730b1006F51A26208B000eA9E2',
  MockUSD: '0xB5b7eaffbF9bf68cbcC1Ce8B5850b2ea9d6f9a2a',
  creForwarder: '0xF8344CFd5c43616a4366C34E3EEE75af79a74482',
  expectedWorkflowOwner: '0x1111111111111111111111111111111111111111',
  erc8004Identity: '0x8004A818BFB912233c491871b3d84c89A494BD9e',
  erc8004Reputation: '0x8004B663056A597Dffe9eCcC1965A193B7388713',
  delegationManager: '0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3',
} as const;

export const MUSD = DEP.MockUSD as Address;
export const ENFORCER = DEP.PulseCosignEnforcer as Address;
export const SENTINEL = DEP.RiparSentinel as Address;
export const RELAY = DEP.RiparReputationRelay as Address;
/** the demo invoices' addresses (data/invoices.example.json) */
export const CLOUDNEST = '0xFc8Eb32DF5BD4B08E6326a3118a94f55BeCBE7e9' as Address;
export const STUDIO_ARC = '0x7923d9Cd734e67671335546dAd9b43a529b61294' as Address;
export const LABELWORKS = '0x6A25dF78B9c4C7022cF1A7F04a0110747Cab6e82' as Address;
export const ATTACKER = '0x069ef010B46a838FeCD98ADD1E60a407Ef6E575a' as Address;

const created: string[] = [];

/** removes the data directories of this test file (test/helpers/setup.ts runs it after each file) */
export function cleanupTmp(): void {
  for (const d of created.splice(0)) rmSync(d, { recursive: true, force: true });
}

/** a fresh data directory (removed after the test file; RIPAR_TEST_TMP overrides the base) */
export function testTmpDir(prefix: string): string {
  const base = process.env.RIPAR_TEST_TMP ?? (existsSync('F:/tmp') ? 'F:/tmp/ripar-agent-tests' : join(tmpdir(), 'ripar-agent-tests'));
  mkdirSync(base, { recursive: true });
  const d = mkdtempSync(join(base, `${prefix}-`));
  created.push(d);
  return d;
}

export const DEFAULT_PULSE = (dev: SoftDevice): PulseOpts => {
  void dev;
  return {
    enforcer: ENFORCER,
    token: MUSD,
    perTxAutoCap: 5_000_000n,
    periodAutoCap: 20_000_000n,
    period: 86400,
    epoch: 0,
    newPayeeNeedsHuman: true,
    sentinel: SENTINEL,
  };
};

export interface Fixture {
  config: AgentConfig;
  chain: FakeChain;
  dev: SoftDevice;
  agent: Address;
  store: AgentStore;
  events: EventBus;
  svc: AgentService;
  mandate: Delegation;
  dataDir: string;
  /** a new service on the same data directory (restart) */
  restart(): AgentService;
}

export function makeFixture(env: Record<string, string> = {}, pulse?: Partial<PulseOpts>): Fixture {
  const agentKey = generatePrivateKey();
  const agent = privateKeyToAddress(agentKey);
  const dataDir = testTmpDir('unit');
  const config = loadConfig(
    {
      RPC_URL: 'http://127.0.0.1:9',
      CHAIN_ID: '10143',
      AGENT_PRIVATE_KEY: agentKey,
      DATA_DIR: dataDir,
      PORT: '0',
      ...env,
    },
    { deploymentJson: { ...DEP } },
  );
  const chain = new FakeChain(agent, ENFORCER);
  chain.tokens.set(MUSD.toLowerCase(), { decimals: 6, symbol: 'mUSD' });
  const dev = newSoftDevice();
  chain.owners.set(dev.vault.toLowerCase(), dev.k1);
  chain.setBalance(MUSD, dev.vault, 100_000_000n);
  const store = new AgentStore(config.dataDir, config.invoicesPath, config.invoicesExamplePath);
  const events = new EventBus();
  const svc = new AgentService({ config, chain, store, events });
  const mandate = signMandate(dev, { chainId: 10143, agent, pulse: { ...DEFAULT_PULSE(dev), ...pulse } });
  return {
    config,
    chain,
    dev,
    agent,
    store,
    events,
    svc,
    mandate,
    dataDir,
    restart() {
      const s2 = new AgentStore(config.dataDir, config.invoicesPath, config.invoicesExamplePath);
      return new AgentService({ config, chain, store: s2, events: new EventBus() });
    },
  };
}
