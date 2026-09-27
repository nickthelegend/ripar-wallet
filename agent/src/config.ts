// Configuration from the environment (agent/.env, see .env.example). Ripar contract addresses always come from a
// deployments JSON (contracts/deployments/<chainId>.json written by script/Deploy.s.sol), never from constants.
import { existsSync, readFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FIRMWARE_CHAIN_IDS, parseDeployment, type RiparDeployment } from '@ripar/protocol';
import type { Hex } from 'viem';

export const AGENT_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const DEFAULT_QWEN_BASE_URL = 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1';
export const DEFAULT_QWEN_MODEL = 'qwen3.8-max';
/** the device refuses a co-sign expiry more than 7 days after its time */
export const MAX_COSIGN_TTL_SECONDS = 7 * 24 * 3600;
export const DEFAULT_ORIGINS = ['http://localhost:5173', 'http://127.0.0.1:5173'];

export type SignerConfig =
  | { kind: 'local'; privateKey: Hex }
  | { kind: 'privy'; appId?: string; walletId?: string; address?: string };

export interface QwenConfig {
  /** unset = the deterministic scripted planner */
  apiKey?: string;
  baseUrl: string;
  model: string;
  /** merged into every chat.completions request body (DashScope: {"enable_thinking": false}) */
  extraBody: Record<string, unknown>;
  /** tool-calling rounds per planner step */
  maxRounds: number;
}

export interface AgentConfig {
  rpcUrl: string;
  chainId: number;
  deploymentsPath: string;
  deployment: RiparDeployment;
  signer: SignerConfig;
  qwen: QwenConfig;
  port: number;
  host: string;
  /** CORS allow-list (the companion's origin) */
  companionOrigins: string[];
  /** optional bearer token for POST requests */
  apiToken?: string;
  dataDir: string;
  invoicesPath: string;
  invoicesExamplePath: string;
  /** ERC-8004 agent id: attestApproval after every HUMAN redemption when set */
  agentId?: bigint;
  cosignTtlSeconds: number;
  gasMarginPercent: number;
  autoRunSeconds: number;
  /** pay_invoice calls one planner step may make */
  maxPaymentsPerStep: number;
}

export class ConfigError extends Error {
  override name = 'ConfigError';
}

type Env = Record<string, string | undefined>;

const str = (env: Env, k: string): string | undefined => {
  const v = env[k];
  return v === undefined || v.trim() === '' ? undefined : v.trim();
};

function int(env: Env, k: string, dflt: number, min: number, max: number): number {
  const v = str(env, k);
  if (v === undefined) return dflt;
  if (!/^\d+$/.test(v)) throw new ConfigError(`${k} must be an integer`);
  const n = Number(v);
  if (n < min || n > max) throw new ConfigError(`${k} must be between ${min} and ${max}`);
  return n;
}

/** relative paths are relative to agent/ */
export function agentPath(p: string, base = AGENT_DIR): string {
  return isAbsolute(p) ? p : resolve(base, p);
}

/** loads agent/.env (if present) into process.env without overriding variables that are already set */
export function loadDotEnv(path = resolve(AGENT_DIR, '.env')): boolean {
  if (!existsSync(path)) return false;
  process.loadEnvFile(path);
  return true;
}

export interface LoadOptions {
  /** base directory for relative paths (default agent/) */
  baseDir?: string;
  /** read the deployments JSON from here instead of the file system (tests) */
  deploymentJson?: string | Record<string, unknown>;
}

export function loadConfig(env: Env = process.env, opts: LoadOptions = {}): AgentConfig {
  const base = opts.baseDir ?? AGENT_DIR;
  const rpcUrl = str(env, 'RPC_URL');
  if (!rpcUrl) throw new ConfigError('RPC_URL is required');
  if (!/^https?:\/\//.test(rpcUrl)) throw new ConfigError('RPC_URL must be an http(s) URL');
  const chainIdS = str(env, 'CHAIN_ID');
  if (!chainIdS || !/^\d+$/.test(chainIdS)) throw new ConfigError('CHAIN_ID is required (e.g. 10143)');
  const chainId = Number(chainIdS);

  const depPath = str(env, 'DEPLOYMENTS');
  if (!depPath && !opts.deploymentJson) throw new ConfigError('DEPLOYMENTS (path to a deployments JSON) is required');
  const deploymentsPath = depPath ? agentPath(depPath, base) : '(inline)';
  let depJson: string | Record<string, unknown>;
  if (opts.deploymentJson) depJson = opts.deploymentJson;
  else {
    if (!existsSync(deploymentsPath)) throw new ConfigError(`DEPLOYMENTS: ${deploymentsPath} does not exist`);
    depJson = readFileSync(deploymentsPath, 'utf8');
  }
  let deployment: RiparDeployment;
  try {
    deployment = parseDeployment(depJson, chainId);
  } catch (e) {
    throw new ConfigError(`DEPLOYMENTS: ${(e as Error).message}`);
  }

  const signerKind = (str(env, 'AGENT_SIGNER') ?? 'local').toLowerCase();
  let signer: SignerConfig;
  if (signerKind === 'local') {
    const pk = str(env, 'AGENT_PRIVATE_KEY');
    if (!pk) throw new ConfigError('AGENT_PRIVATE_KEY is required with AGENT_SIGNER=local (a fresh dev key: `cast wallet new`)');
    if (!/^0x[0-9a-fA-F]{64}$/.test(pk)) throw new ConfigError('AGENT_PRIVATE_KEY must be 0x followed by 64 hex digits');
    signer = { kind: 'local', privateKey: pk as Hex };
  } else if (signerKind === 'privy') {
    signer = {
      kind: 'privy',
      appId: str(env, 'PRIVY_APP_ID'),
      walletId: str(env, 'PRIVY_WALLET_ID'),
      address: str(env, 'PRIVY_WALLET_ADDRESS'),
    };
  } else {
    throw new ConfigError('AGENT_SIGNER must be "local" or "privy"');
  }

  let extraBody: Record<string, unknown> = { enable_thinking: false };
  const eb = str(env, 'QWEN_EXTRA_BODY');
  if (eb !== undefined) {
    try {
      const o = JSON.parse(eb) as unknown;
      if (o === null || typeof o !== 'object' || Array.isArray(o)) throw new Error('not an object');
      extraBody = o as Record<string, unknown>;
    } catch (e) {
      throw new ConfigError(`QWEN_EXTRA_BODY must be a JSON object (${(e as Error).message})`);
    }
  }
  const qwen: QwenConfig = {
    apiKey: str(env, 'QWEN_API_KEY'),
    baseUrl: str(env, 'QWEN_BASE_URL') ?? DEFAULT_QWEN_BASE_URL,
    model: str(env, 'QWEN_MODEL') ?? DEFAULT_QWEN_MODEL,
    extraBody,
    maxRounds: int(env, 'QWEN_MAX_ROUNDS', 6, 1, 20),
  };

  const origins = (str(env, 'COMPANION_ORIGIN') ?? DEFAULT_ORIGINS.join(','))
    .split(',')
    .map((s) => s.trim().replace(/\/$/, ''))
    .filter(Boolean);
  for (const o of origins) if (o !== '*' && !/^https?:\/\/[^/]+$/.test(o)) throw new ConfigError(`COMPANION_ORIGIN: bad origin ${o}`);

  const agentIdS = str(env, 'AGENT_ID');
  if (agentIdS !== undefined && !/^\d+$/.test(agentIdS)) throw new ConfigError('AGENT_ID must be an integer');

  const dataDir = agentPath(str(env, 'DATA_DIR') ?? 'data', base);
  return {
    rpcUrl,
    chainId,
    deploymentsPath,
    deployment,
    signer,
    qwen,
    port: int(env, 'PORT', 8787, 0, 65535),
    host: str(env, 'HOST') ?? '127.0.0.1',
    companionOrigins: origins,
    apiToken: str(env, 'AGENT_API_TOKEN'),
    dataDir,
    invoicesPath: agentPath(str(env, 'INVOICES') ?? resolve(dataDir, 'invoices.json'), base),
    invoicesExamplePath: resolve(AGENT_DIR, 'data', 'invoices.example.json'),
    agentId: agentIdS !== undefined ? BigInt(agentIdS) : undefined,
    cosignTtlSeconds: int(env, 'COSIGN_TTL_SECONDS', 3600, 60, MAX_COSIGN_TTL_SECONDS),
    gasMarginPercent: int(env, 'GAS_MARGIN_PERCENT', 20, 0, 200),
    autoRunSeconds: int(env, 'AUTO_RUN_SECONDS', 0, 0, 86400),
    maxPaymentsPerStep: int(env, 'MAX_PAYMENTS_PER_STEP', 3, 1, 20),
  };
}

/** warnings worth printing at start-up (never includes secrets) */
export function configWarnings(c: AgentConfig): string[] {
  const w: string[] = [];
  if (!FIRMWARE_CHAIN_IDS.includes(c.chainId)) {
    w.push(`chain ${c.chainId} is not in the Ripar firmware chain table (${FIRMWARE_CHAIN_IDS.join(', ')}): the device will refuse its co-signs`);
  }
  if (!c.qwen.apiKey) w.push('QWEN_API_KEY is not set: using the deterministic scripted planner');
  if (c.companionOrigins.includes('*')) w.push('COMPANION_ORIGIN=* lets any web page call this API');
  if (c.host !== '127.0.0.1' && c.host !== 'localhost' && !c.apiToken) {
    w.push(`listening on ${c.host} without AGENT_API_TOKEN: anyone who can reach the port can trigger planner steps`);
  }
  return w;
}

/** the config without secrets, for /health and logs */
export function publicConfig(c: AgentConfig): Record<string, unknown> {
  return {
    chainId: c.chainId,
    rpcUrl: c.rpcUrl.replace(/\/\/([^/@]*@)/, '//***@'),
    deploymentsPath: c.deploymentsPath,
    signer: c.signer.kind,
    planner: c.qwen.apiKey ? `qwen (${c.qwen.model})` : 'scripted',
    agentId: c.agentId?.toString() ?? null,
    cosignTtlSeconds: c.cosignTtlSeconds,
    gasMarginPercent: c.gasMarginPercent,
  };
}
