// The local dev stack (scripts/dev-stack.sh) writes its description to companion/public/devstack/stack.json, which the
// companion's own dev server serves. Opening the companion with `?devstack` applies it to the Connect settings: the
// local anvil fork RPC, the anvil courier, the deployments JSON and the agent URL. Only a local RPC and a local agent
// are accepted (a dev convenience; the anvil courier only works on a local RPC anyway), and only a same-origin file.
import { isValidAddress, parseDeployment, toChecksumAddress } from '@ripar/protocol';
import { isRecord } from './json';
import { isLocalRpc } from './networks';
import type { Settings } from './store';

export const DEVSTACK_PATH = '/devstack/stack.json';

/** the Connect settings described by a dev-stack stack.json (throws Error with a user-facing message) */
export function devStackSettings(x: unknown): Partial<Settings> {
  if (!isRecord(x)) throw new Error('stack.json: not an object');
  const text = (k: string): string => {
    const v = x[k];
    if (typeof v !== 'string' || !v) throw new Error(`stack.json: ${k} missing`);
    return v;
  };
  const rpcUrl = text('rpcUrl');
  const agentUrl = text('agentUrl');
  if (!isLocalRpc(rpcUrl)) throw new Error(`stack.json: rpcUrl ${rpcUrl} is not a local RPC`);
  if (!isLocalRpc(agentUrl)) throw new Error(`stack.json: agentUrl ${agentUrl} is not local`);
  const chainId = x.chainId;
  if (chainId !== 10143 && chainId !== 143) throw new Error('stack.json: chainId must be 10143 or 143 (the chains the device knows)');
  const courier = text('courier');
  if (!isValidAddress(courier)) throw new Error('stack.json: courier is not an address');
  if (!isRecord(x.deployments)) throw new Error('stack.json: deployments missing');
  parseDeployment(x.deployments, chainId); // validates every address and the chain id
  const deploymentsUrl = typeof x.companionDeploymentsUrl === 'string' && x.companionDeploymentsUrl.startsWith('/') ? x.companionDeploymentsUrl : '';
  return {
    network: 'anvil-fork',
    rpcUrl,
    chainId,
    courier: 'anvil',
    anvilAccount: toChecksumAddress(courier),
    agentUrl,
    deploymentsUrl,
    deploymentsJson: JSON.stringify(x.deployments, null, 2),
  };
}

/**
 * `?devstack` (or `?devstack=/other/path.json`, same origin only) in the page URL: fetch the stack description and
 * return the settings to apply, or null when the page was opened without it.
 */
export async function loadDevStack(
  loc: Pick<Location, 'search' | 'origin'>,
  fetchImpl: typeof fetch = (...a) => globalThis.fetch(...a),
): Promise<Partial<Settings> | null> {
  const params = new URLSearchParams(loc.search);
  if (!params.has('devstack')) return null;
  const url = new URL(params.get('devstack') || DEVSTACK_PATH, loc.origin);
  if (url.origin !== loc.origin) throw new Error('?devstack: only a file served by this companion is accepted');
  const r = await fetchImpl(url.href, { cache: 'no-store' });
  if (!r.ok) throw new Error(`?devstack: ${url.pathname} answered HTTP ${r.status} (is scripts/dev-stack.sh running?)`);
  return devStackSettings(await r.json());
}

/** set when this page load applied `?devstack` (Connect then runs its checks and says where the settings came from) */
export const devStackState: { appliedAt: number | null } = { appliedAt: null };

/** a companion served from this machine (the dev server), where a dev stack may be running next to it */
export function isLocalOrigin(loc: Pick<Location, 'hostname'>): boolean {
  return ['localhost', '127.0.0.1', '[::1]', '::1'].includes(loc.hostname) || loc.hostname.endsWith('.localhost');
}

/**
 * Without `?devstack`: is a local dev stack running next to this companion? Returns its settings, or null (not a
 * local origin, no stack.json, or a malformed one). Never throws.
 */
export async function probeDevStack(
  loc: Pick<Location, 'origin' | 'hostname'>,
  fetchImpl: typeof fetch = (...a) => globalThis.fetch(...a),
): Promise<Partial<Settings> | null> {
  if (!isLocalOrigin(loc)) return null;
  try {
    const r = await fetchImpl(new URL(DEVSTACK_PATH, loc.origin).href, { cache: 'no-store' });
    if (!r.ok || !/json/i.test(r.headers.get('content-type') ?? '')) return null;
    return devStackSettings(await r.json());
  } catch {
    return null;
  }
}
