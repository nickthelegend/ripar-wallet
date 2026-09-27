// Registers the agent in the ERC-8004 IdentityRegistry (Monad testnet 0x8004A818BFB912233c491871b3d84c89A494BD9e)
// from the agent's own signer, with the metadata
//   ripar.vault = the vault address (20 raw bytes)      ripar.keyId = the device key id (32 raw bytes)
// The registry mints an ERC-721 agentId to the agent: RiparReputationRelay.attestApproval then credits the agent's
// device-co-signed redemptions to that id (the relay requires identity.isAuthorizedOrOwner(redeemer, agentId)).
//
//   npm run register-erc8004                       # simulate only (prints the agentId it would get)
//   npm run register-erc8004 -- --broadcast        # send the transaction, then set AGENT_ID in agent/.env
//   options: --uri <agentURI>  --vault <0x..>  --key-id <0x..32 bytes>   (vault / key id default to data/mandate.json)
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { ERC8004_IDENTITY_ABI } from '@ripar/protocol';
import {
  createPublicClient,
  encodeFunctionData,
  http,
  parseEventLogs,
  parseAbi,
  type Address,
  type Hash,
  type Hex,
  type PublicClient,
} from 'viem';
import { loadConfig, loadDotEnv } from '../src/config.js';
import { ChainRevertError, decodeRevert } from '../src/errors.js';
import { chainFor, createSigner, type Signer } from '../src/signer.js';
import type { StoredMandate } from '../src/types.js';

const TRANSFER_ABI = parseAbi(['event Transfer(address indexed from, address indexed to, uint256 indexed tokenId)']);

export interface RegisterOptions {
  client: PublicClient;
  signer: Signer;
  /** the ERC-8004 IdentityRegistry */
  identity: Address;
  agentURI: string;
  vault?: Address;
  keyId?: Hex;
  gasMarginPercent?: number;
  /** false = simulate only */
  broadcast: boolean;
}

export interface RegisterResult {
  simulatedAgentId: bigint;
  agentId?: bigint;
  txHash?: Hash;
  metadata: { key: string; value: Hex }[];
}

export function defaultAgentURI(vault?: string): string {
  const doc = {
    type: 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1',
    name: 'Ripar treasury agent',
    description:
      'Pays invoices from a Ripar vault under a MetaMask delegation. Small payments to approved payees run inside the ' +
      'PulseCosignEnforcer caps; everything else needs a co-signature from the owner\'s Ripar hardware wallet.',
    ...(vault ? { ripar: { vault } } : {}),
  };
  return `data:application/json;base64,${Buffer.from(JSON.stringify(doc)).toString('base64')}`;
}

export async function registerAgent(o: RegisterOptions): Promise<RegisterResult> {
  const metadata: { key: string; value: Hex }[] = [];
  if (o.vault) metadata.push({ key: 'ripar.vault', value: o.vault.toLowerCase() as Hex });
  if (o.keyId) {
    if (!/^0x[0-9a-fA-F]{64}$/.test(o.keyId)) throw new Error('keyId must be 32 bytes of hex');
    metadata.push({ key: 'ripar.keyId', value: o.keyId.toLowerCase() as Hex });
  }
  const account = o.signer.address;
  let simulatedAgentId: bigint;
  try {
    const sim = await o.client.simulateContract({
      account,
      address: o.identity,
      abi: ERC8004_IDENTITY_ABI,
      functionName: 'register',
      args: [o.agentURI, metadata],
    });
    simulatedAgentId = sim.result;
  } catch (e) {
    const r = decodeRevert(e);
    if (r) throw new ChainRevertError(r, 'estimate');
    throw e;
  }
  if (!o.broadcast) return { simulatedAgentId, metadata };

  const data = encodeFunctionData({ abi: ERC8004_IDENTITY_ABI, functionName: 'register', args: [o.agentURI, metadata] });
  const est = await o.client.estimateGas({ account, to: o.identity, data });
  const gas = est + (est * BigInt(o.gasMarginPercent ?? 20)) / 100n;
  const txHash = await o.signer.sendTransaction({ to: o.identity, data, gas });
  const rcpt = await o.client.waitForTransactionReceipt({ hash: txHash, timeout: 120_000 });
  if (rcpt.status !== 'success') throw new Error(`register reverted (${txHash})`);
  const mints = parseEventLogs({ abi: TRANSFER_ABI, logs: rcpt.logs, eventName: 'Transfer' }).filter(
    (l) => l.address.toLowerCase() === o.identity.toLowerCase() && BigInt(l.args.from) === 0n && l.args.to.toLowerCase() === account.toLowerCase(),
  );
  const agentId = mints[0]?.args.tokenId;
  if (agentId === undefined) throw new Error(`no ERC-721 mint to ${account} in ${txHash}`);
  const owner = await o.client.readContract({ address: o.identity, abi: ERC8004_IDENTITY_ABI, functionName: 'ownerOf', args: [agentId] });
  if (owner.toLowerCase() !== account.toLowerCase()) throw new Error(`agent ${agentId} is owned by ${owner}, not ${account}`);
  return { simulatedAgentId, agentId, txHash, metadata };
}

function argOf(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
}

async function cli(argv: string[]): Promise<void> {
  loadDotEnv();
  const config = loadConfig();
  const identity = config.deployment.erc8004Identity;
  if (/^0x0{40}$/.test(identity)) throw new Error('the deployment has no ERC-8004 identity registry');
  const chain = chainFor(config.chainId, config.rpcUrl);
  const transport = http(config.rpcUrl);
  const client = createPublicClient({ chain, transport }) as PublicClient;
  const signer = createSigner(config.signer, chain, transport);
  const mandatePath = resolve(config.dataDir, 'mandate.json');
  const mandate = existsSync(mandatePath) ? (JSON.parse(readFileSync(mandatePath, 'utf8')) as StoredMandate | null) : null;
  const vault = (argOf(argv, '--vault') ?? mandate?.vault) as Address | undefined;
  const keyId = (argOf(argv, '--key-id') ?? mandate?.pulse.keyId) as Hex | undefined;
  const broadcast = argv.includes('--broadcast');
  const res = await registerAgent({
    client,
    signer,
    identity,
    agentURI: argOf(argv, '--uri') ?? defaultAgentURI(vault),
    ...(vault ? { vault } : {}),
    ...(keyId ? { keyId } : {}),
    gasMarginPercent: config.gasMarginPercent,
    broadcast,
  });
  console.log(`agent ${signer.address} on chain ${config.chainId}, IdentityRegistry ${identity}`);
  console.log(`metadata: ${res.metadata.map((m) => `${m.key}=${m.value}`).join(' ') || '(none)'}`);
  if (!broadcast) {
    console.log(`simulation: register() would mint agentId ${res.simulatedAgentId}. Re-run with --broadcast to send it.`);
    return;
  }
  console.log(`registered: agentId ${res.agentId} (tx ${res.txHash}). Set AGENT_ID=${res.agentId} in agent/.env.`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  cli(process.argv.slice(2)).catch((e: unknown) => {
    console.error(`register-erc8004: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  });
}

