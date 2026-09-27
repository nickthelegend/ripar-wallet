// Ripar contract addresses come from contracts/deployments/<chainId>.json (written by contracts/script/Deploy.s.sol),
// never from constants: parseDeployment() validates such a file, pairFieldsFromDeployment() turns it into the
// contracts a pairing pins.
import { type Address, type IntLike, toAddr, toBytes, toHex, toInt, type Hex } from './bytes.js';
import { DELEGATION_MANAGER, FIRMWARE_CHAIN_IDS } from './constants.js';
import { ProtoError } from './errors.js';
import { isValidAddress, toChecksumAddress } from './hash.js';
import type { PairFields } from './requests.js';

/** contracts/deployments/<chainId>.json, addresses EIP-55 */
export interface RiparDeployment {
  chainId: bigint;
  /** CREATE2 salt of the deploy script */
  salt: Hex;
  create2Deployer: Address;
  registry: Address;
  enforcer: Address;
  sentinel: Address;
  relay: Address;
  /** MockUSD (testnet demo token; 6 decimals, symbol mUSD; not in the firmware token table) */
  mockUsd: Address;
  creForwarder: Address;
  expectedWorkflowOwner: Address;
  erc8004Identity: Address;
  erc8004Reputation: Address;
  delegationManager: Address;
}

/** JSON key of each field, as Deploy.s.sol _writeJson() serializes it */
export const DEPLOYMENT_JSON_KEYS = {
  chainId: 'chainId',
  salt: 'salt',
  create2Deployer: 'create2Deployer',
  registry: 'RiparDeviceRegistry',
  enforcer: 'PulseCosignEnforcer',
  sentinel: 'RiparSentinel',
  relay: 'RiparReputationRelay',
  mockUsd: 'MockUSD',
  creForwarder: 'creForwarder',
  expectedWorkflowOwner: 'expectedWorkflowOwner',
  erc8004Identity: 'erc8004Identity',
  erc8004Reputation: 'erc8004Reputation',
  delegationManager: 'delegationManager',
} as const satisfies Record<keyof RiparDeployment, string>;

/**
 * Validates a deployments JSON (text or parsed object). Every address must be a 0x address with a valid (or absent)
 * EIP-55 checksum; the four Ripar contracts must be non-zero. `expectChainId` refuses a file of another chain.
 */
export function parseDeployment(json: string | Record<string, unknown>, expectChainId?: IntLike): RiparDeployment {
  let o: Record<string, unknown>;
  try {
    o = typeof json === 'string' ? (JSON.parse(json) as Record<string, unknown>) : json;
  } catch (e) {
    throw new ProtoError(`deployments: not JSON (${(e as Error).message})`);
  }
  if (o === null || typeof o !== 'object' || Array.isArray(o)) throw new ProtoError('deployments: not a JSON object');
  const addr = (k: string, nonZero: boolean): Address => {
    const v = o[k];
    if (typeof v !== 'string' || !isValidAddress(v)) throw new ProtoError(`deployments: ${k} is not a valid address`);
    const a = toChecksumAddress(v);
    if (nonZero && /^0x0{40}$/.test(a)) throw new ProtoError(`deployments: ${k} is the zero address`);
    return a;
  };
  const K = DEPLOYMENT_JSON_KEYS;
  const cid = o[K.chainId];
  if (typeof cid !== 'number' && typeof cid !== 'string') throw new ProtoError('deployments: chainId missing');
  const chainId = toInt(cid);
  if (expectChainId !== undefined && chainId !== toInt(expectChainId)) {
    throw new ProtoError(`deployments: chainId ${chainId} is not ${toInt(expectChainId)}`);
  }
  const saltV = o[K.salt];
  const salt = typeof saltV === 'string' ? toHex(toBytes(saltV, 32, 'deployments: salt')) : (`0x${'00'.repeat(32)}` as Hex);
  return {
    chainId,
    salt,
    create2Deployer: addr(K.create2Deployer, false),
    registry: addr(K.registry, true),
    enforcer: addr(K.enforcer, true),
    sentinel: addr(K.sentinel, true),
    relay: addr(K.relay, true),
    mockUsd: addr(K.mockUsd, false),
    creForwarder: addr(K.creForwarder, false),
    expectedWorkflowOwner: addr(K.expectedWorkflowOwner, false),
    erc8004Identity: addr(K.erc8004Identity, false),
    erc8004Reputation: addr(K.erc8004Reputation, false),
    delegationManager: addr(K.delegationManager, true),
  };
}

/**
 * The pair request fields of a deployment: chain, registry, DelegationManager, enforcer, sentinel, relay, plus the
 * vault (computeVaultAddress(K1)) and the optional clock / floors. Refuses a chain outside the firmware table and a
 * DelegationManager other than the one compiled into the firmware (the device would refuse both).
 */
export function pairFieldsFromDeployment(
  d: RiparDeployment,
  extra: Pick<PairFields, 'vault' | 'now' | 'minEpoch' | 'reopenNonce' | 'reqId' | 'uuidTag'> = {},
): PairFields {
  if (!FIRMWARE_CHAIN_IDS.includes(Number(d.chainId))) {
    throw new ProtoError(`chain ${d.chainId} is not in the firmware chain table (${FIRMWARE_CHAIN_IDS.join(', ')})`);
  }
  if (toChecksumAddress(toAddr(d.delegationManager)) !== DELEGATION_MANAGER) {
    throw new ProtoError(`DelegationManager ${d.delegationManager} is not the firmware's ${DELEGATION_MANAGER}`);
  }
  return {
    chainId: d.chainId,
    registry: d.registry,
    manager: d.delegationManager,
    enforcer: d.enforcer,
    sentinel: d.sentinel,
    relay: d.relay,
    ...extra,
  };
}
