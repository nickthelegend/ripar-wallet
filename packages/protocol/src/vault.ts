// The canonical Ripar vault: a MetaMask HybridDeleGator (delegation-framework v1.3.0) owned by the device's K1 alone,
// behind an ERC1967Proxy deployed by the canonical SimpleFactory (contracts/.work/vault-derivation.md). Firmware v1.2
// derives the same address from K1 and refuses any other vault. It equals @metamask/smart-accounts-kit 2.0.0
// getCounterfactualAccountData({implementation: Hybrid, deployParams: [K1, [], [], []], deploySalt: '0x'}).
import { encodeAbiParameters, encodeFunctionData, getContractAddress, keccak256 as viemKeccak } from 'viem';
import { type Address, type BytesLike, type Hex, concatBytes, toAddr, toBytes, toHex, unhex } from './bytes.js';
import { HYBRID_DELEGATOR_IMPL, SIMPLE_FACTORY } from './constants.js';
import { toChecksumAddress } from './hash.js';
import { ERC1967_PROXY_CREATION_CODE } from './proxy-bytecode.js';

/** HybridDeleGator.initialize(address _owner, string[] _keyIds, uint256[] _xValues, uint256[] _yValues) */
export const HYBRID_INITIALIZE_ABI = [
  {
    type: 'function',
    name: 'initialize',
    stateMutability: 'nonpayable',
    inputs: [
      { name: '_owner', type: 'address' },
      { name: '_keyIds', type: 'string[]' },
      { name: '_xValues', type: 'uint256[]' },
      { name: '_yValues', type: 'uint256[]' },
    ],
    outputs: [],
  },
] as const;

/** the Ripar vault's deploy salt: bytes32(0) (the kit's deploySalt "0x", left-padded) */
export const VAULT_DEPLOY_SALT: Hex = `0x${'00'.repeat(32)}`;

export interface VaultDerivationOptions {
  /** default SIMPLE_FACTORY */
  factory?: BytesLike;
  /** default HYBRID_DELEGATOR_IMPL */
  implementation?: BytesLike;
  /** default bytes32(0); a shorter value is left-padded to 32 bytes like the kit */
  salt?: BytesLike;
}

/** initialize(K1, [], [], []): the proxy's init call (EOA owner only, no P-256 owners) */
export function vaultInitCalldata(owner: BytesLike): Hex {
  return encodeFunctionData({
    abi: HYBRID_INITIALIZE_ABI,
    functionName: 'initialize',
    args: [toChecksumAddress(toAddr(owner, 'owner')), [], [], []],
  });
}

/** ERC1967Proxy creation code ‖ abi.encode(address implementation, bytes initcode) */
export function vaultCreationCode(owner: BytesLike, opts: VaultDerivationOptions = {}): Hex {
  const impl = toChecksumAddress(toAddr(opts.implementation ?? HYBRID_DELEGATOR_IMPL, 'implementation'));
  const args = encodeAbiParameters([{ type: 'address' }, { type: 'bytes' }], [impl, vaultInitCalldata(owner)]);
  return toHex(concatBytes(unhex(ERC1967_PROXY_CREATION_CODE), unhex(args)));
}

/** keccak256 of the vault's creation code (the CREATE2 init code hash) */
export function vaultInitCodeHash(owner: BytesLike, opts: VaultDerivationOptions = {}): Hex {
  return viemKeccak(vaultCreationCode(owner, opts));
}

function salt32(s: BytesLike | undefined): Hex {
  if (s === undefined) return VAULT_DEPLOY_SALT;
  const b = toBytes(s, null, 'salt');
  if (b.length > 32) throw new RangeError('salt longer than 32 bytes');
  const out = new Uint8Array(32);
  out.set(b, 32 - b.length);
  return toHex(out);
}

/**
 * The counterfactual vault address of a K1 owner:
 * address(keccak256(0xff ‖ SimpleFactory ‖ bytes32(0) ‖ keccak256(creation code))[12:]), EIP-55.
 * Pin it at pairing (pair key 8) and use it as the mandate delegator / co-sign key 5.
 */
export function computeVaultAddress(owner: BytesLike, opts: VaultDerivationOptions = {}): Address {
  const addr = getContractAddress({
    opcode: 'CREATE2',
    from: toChecksumAddress(toAddr(opts.factory ?? SIMPLE_FACTORY, 'factory')),
    salt: salt32(opts.salt),
    bytecode: vaultCreationCode(owner, opts),
  });
  return toChecksumAddress(addr);
}

/** SimpleFactory.deploy(bytes bytecode, bytes32 salt) calldata (ERC-4337 factoryData of the vault) */
export const SIMPLE_FACTORY_DEPLOY_ABI = [
  {
    type: 'function',
    name: 'deploy',
    stateMutability: 'nonpayable',
    inputs: [
      { name: '_bytecode', type: 'bytes' },
      { name: '_salt', type: 'bytes32' },
    ],
    outputs: [{ name: 'addr_', type: 'address' }],
  },
] as const;

export function vaultFactoryData(owner: BytesLike, opts: VaultDerivationOptions = {}): Hex {
  return encodeFunctionData({
    abi: SIMPLE_FACTORY_DEPLOY_ABI,
    functionName: 'deploy',
    args: [vaultCreationCode(owner, opts), salt32(opts.salt)],
  });
}
