// The canonical Ripar vault of a K1 owner, derived twice: by @ripar/protocol (the formula firmware v1.2 pins) and by
// @metamask/smart-accounts-kit's counterfactual account data (Hybrid, deployParams [K1, [], [], []], salt 0).
// The companion deploys with the kit's factory + factoryData, and only when both derivations agree.
import { getAddress } from 'viem';
import { SIMPLE_FACTORY, computeVaultAddress, toChecksumAddress, vaultFactoryData } from '@ripar/protocol';

type Address = `0x${string}`;
type Hex = `0x${string}`;

export interface VaultDerivation {
  owner: Address;
  /** @ripar/protocol computeVaultAddress (what the device pins) */
  address: Address;
  /** smart-accounts-kit getCounterfactualAccountData */
  kitAddress: Address;
  factory: Address;
  factoryData: Hex;
  protocolFactoryData: Hex;
  /** both derivations agree on address and factory data, and the factory is the canonical SimpleFactory */
  matches: boolean;
}

export async function deriveVault(owner: string, chainId: number): Promise<VaultDerivation> {
  const k1 = toChecksumAddress(owner);
  // loaded on demand: the kit is large and only the Vault page needs it
  const [{ Implementation, getSmartAccountsEnvironment }, { getCounterfactualAccountData }] = await Promise.all([
    import('@metamask/smart-accounts-kit'),
    import('@metamask/smart-accounts-kit/utils'),
  ]);
  const env = getSmartAccountsEnvironment(chainId);
  const kit = await getCounterfactualAccountData({
    factory: env.SimpleFactory,
    implementations: env.implementations,
    implementation: Implementation.Hybrid,
    deployParams: [k1, [], [], []],
    deploySalt: '0x',
  });
  const address = computeVaultAddress(k1);
  const protocolFactoryData = vaultFactoryData(k1);
  const kitAddress = getAddress(kit.address);
  const factory = getAddress(env.SimpleFactory);
  return {
    owner: k1,
    address,
    kitAddress,
    factory,
    factoryData: kit.factoryData,
    protocolFactoryData,
    matches: kitAddress === address && kit.factoryData.toLowerCase() === protocolFactoryData.toLowerCase() && factory === SIMPLE_FACTORY,
  };
}
