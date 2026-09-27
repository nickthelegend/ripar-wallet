// Canonical addresses and chain facts shared by the companion, the agent and the tests. Ripar's own contracts
// (registry, enforcer, sentinel, relay) are NOT here: their addresses are not final, read them from a deployments
// JSON (deployments.ts) or from configuration.
import type { Address } from './bytes.js';

/** Monad testnet */
export const MONAD_TESTNET_CHAIN_ID = 10143;
/** Monad mainnet */
export const MONAD_MAINNET_CHAIN_ID = 143;
/** the firmware chain table (docs/PROTOCOL.md §4 pair key 2): the device refuses any other chain */
export const FIRMWARE_CHAIN_IDS: readonly number[] = [MONAD_TESTNET_CHAIN_ID, MONAD_MAINNET_CHAIN_ID];

/**
 * MetaMask delegation-framework v1.3.0 DelegationManager, the same on 10143 and 143 and compiled into the firmware
 * (pair key 4 must equal it; when key 4 is absent the device pins it).
 */
export const DELEGATION_MANAGER: Address = '0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3';
/** MetaMask SimpleFactory (CREATE2 deployer of the vault proxy), 10143 and 143 */
export const SIMPLE_FACTORY: Address = '0x69Aa2f9fe1572F1B640E1bbc512f5c3a734fc77c';
/** MetaMask HybridDeleGator implementation v1.3.0, 10143 and 143 */
export const HYBRID_DELEGATOR_IMPL: Address = '0x48dBe696A4D990079e039489bA2053B36E8FFEC4';
/** ERC-4337 EntryPoint v0.7 */
export const ENTRY_POINT_V07: Address = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';
/** the framework's ANY_DELEGATE (a mandate may not use it: the device refuses) */
export const ANY_DELEGATE: Address = '0x0000000000000000000000000000000000000a11';

/** ERC-8004 registries on Monad testnet (10143) */
export const ERC8004_TESTNET = {
  identity: '0x8004A818BFB912233c491871b3d84c89A494BD9e',
  reputation: '0x8004B663056A597Dffe9eCcC1965A193B7388713',
} as const satisfies Record<string, Address>;
