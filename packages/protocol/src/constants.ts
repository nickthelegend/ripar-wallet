// Canonical addresses and chain facts shared by the companion, the agent and the tests, including the Ripar contracts
// compiled into firmware v1.2 (make_request.py RIPAR_COSIGN / RIPAR_REGISTRY / RIPAR_RELAY, firmware src/enforcers.cpp):
// CREATE2 addresses of the bytecode frozen for contracts v1.2. The RiparSentinel is not compiled in (its address depends
// on the CRE workflow owner): read it from a deployments JSON (deployments.ts) or from configuration.
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

/** firmware v1.2 compiled-in Ripar PulseCosignEnforcer (CREATE2, the same on 10143 and 143) */
export const PULSE_COSIGN_ENFORCER: Address = '0x64d61fe5438981DC803ED61250FEf024617ae7eE';
/** firmware v1.2 compiled-in RiparDeviceRegistry (CREATE2, the same on 10143 and 143) */
export const RIPAR_DEVICE_REGISTRY: Address = '0xA08a47c9d645926615CF04D69b7a048133F68c9f';

/** chain -> address table of a contract compiled into the firmware; a chain missing = not compiled in */
export type FirmwareTable = Readonly<Record<string, Address>>;

/** firmware v1.2 (src/enforcers.cpp) PulseCosignEnforcer per chain: pair key 5 / co-sign key 3 / pulse caveat */
export const FIRMWARE_PULSE_ENFORCER: FirmwareTable = { '10143': PULSE_COSIGN_ENFORCER, '143': PULSE_COSIGN_ENFORCER };
/** firmware v1.2 RiparDeviceRegistry per chain: pair key 3 (the BindDevice domain) */
export const FIRMWARE_REGISTRY: FirmwareTable = { '10143': RIPAR_DEVICE_REGISTRY, '143': RIPAR_DEVICE_REGISTRY };
/**
 * firmware v1.2 RiparReputationRelay per chain: pair key 7 / deny key 3. Other constructor arguments per chain (the
 * chain's ERC-8004 registries), all public constants (contracts/test/FirmwarePins.t.sol recomputes both).
 */
export const FIRMWARE_RELAY: FirmwareTable = {
  '10143': '0xE433dCA75CA6cd730b1006F51A26208B000eA9E2',
  '143': '0x108BA102F7D0915f51c93F128b96Bd24F647f06d',
};
/** the MetaMask DelegationManager compiled into the firmware per chain: pair key 4 / mandate key 3 */
export const FIRMWARE_MANAGER: FirmwareTable = { '10143': DELEGATION_MANAGER, '143': DELEGATION_MANAGER };

/** the address of `table` compiled in for `chainId`, or undefined */
export function firmwareAddress(table: FirmwareTable, chainId: number | bigint | string): Address | undefined {
  return table[String(chainId)];
}
