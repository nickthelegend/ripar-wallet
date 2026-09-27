// What firmware v1.2 refuses whatever it pinned at pairing (make_request.py firmware_refusal): Ripar contracts that
// differ from the ones compiled in for the chain, and a vault / delegator that is not the vault derived from its K1
// (docs/PROTOCOL.md 2.1 and 4). The rest of the pinned-context policy (the chain and the sentinel pinned at pairing,
// the epoch, PANIC FIRST, ...) depends on the device's context and is not simulated here.
import { type BytesLike, bytesEqual, toAddr, unhex } from './bytes.js';
import {
  FIRMWARE_CHAIN_IDS,
  FIRMWARE_MANAGER,
  FIRMWARE_PULSE_ENFORCER,
  FIRMWARE_REGISTRY,
  FIRMWARE_RELAY,
  type FirmwareTable,
  firmwareAddress,
} from './constants.js';
import { toChecksumAddress } from './hash.js';
import type { AnyRequest } from './requests.js';
import { computeVaultAddress } from './vault.js';

const eip = (b: Uint8Array): string => toChecksumAddress(b);

function differs(table: FirmwareTable, chain: bigint, v: Uint8Array | null): string | null {
  const want = firmwareAddress(table, chain);
  if (want === undefined || v === null || bytesEqual(v, unhex(want))) return null;
  return want;
}

/**
 * make_request firmware_refusal: why firmware v1.2 refuses this request regardless of its pairing (compiled-in
 * contracts, the vault derived from K1), or null. `k1Address` = the device's K1 (the vault checks need it). The texts
 * are make_request's (the device's own wording is longer, see docs/PROTOCOL.md 4).
 */
export function firmwareRefusal(q: AnyRequest, k1Address?: BytesLike | null): string | null {
  const vault = k1Address != null ? unhex(computeVaultAddress(toAddr(k1Address, 'k1Address'))) : null;
  if (q.kind === 'pair') {
    if (!FIRMWARE_CHAIN_IDS.some((c) => BigInt(c) === q.chainId)) return `UNSUPPORTED CHAIN ${q.chainId}`;
    const pins: [Uint8Array | null, FirmwareTable, string][] = [
      [q.registry, FIRMWARE_REGISTRY, 'REGISTRY'],
      [q.manager, FIRMWARE_MANAGER, 'DELEGATION MANAGER'],
      [q.enforcer, FIRMWARE_PULSE_ENFORCER, 'PULSE CO-SIGN ENFORCER'],
      [q.relay, FIRMWARE_RELAY, 'REPUTATION RELAY'],
    ];
    for (const [v, table, label] of pins) {
      const want = differs(table, q.chainId, v);
      if (want !== null) return `WRONG ${label}: ${eip(v!)} (firmware: ${want})`;
    }
    if (vault !== null && q.vault !== null && !bytesEqual(q.vault, vault)) {
      return `VAULT IS NOT THIS DEVICE'S VAULT: key 8 = ${eip(q.vault)}, K1 owns ${eip(vault)}`;
    }
  } else if (q.kind === 'cosign') {
    if (differs(FIRMWARE_PULSE_ENFORCER, q.chainId, q.enforcer) !== null) return `ENFORCER NOT PINNED: ${eip(q.enforcer)}`;
    if (vault !== null && !bytesEqual(q.delegator, vault)) {
      return `NOT THIS DEVICE'S VAULT: delegator ${eip(q.delegator)} (vault ${eip(vault)})`;
    }
  } else if (q.kind === 'mandate') {
    if (differs(FIRMWARE_MANAGER, q.chainId, q.manager) !== null) return `WRONG DELEGATION MANAGER: ${eip(q.manager)}`;
    if (vault !== null && !bytesEqual(q.delegator, vault)) {
      return `NOT THIS DEVICE'S VAULT: delegator ${eip(q.delegator)} (vault ${eip(vault)})`;
    }
  } else if (q.kind === 'deny') {
    if (differs(FIRMWARE_RELAY, q.chainId, q.relay) !== null) return `RELAY NOT PINNED: ${eip(q.relay)}`;
  }
  return null;
}
