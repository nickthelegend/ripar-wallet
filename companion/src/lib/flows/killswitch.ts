// Device-initiated messages (docs/PROTOCOL.md §4): ripar-revoke, ripar-panic, ripar-reopen. The device signs them
// for the contracts it pinned at pairing; the companion verifies each one against that pinned context and the P1 key,
// then relays it (anyone may: the signature is the authorization).
import { type VerifyReport, ProtoError, expectVerified, parseResponse } from '@ripar/protocol';
import { type WriteRequest, panicWrite, reopenWrite, revokeWrite } from '../chain';
import type { PairedDevice } from '../store';

export const KILL_TYPES = ['ripar-revoke', 'ripar-panic', 'ripar-reopen'] as const;
export type KillType = (typeof KILL_TYPES)[number];

export interface KillSwitchMessage {
  type: KillType;
  report: VerifyReport;
  write: WriteRequest;
  /** one line for the user: what relaying it does */
  effect: string;
}

export function acceptKillSwitch(ur: string, device: PairedDevice): KillSwitchMessage {
  const p = device.pinned;
  const rep = expectVerified(
    parseResponse(ur, {
      p1Key: device.p1Key,
      pinned: { chainId: p.chainId, enforcer: p.enforcer, sentinel: p.sentinel, relay: p.relay },
    }),
  );
  switch (rep.type) {
    case 'ripar-revoke':
      return {
        type: rep.type,
        report: rep,
        write: revokeWrite(p.enforcer, device.px, device.py, rep.fields.delegationHash, rep.fields.rs),
        effect: `Revokes mandate ${rep.fields.delegationHash}: the agent can no longer redeem it.`,
      };
    case 'ripar-panic':
      return {
        type: rep.type,
        report: rep,
        write: panicWrite(p.enforcer, device.px, device.py, rep.fields.minEpoch, rep.fields.rs),
        effect: `Raises the device's min epoch to ${rep.fields.minEpoch}: every mandate with a lower epoch dies at once.`,
      };
    case 'ripar-reopen':
      if (rep.fields.vault !== p.vault) throw new ProtoError(`the reopen names vault ${rep.fields.vault}, not your vault ${p.vault}`);
      return {
        type: rep.type,
        report: rep,
        write: reopenWrite(p.sentinel, rep.fields.vault, rep.fields.nonce, rep.fields.rs),
        effect: `Reopens the AUTO lane of your vault (nonce ${rep.fields.nonce}). Relay it now: it stays valid until a higher nonce lands.`,
      };
    default:
      throw new ProtoError(`${rep.type} is not a kill-switch message`);
  }
}
