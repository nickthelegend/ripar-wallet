// "Next on the device": one plain sentence, from the emulated device's live state, telling the user what to do with
// the SIGN key or the thumb now (docs/FIRMWARE.md §5 is the key table). Also turns the device's refusal reasons
// into advice for the companion user. Pure functions: tested in test/logic.test.ts.
import type { EmuState } from './emulator';

export type RoundKind = 'keys' | 'pair' | 'mandate' | 'cosign' | 'kill';

export interface GuideLine {
  text: string;
  tone: 'info' | 'warn' | 'bad' | 'good';
}

/** advice for a refusal the device showed (its REFUSED line or message screen), or null when there is none to add */
export function refusalHelp(reason: string): string | null {
  const r = reason.toUpperCase();
  if (/VAULT IS NOT THIS DEVICE'?S VAULT/.test(r)) {
    return "The device pins only the SimpleFactory vault of its own K1 (firmware v1.2 derives it: CREATE2, salt 0). Pair-request key 8 named another vault: the keys read in step 1 are not this device's. Read the device keys again on the Pair page (step 1), then pair (this companion leaves key 8 out, so the device pins its own vault).";
  }
  if (/NOT THIS DEVICE'?S VAULT|VAULT MISMATCH/.test(r)) {
    return "The request's delegator is not the vault this device derives from its K1. Pair this device on the Pair page (the companion then uses its derived vault) and prepare the mandate / co-sign again.";
  }
  if (/WRONG (REGISTRY|PULSE CO-?SIGN ENFORCER|REPUTATION RELAY|DELEGATION MANAGER)/.test(r)) {
    return 'Firmware v1.2 has the RiparDeviceRegistry, PulseCosignEnforcer, relay and DelegationManager compiled in and refuses any other. This deployments JSON names other addresses: load the deployment made by contracts/script/Deploy.s.sol (CREATE2; on Monad testnet or an anvil fork of it it lands at the compiled-in addresses) on the Connect page, then pair again.';
  }
  if (/DIFFERS FROM FIRMWARE TABLE/.test(r)) {
    return 'The device pinned a contract (from an older pairing) that is not the one compiled into its firmware: pair it again on the Pair page.';
  }
  if (/UNSUPPORTED CHAIN/.test(r)) return 'The device knows only Monad testnet (10143) and Monad (143): pick one of them on the Connect page.';
  if (/PAIRING LOST/.test(r)) {
    return 'The device dropped its pinned context (older layout, or not its vault): pair it again, with the on-chain panic floor and reopen nonce (the Pair page reads and sends them).';
  }
  if (/PANIC FIRST/.test(r)) {
    return 'Mandates this device signed may still be live and a panic has not covered them: moving the device to another chain now would leave them out of its PANIC. On Home hold SIGN for 5 s (PANIC; every mandate it signed dies), relay that QR on the Kill switch page, then repeat this step. A revoke is not enough.';
  }
  if (/REVOKE FIRST/.test(r)) {
    // firmware v1.1 wording (v1.2 says PANIC FIRST)
    return 'The device still remembers a mandate: revoke it (Kill switch page, device menu > REVOKE) and relay it, then repeat this step.';
  }
  if (/STALE|EPOCH/.test(r)) {
    return "The epoch is below the device's panic floor: relay the device's last PANIC QR, reload the epoch on the Mandate page and prepare the mandate again.";
  }
  if (/NOT PAIRED|UNPAIRED/.test(r)) return 'The device is not paired yet: pair it on the Pair page first.';
  if (/EXPIRED|EXPIRY/.test(r)) return "Check the device clock against this computer's; build the request again for a fresh expiry.";
  if (/UNKNOWN CALLDATA/.test(r)) return 'The device only signs native sends and ERC-20 transfer / approve / transferFrom calls.';
  if (/CHAIN/.test(r)) return 'The request names another chain than the one the device pinned at pairing.';
  if (/NOT PINNED|PINNED/.test(r)) return 'The request names a contract the device did not pin at pairing: check the deployments JSON on the Connect page and pair again if it changed.';
  return null;
}

/**
 * The next action on the emulated device for a round of kind `round`. `hasRequest`: the companion is showing a
 * request QR (Fig. A) for the device to scan.
 */
export function deviceGuide(s: EmuState, round: RoundKind, hasRequest: boolean, thumbOn: boolean): GuideLine {
  const rv = s.review;
  switch (s.screen) {
    case 'home':
      if (round === 'keys') return { text: 'Hold SIGN for 2 s until the screen says RELEASE = PAIRING QR, then release. (Keep holding to 5 s and it PANICs.)', tone: 'info' };
      if (round === 'kill') {
        return {
          text: 'PANIC: hold SIGN 5 s on Home. REVOKE / REOPEN: hold 2 s and release (pairing QR), hold 2 s again for the device menu.',
          tone: 'info',
        };
      }
      return hasRequest ? { text: 'Press SIGN once to scan the request in Fig. A.', tone: 'info' } : { text: 'Waiting for a request.', tone: 'info' };
    case 'homeHold':
      return round === 'kill'
        ? { text: 'Release now for the pairing QR (then hold 2 s for the menu), or keep holding to 5 s to PANIC.', tone: 'warn' }
        : { text: 'Release SIGN now for the pairing QR. Keep holding to 5 s and the device PANICs (kills every mandate).', tone: 'warn' };
    case 'scan':
      return hasRequest
        ? { text: `Scanning Fig. A${s.scan.seqLen > 1 ? ` (${s.scan.received} of ${s.scan.seqLen} parts)` : ''}. Hold SIGN 2 s to cancel.`, tone: 'info' }
        : { text: 'The device is scanning, but this step shows no request: hold SIGN 2 s to cancel.', tone: 'warn' };
    case 'review': {
      if (!rv) return { text: 'Review: press SIGN for the next page.', tone: 'info' };
      if (!rv.ok) {
        const help = refusalHelp(rv.refusal);
        return { text: `The device REFUSED this request: ${rv.refusal}. Press SIGN to go Home.${help ? ` ${help}` : ''}`, tone: 'bad' };
      }
      const d = s.display.kind === 'review' ? s.display : null;
      let page = '';
      if (d && d.totalRows > d.rowsShown) {
        // each press moves the page by rowsShown - 1 rows; the last page is clamped to the end
        const step = Math.max(1, d.rowsShown - 1);
        const pages = Math.max(1, Math.ceil((d.totalRows - 1) / step));
        const n = d.moreBelow ? Math.min(pages, Math.floor(d.firstRow / step) + 1) : pages;
        page = `Page ${n} of ${pages}: `;
      }
      if (rv.job === 'deny') {
        return rv.allSeen
          ? { text: 'Deny review, last page: press SIGN to sign the DENY (no pulse needed). Hold 2 s to cancel.', tone: 'warn' }
          : { text: `${page}DENY + REPORT AGENT review. Press SIGN for the next page; the deny is signed on the last page.`, tone: 'warn' };
      }
      if (!rv.allSeen) {
        const deny = rv.job === 'cosign' ? ' Hold 2 s to deny instead.' : ' Hold 2 s to cancel.';
        return { text: `${page}${page ? 'read' : 'Read'} every line, then press SIGN for the next page.${deny}`, tone: 'info' };
      }
      return { text: 'Last page: press SIGN to continue to the pulse check.', tone: 'info' };
    }
    case 'pulse':
      return thumbOn
        ? { text: `Thumb on the sensor: hold still until PULSE OK${s.pulse.finger ? ` (${s.pulse.beats}/${s.pulse.minBeats} beats)` : ''}. Pressing SIGN now does nothing.`, tone: 'info' }
        : { text: 'Click "Place thumb" (the pulse sensor) and wait for PULSE OK.', tone: 'warn' };
    case 'armed':
      return { text: 'PULSE OK: press SIGN now to sign.', tone: 'good' };
    case 'qr':
      if (s.qr?.signed === false && round !== 'keys') {
        return { text: 'The device shows its keys-only pairing QR. Press SIGN to go Home (hold 2 s there for the device menu).', tone: 'info' };
      }
      // with a request on show, an answer to IT would already have been read (the exchange ends): this QR is older
      if (hasRequest) return { text: 'The device still shows an earlier answer: press SIGN once to go Home, then press again to scan Fig. A.', tone: 'info' };
      return { text: 'The device shows its answer; this page reads it. Press SIGN afterwards to go Home.', tone: 'good' };
    case 'pairQr':
      return round === 'keys'
        ? { text: 'The device shows its keys; this page reads them.', tone: 'good' }
        : round === 'kill'
          ? { text: 'Hold SIGN 2 s for the device menu (REVOKE / REOPEN), or press to go Home.', tone: 'info' }
          : { text: 'The device shows its keys-only pairing QR: press SIGN to go Home, then press again to scan.', tone: 'info' };
    case 'menu':
      return { text: 'Device menu: press SIGN for the next item (REVOKE, REOPEN, BACK), hold 2 s to select it.', tone: 'info' };
    case 'message': {
      const m = s.message;
      const help = m ? refusalHelp(`${m.title} ${m.body}`) : null;
      return { text: `The device says: ${m ? `${m.title}${m.body ? ` - ${m.body}` : ''}` : 'a message'}. Press SIGN to go Home.${help ? ` ${help}` : ''}`, tone: m?.color === 'bad' ? 'bad' : 'warn' };
    }
    case 'fail':
      return { text: 'The device self-test failed: nothing can be signed. Reset the emulator on the Device page.', tone: 'bad' };
    default:
      return { text: '', tone: 'info' };
  }
}
