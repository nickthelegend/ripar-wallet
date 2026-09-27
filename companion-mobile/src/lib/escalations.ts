// Display helpers for the agent's escalations (ported from companion/src/screens/Inbox.tsx).
import { decodeErc20, firmwareToken, nativeCoin, toChecksumAddress } from '@ripar/protocol';
import type { Escalation } from './agent';
import { amountText } from './format';
import { type AppState, currentAgentMandate } from './store';

export const REASON_TEXT: Record<string, string> = {
  'payee-redirect': 'the payee differs from the invoice of record',
  'chain-human-required': 'the enforcer refused the automatic path',
  'chain-lane-closed': 'the sentinel closed the agent lane',
  'not-meterable': 'not a payment the caps can meter',
  'lane-closed': 'the sentinel closed the agent lane',
  'per-tx-cap': 'above the per-payment cap',
  'new-payee': 'a payee you never approved',
  'period-cap': 'the period budget is used up',
  other: 'the agent asks for a co-sign',
};

export function describeEscalation(e: Escalation, s: AppState): { amount: string; payee: string; kind: string } {
  const c = decodeErc20(e.call.callData);
  const chain = Number(e.chainId);
  if (c.kind === 'none') {
    const n = nativeCoin(chain);
    return { amount: amountText(e.call.value, n?.decimals ?? 18, n?.symbol ?? 'MON'), payee: e.call.target, kind: 'native send' };
  }
  if (c.kind === 'unknown') return { amount: 'unknown call', payee: e.call.target, kind: 'unknown calldata' };
  const listed = firmwareToken(chain, e.call.target);
  const m = currentAgentMandate(s);
  const meta = listed
    ? { d: listed.decimals, s: listed.symbol }
    : m && m.token.toLowerCase() === e.call.target.toLowerCase()
      ? { d: m.tokenDecimals, s: m.tokenSymbol }
      : { d: null, s: null };
  return { amount: amountText(c.amount, meta.d, meta.s), payee: toChecksumAddress(c.to), kind: c.kind };
}

