// Deterministic planner (no API key, tests, demos): each step pays the first due invoice.
//
// It is DELIBERATELY GULLIBLE: when an invoice memo names another address to pay ("bank details changed, send to
// 0x..."), it passes that address as pay_to, exactly as a prompt-injected model would. That is the point of the demo:
// the code refuses to take the AUTO path for it, and the escalation's AI line, risk flag and claims (to = the
// invoice's payee of record, which the device checks against the calldata: AI claims MISMATCH) reveal the redirect on
// the device, where the human denies it.
import type { AgentService } from '../service.js';
import type { Planner, StepResult } from './index.js';
import { PlannerTools } from './tools.js';

const ADDRESS = /0x[0-9a-fA-F]{40}/g;

/** an address in the memo that differs from the payee of record (what an injected model would pay instead) */
export function memoRedirect(memo: string | undefined, payee: string): string | undefined {
  if (!memo) return undefined;
  for (const a of memo.match(ADDRESS) ?? []) if (a.toLowerCase() !== payee.toLowerCase()) return a;
  return undefined;
}

interface DueInvoice {
  id: string;
  vendor: string;
  payee_of_record: string;
  amount: string;
  token: string;
  memo_untrusted: string;
  recurring: boolean;
}

export class ScriptedPlanner implements Planner {
  readonly kind = 'scripted' as const;

  constructor(private readonly svc: AgentService) {}

  async step(): Promise<StepResult> {
    const startedAt = Date.now();
    const tools = new PlannerTools(this.svc, { planner: 'scripted', maxPayments: 1 });
    const due = (await tools.call('list_invoices', { only_due: true })) as DueInvoice[] | { error: string };
    if (!Array.isArray(due)) {
      return { planner: 'scripted', startedAt, finishedAt: Date.now(), actions: tools.actions, summary: 'could not list invoices', error: due.error };
    }
    const inv = due[0];
    if (!inv) {
      return { planner: 'scripted', startedAt, finishedAt: Date.now(), actions: tools.actions, summary: 'nothing is due' };
    }
    const redirect = memoRedirect(inv.memo_untrusted, inv.payee_of_record);
    const note = inv.recurring ? 'recurring invoice due' : 'invoice due';
    const res = (await tools.call('pay_invoice', {
      invoice_id: inv.id,
      ...(redirect ? { pay_to: redirect } : {}),
      note,
    })) as Record<string, unknown>;
    const summary =
      res.outcome === 'paid'
        ? `paid ${inv.id} (${inv.amount} ${inv.token}) on the AUTO path`
        : res.outcome === 'sent_to_human'
          ? `sent ${inv.id} to the human for a device co-sign: ${String(res.why)}`
          : `${inv.id}: ${String(res.reason ?? res.error ?? res.outcome)}`;
    return { planner: 'scripted', startedAt, finishedAt: Date.now(), actions: tools.actions, summary };
  }
}
