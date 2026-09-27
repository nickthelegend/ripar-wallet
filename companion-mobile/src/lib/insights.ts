// Insights over the activity feed (pure: tested in test/flows.test.ts).
import type { FeedItem } from './feed';

export interface Insights {
  /** outgoing payments per day, oldest first (14 days) */
  daily: number[];
  total: number;
  byActor: { you: number; agentAuto: number; agentCosigned: number; denied: number };
}

/** counts, not sums: the feed mixes assets, and a sum across MON and mUSD would be a made-up number */
export function insightsOf(items: FeedItem[], now = Date.now() / 1000, days = 14): Insights {
  const daily = new Array<number>(days).fill(0);
  const byActor = { you: 0, agentAuto: 0, agentCosigned: 0, denied: 0 };
  let total = 0;
  for (const i of items) {
    const out = (i.kind === 'Payment' && i.subtitle === 'Co-signed on your Ripar') || i.kind === 'AutoSpend' || i.kind === 'HumanCosigned';
    if (i.kind === 'Verdict' && i.title === 'Denial filed') byActor.denied++;
    if (!out || i.at === null) continue;
    const ago = Math.floor((now - i.at) / 86400);
    if (ago < 0 || ago >= days) continue;
    daily[days - 1 - ago]!++;
    total++;
    if (i.actor === 'you') byActor.you++;
    else if (i.kind === 'AutoSpend') byActor.agentAuto++;
    else byActor.agentCosigned++;
  }
  return { daily, total, byActor };
}
