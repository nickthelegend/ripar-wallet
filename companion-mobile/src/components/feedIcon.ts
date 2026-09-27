import type { FeedItem } from '../lib/feed';

/** the round icon and tone of an activity row */
export function iconOf(i: FeedItem) {
  if (i.kind === 'TransferIn') return { icon: 'receive' as const, tone: 'good' as const };
  if (i.kind === 'Panicked' || i.kind === 'Revoked') return { icon: 'power' as const, tone: 'bad' as const };
  if (i.kind === 'LaneChanged') return { icon: 'refresh' as const, tone: 'info' as const };
  if (i.kind === 'Verdict' || i.kind === 'AgentShielded') return { icon: 'deny' as const, tone: 'warn' as const };
  if (i.actor === 'agent') return { icon: 'agents' as const, tone: 'info' as const };
  return { icon: 'send' as const, tone: 'signal' as const };
}
