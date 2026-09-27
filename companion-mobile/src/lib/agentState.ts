// The agent service as the Agents tab sees it: health, the escalation inbox (polled while the tab is open: React
// Native has no EventSource), and "ask the agent to run" (one planner step). Everything the agent sends is parsed
// strictly (lib/agent.ts) and checked again before anything reaches the device.
import { useSyncExternalStore } from 'react';
import { type AgentHealth, type Escalation, type RunResult, agentClientOf } from './agent';
import { errorText } from './format';
import { store } from './store';

export interface AgentState {
  health: AgentHealth | null;
  items: Escalation[];
  rejected: { raw: unknown; error: string }[];
  error: string | null;
  loading: boolean;
  readAt: number | null;
  lastRun: (RunResult & { at: number }) | null;
}

let state: AgentState = { health: null, items: [], rejected: [], error: null, loading: false, readAt: null, lastRun: null };
const listeners = new Set<() => void>();
const set = (p: Partial<AgentState>) => {
  state = { ...state, ...p };
  for (const l of [...listeners]) l();
};

export async function pollAgent(): Promise<void> {
  const s = store.get().settings;
  if (!s.agentUrl) return set({ error: 'No agent URL (Settings > Network).', health: null, items: [] });
  set({ loading: true });
  const c = agentClientOf(s);
  try {
    const [health, esc] = await Promise.all([c.health().catch(() => null), c.escalations()]);
    set({ health, items: esc.items, rejected: esc.rejected, error: null, loading: false, readAt: Date.now() });
  } catch (e) {
    set({ error: errorText(e), loading: false, readAt: Date.now() });
  }
}

export async function runAgent(): Promise<RunResult> {
  const r = await agentClientOf(store.get().settings).run();
  set({ lastRun: { ...r, at: Date.now() } });
  void pollAgent();
  return r;
}

export function escalationById(id: string): Escalation | null {
  return state.items.find((e) => e.id === id) ?? null;
}

export function useAgent(): AgentState {
  return useSyncExternalStore(
    (l) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    () => state,
  );
}
