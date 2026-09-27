// In-process event bus behind GET /events (Server-Sent Events): the companion follows escalations and payments live.
import { EventEmitter } from 'node:events';
import { jsonSafe } from './util.js';

export type AgentEventType = 'log' | 'mandate' | 'escalation' | 'payment' | 'invoice' | 'run';

export interface AgentEvent {
  seq: number;
  type: AgentEventType;
  at: number;
  data: unknown;
}

export class EventBus {
  private readonly emitter = new EventEmitter();
  private seq = 0;
  /** the last events, replayed to a new subscriber that sends Last-Event-ID */
  readonly recent: AgentEvent[] = [];

  constructor(private readonly keep = 200) {
    this.emitter.setMaxListeners(100);
  }

  emit(type: AgentEventType, data: unknown): AgentEvent {
    const ev: AgentEvent = { seq: ++this.seq, type, at: Date.now(), data: jsonSafe(data) };
    this.recent.push(ev);
    if (this.recent.length > this.keep) this.recent.shift();
    this.emitter.emit('event', ev);
    return ev;
  }

  log(message: string, extra: Record<string, unknown> = {}): void {
    this.emit('log', { message, ...extra });
  }

  subscribe(fn: (ev: AgentEvent) => void): () => void {
    this.emitter.on('event', fn);
    return () => this.emitter.off('event', fn);
  }
}
