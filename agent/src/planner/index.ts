// Planners: one step = look at the due invoices and propose payments through the tools.
//   - QwenPlanner: Qwen tool-calling (OpenAI-compatible API, non-streaming) when QWEN_API_KEY is set.
//   - ScriptedPlanner: deterministic, used without an API key and in tests.
import type { QwenConfig } from '../config.js';
import type { AgentService } from '../service.js';
import { QwenPlanner, type ChatCompletionsLike } from './qwen.js';
import { ScriptedPlanner } from './scripted.js';
import type { PlannerAction } from './tools.js';

export interface StepResult {
  planner: string;
  startedAt: number;
  finishedAt: number;
  actions: PlannerAction[];
  summary: string;
  rounds?: number;
  error?: string;
}

export interface Planner {
  readonly kind: 'qwen' | 'scripted';
  step(instruction?: string): Promise<StepResult>;
}

export function createPlanner(svc: AgentService, qwen: QwenConfig, maxPayments: number, client?: ChatCompletionsLike): Planner {
  if (qwen.apiKey || client) return new QwenPlanner(svc, qwen, maxPayments, client);
  return new ScriptedPlanner(svc);
}

export { QwenPlanner, ScriptedPlanner };
export type { ChatCompletionsLike };
