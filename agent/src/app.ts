// Wiring: config -> signer -> chain -> store -> service -> planner -> HTTP server.
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { http, type Transport } from 'viem';
import { ViemChain, type RiparChain } from './chain.js';
import { configWarnings, type AgentConfig } from './config.js';
import { EventBus } from './events.js';
import { createPlanner, type ChatCompletionsLike, type Planner, type StepResult } from './planner/index.js';
import { createAgentServer } from './server.js';
import { AgentService } from './service.js';
import { chainFor, createSigner, type Signer } from './signer.js';
import { AgentStore } from './store.js';

export interface AgentApp {
  config: AgentConfig;
  signer?: Signer;
  chain: RiparChain;
  store: AgentStore;
  events: EventBus;
  svc: AgentService;
  planner: Planner;
  server: Server & { runStep: (instruction?: string) => Promise<StepResult> };
  /** listens on config.host:config.port (0 = a free port); returns the base URL */
  listen(): Promise<string>;
  close(): Promise<void>;
}

export interface AppOptions {
  /** a prebuilt chain (tests: a fake) instead of ViemChain */
  chain?: RiparChain;
  transport?: Transport;
  chatClient?: ChatCompletionsLike;
  /** skip the RPC chain-id check */
  skipChainCheck?: boolean;
}

export async function createApp(config: AgentConfig, opts: AppOptions = {}): Promise<AgentApp> {
  let signer: Signer | undefined;
  let chain: RiparChain;
  if (opts.chain) chain = opts.chain;
  else {
    const c = chainFor(config.chainId, config.rpcUrl);
    const transport = opts.transport ?? http(config.rpcUrl, { retryCount: 2, timeout: 30_000 });
    signer = createSigner(config.signer, c, transport);
    chain = new ViemChain({
      chain: c,
      transport,
      signer,
      manager: config.deployment.delegationManager,
      enforcer: config.deployment.enforcer,
      gasMarginPercent: config.gasMarginPercent,
    });
  }
  if (!opts.skipChainCheck) {
    const id = await chain.getChainId();
    if (id !== config.chainId) throw new Error(`RPC_URL serves chain ${id}, CHAIN_ID is ${config.chainId}`);
  }
  const store = new AgentStore(config.dataDir, config.invoicesPath, config.invoicesExamplePath);
  const events = new EventBus();
  const svc = new AgentService({ config, chain, store, events });
  await svc.recover();
  const planner = createPlanner(svc, config.qwen, config.maxPaymentsPerStep, opts.chatClient);
  const server = createAgentServer({ svc, planner, config });
  let timer: NodeJS.Timeout | undefined;
  return {
    config,
    ...(signer ? { signer } : {}),
    chain,
    store,
    events,
    svc,
    planner,
    server,
    listen: () =>
      new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(config.port, config.host, () => {
          const a = server.address() as AddressInfo;
          if (config.autoRunSeconds > 0) {
            timer = setInterval(() => {
              server.runStep().catch((e: unknown) => events.log(`planner step failed: ${String(e)}`));
            }, config.autoRunSeconds * 1000);
            timer.unref();
          }
          resolve(`http://${a.family === 'IPv6' ? `[${a.address}]` : a.address}:${a.port}`);
        });
      }),
    close: () =>
      new Promise((resolve) => {
        if (timer) clearInterval(timer);
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}

export { configWarnings };
