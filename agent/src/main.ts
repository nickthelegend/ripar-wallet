// Entry point: `npm start` (tsx src/main.ts) in agent/. Reads agent/.env, starts the HTTP API.
import { createApp, configWarnings } from './app.js';
import { loadConfig, loadDotEnv, publicConfig } from './config.js';

async function main(): Promise<void> {
  loadDotEnv();
  const config = loadConfig();
  for (const w of configWarnings(config)) console.warn(`warning: ${w}`);
  const app = await createApp(config);
  const url = await app.listen();
  console.log(`ripar agent ${app.svc.agent} on chain ${config.chainId}: ${url}`);
  console.log(JSON.stringify(publicConfig(config)));
  const m = app.svc.mandate();
  console.log(m ? `mandate ${m.delegationHash} (${m.status}) from vault ${m.vault}` : 'no mandate yet: POST /mandate from the companion');
  app.events.subscribe((ev) => {
    if (ev.type === 'log') console.log(`[${new Date(ev.at).toISOString()}] ${(ev.data as { message: string }).message}`);
  });
  const stop = (): void => {
    console.log('stopping');
    void app.close().then(() => process.exit(0));
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

main().catch((e: unknown) => {
  console.error(`ripar agent: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
});
