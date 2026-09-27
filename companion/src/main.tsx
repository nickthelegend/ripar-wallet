import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { DeviceProvider } from './device/DeviceContext';
import { devStackState, loadDevStack } from './lib/devstack';
import { store } from './lib/store';
import './styles/app.css';

async function start(): Promise<void> {
  // `?devstack`: take the Connect settings of the local dev stack (scripts/dev-stack.sh), then drop the parameter
  try {
    const s = await loadDevStack(window.location);
    if (s) {
      store.setSettings(s);
      devStackState.appliedAt = Date.now();
      history.replaceState(null, '', `${location.pathname}${location.hash || '#/connect'}`);
    }
  } catch (e) {
    console.warn((e as Error).message);
  }
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <DeviceProvider>
        <App />
      </DeviceProvider>
    </StrictMode>,
  );
}

void start();
