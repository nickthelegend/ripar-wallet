// The shell: running header (network, device, kill switch), the contents rail (a manual's table of contents with dot
// leaders to each section's state) and the hash-routed pages.
import { type ReactNode, useEffect, useRef, useState } from 'react';
import { Icon } from './components/Icon';
import { EmulatorMark } from './components/ui';
import { useDevice } from './device/DeviceContext';
import { NETWORKS } from './lib/networks';
import { useSetupStatus } from './lib/setup';
import { currentMandate, deploymentOf, store, useStore } from './lib/store';
import { About } from './screens/About';
import { Activity } from './screens/Activity';
import { Connect } from './screens/Connect';
import { Device } from './screens/Device';
import { Inbox } from './screens/Inbox';
import { KillSwitch } from './screens/KillSwitch';
import { Mandate } from './screens/Mandate';
import { Pair } from './screens/Pair';
import { Vault } from './screens/Vault';

export type Route = 'connect' | 'device' | 'pair' | 'vault' | 'mandate' | 'inbox' | 'kill' | 'activity' | 'about';

const SETUP: { id: Route; title: string }[] = [
  { id: 'connect', title: 'Connect' },
  { id: 'device', title: 'Device' },
  { id: 'pair', title: 'Pair' },
  { id: 'vault', title: 'Vault' },
  { id: 'mandate', title: 'Mandate' },
];
const OPERATION: { id: Route; title: string }[] = [
  { id: 'inbox', title: 'Inbox' },
  { id: 'kill', title: 'Kill switch' },
  { id: 'activity', title: 'Activity' },
];
const REFERENCE: { id: Route; title: string }[] = [{ id: 'about', title: 'About and proof' }];
const ALL = [...SETUP, ...OPERATION, ...REFERENCE];

function routeOf(hash: string): Route {
  const r = hash.replace(/^#\/?/, '').split(/[/?]/)[0] as Route;
  return ALL.some((x) => x.id === r) ? r : 'connect';
}

function useRoute(): Route {
  const [r, setR] = useState<Route>(() => routeOf(location.hash));
  useEffect(() => {
    const f = () => setR(routeOf(location.hash));
    window.addEventListener('hashchange', f);
    return () => window.removeEventListener('hashchange', f);
  }, []);
  return r;
}

function useTheme() {
  const theme = useStore((s) => s.settings.theme);
  useEffect(() => {
    const el = document.documentElement;
    if (theme === 'system') el.removeAttribute('data-theme');
    else el.setAttribute('data-theme', theme);
  }, [theme]);
  return theme;
}

type TocState = { text: string; tone?: 'done' | 'next' | 'alert' };

/** which setup steps are really done: from chain reads where the chain is the truth (registry, vault code, funds) */
export function useSetupDone(): Record<string, boolean> {
  const s = useStore((x) => x);
  const dev = useDevice();
  const chain = useSetupStatus();
  const dep = deploymentOf(s.settings);
  const m = currentMandate(s);
  return {
    connect: !!dep.deployment,
    device: dev.mode === 'hardware' || dev.emulatorStatus === 'ready',
    pair: !!s.device && chain.registered === true,
    vault: !!s.device && chain.vaultDeployed === true && chain.vaultFunded === true,
    mandate: !!m && !!m.sentToAgentAt && chain.mandateLive !== false,
  };
}

function useTocStates(): Record<Route, TocState> {
  const s = useStore((x) => x);
  const dev = useDevice();
  const chain = useSetupStatus();
  const dep = deploymentOf(s.settings);
  const m = currentMandate(s);
  const setupDone = useSetupDone();
  const next = SETUP.find((x) => !setupDone[x.id])?.id;
  const st = (id: Route, doneText: string, partial?: string): TocState =>
    setupDone[id]
      ? { text: doneText, tone: 'done' }
      : id === next
        ? { text: partial ?? 'next', tone: 'next' }
        : partial
          ? { text: partial }
          : { text: '' };
  const handled = Object.keys(s.inbox).length;
  const waiting = Object.values(s.work).filter((w) => w.answer && !w.agentAt).length;
  return {
    connect: dep.error ? { text: 'check', tone: 'alert' } : st('connect', 'ready'),
    device: st('device', dev.mode === 'emulator' ? 'emulator' : 'hardware'),
    pair: st('pair', 'registered', s.device ? (chain.registered === false ? 'register' : undefined) : undefined),
    vault: st(
      'vault',
      'funded',
      s.device ? (chain.vaultDeployed === false ? 'deploy' : chain.vaultDeployed && chain.vaultFunded === false ? 'fund' : undefined) : undefined,
    ),
    mandate: m && chain.mandateLive === false ? { text: 'dead', tone: 'alert' } : st('mandate', 'signed', m && !m.sentToAgentAt ? 'send' : undefined),
    inbox: waiting ? { text: `${waiting} to deliver`, tone: 'alert' } : { text: handled ? `${handled} answered` : '' },
    kill: { text: '' },
    activity: { text: '' },
    about: { text: '' },
  };
}

function Toc({ route, onNavigate }: { route: Route; onNavigate: () => void }) {
  const states = useTocStates();
  const group = (title: string, items: { id: Route; title: string }[], numbered: boolean) => (
    <>
      <h2>{title}</h2>
      <ol>
        {items.map((it, i) => (
          <li key={it.id}>
            <a href={`#/${it.id}`} aria-current={route === it.id ? 'page' : undefined} onClick={onNavigate}>
              <span className="num">{numbered ? i + 1 : ''}</span>
              <span>{it.title}</span>
              <span className="leader" aria-hidden="true" />
              <span className={`state ${states[it.id].tone ?? ''}`}>{states[it.id].text}</span>
            </a>
          </li>
        ))}
      </ol>
    </>
  );
  const settings = useStore((s) => s.settings);
  const device = useStore((s) => s.device);
  return (
    <nav className="toc" aria-label="Contents">
      <p className="toc-status">
        {NETWORKS[settings.network]?.label ?? 'Network'} ({settings.chainId})
        <br />
        {device ? `Paired ${device.k1Address.slice(0, 8)}...${device.k1Address.slice(-4)}` : 'No device paired'}
      </p>
      {group('Setup', SETUP, true)}
      {group('Operation', OPERATION, false)}
      {group('Reference', REFERENCE, false)}
    </nav>
  );
}

const PAGES: Record<Route, () => ReactNode> = {
  connect: () => <Connect />,
  device: () => <Device />,
  pair: () => <Pair />,
  vault: () => <Vault />,
  mandate: () => <Mandate />,
  inbox: () => <Inbox />,
  kill: () => <KillSwitch />,
  activity: () => <Activity />,
  about: () => <About />,
};

export function App() {
  const route = useRoute();
  const theme = useTheme();
  const [menu, setMenu] = useState(false);
  const settings = useStore((s) => s.settings);
  const device = useStore((s) => s.device);
  const dev = useDevice();
  const main = useRef<HTMLElement>(null);

  // the contents sheet (narrow screens): Escape closes it, opening it moves focus to its first link
  useEffect(() => {
    if (!menu) return;
    document.querySelector<HTMLElement>('#rail a')?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setMenu(false);
        document.querySelector<HTMLElement>('.menu-btn')?.focus();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [menu]);

  useEffect(() => {
    setMenu(false);
    const h1 = main.current?.querySelector('h1');
    if (h1 instanceof HTMLElement && document.activeElement !== document.body) h1.focus({ preventScroll: false });
    window.scrollTo({ top: 0 });
  }, [route]);

  const nextTheme = theme === 'system' ? 'dark' : theme === 'dark' ? 'light' : 'system';
  return (
    <>
      <a className="skip" href="#main">
        Skip to content
      </a>
      <header className="topbar">
        <button
          type="button"
          className="icon-btn menu-btn"
          aria-label="Contents"
          aria-expanded={menu}
          aria-controls="rail"
          onClick={() => setMenu((m) => !m)}
        >
          <Icon name={menu ? 'cross' : 'menu'} />
        </button>
        <a className="wordmark" href="#/connect" aria-label="Ripar companion, start">
          <b>RIPAR</b>
          <span>Companion</span>
        </a>
        <div className="runhead" aria-label="Status">
          <span className="sep" aria-hidden="true" />
          <span>
            {NETWORKS[settings.network]?.label ?? 'Network'} ({settings.chainId})
          </span>
          <span className="sep" aria-hidden="true" />
          <span>{device ? `Paired ${device.k1Address.slice(0, 8)}...${device.k1Address.slice(-4)}` : 'No device paired'}</span>
        </div>
        {/* always visible, at every width: the signer is an emulator with demo keys */}
        {dev.mode === 'emulator' && <EmulatorMark compact />}
        <span className="grow" />
        <button
          type="button"
          className="icon-btn"
          aria-label={`Theme: ${theme}. Switch to ${nextTheme}`}
          title={`Theme: ${theme}`}
          onClick={() => store.setSettings({ theme: nextTheme })}
        >
          <Icon name={theme === 'dark' ? 'moon' : theme === 'light' ? 'sun' : 'device'} />
        </button>
        <a className="kill" href="#/kill" aria-label="Kill switch" aria-current={route === 'kill' ? 'page' : undefined}>
          <Icon name="power" size={16} />
          <span className="kill-text">Kill switch</span>
        </a>
      </header>
      <div className="shell">
        <aside className="rail" id="rail" data-open={menu}>
          <Toc route={route} onNavigate={() => setMenu(false)} />
        </aside>
        <main className="main" id="main" ref={main}>
          {PAGES[route]()}
        </main>
      </div>
    </>
  );
}

export function PageHead({ no, title, lede }: { no?: string; title: string; lede: ReactNode }) {
  return (
    <header className="page-head">
      <h1 tabIndex={-1}>
        {no && (
          <span className="h-no">
            <span className="sr-only">Section </span>
            {no}
          </span>
        )}
        {title}
      </h1>
      <p className="lede">{lede}</p>
    </header>
  );
}
