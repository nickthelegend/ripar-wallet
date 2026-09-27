// The manual's small parts: full addresses in reading groups, spec tables, numbered procedure steps, figure plates
// with crop marks and captions, notes, printed status marks, and buttons with a busy state.
import { type ButtonHTMLAttributes, Children, Fragment, type ReactElement, type ReactNode, cloneElement, isValidElement, useState } from 'react';
import { hexGroups } from '../lib/format';
import { explorerAddressUrl } from '../lib/networks';
import { Icon, type IconName } from './Icon';

export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="icon-btn"
      title={done ? 'Copied' : label}
      aria-label={done ? 'Copied' : label}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1400);
        } catch {
          /* clipboard blocked */
        }
      }}
    >
      <Icon name={done ? 'check' : 'copy'} size={16} />
    </button>
  );
}

/** a full hex value (address, hash, key) in 4-character reading groups; copy copies the exact text */
export function Hex({ value, copy = true, explorer, label }: { value: string; copy?: boolean; explorer?: string | null; label?: string }) {
  const g = hexGroups(value);
  const url = explorer ? explorerAddressUrl(explorer, value) : null;
  return (
    <span className="addr-line">
      <span className="addr">
        {g.map((x, i) => (
          <Fragment key={i}>
            {i > 0 && <wbr />}
            <span className={i === 0 && x === '0x' ? 'g0' : undefined}>{x}</span>
          </Fragment>
        ))}
      </span>
      {copy && <CopyButton text={value} label={`Copy ${label ?? (value.length === 42 ? 'address' : 'value')} ${value.slice(0, 6)}...${value.slice(-4)}`} />}
      {url && (
        <a className="icon-btn" href={url} target="_blank" rel="noreferrer" aria-label="Open in the explorer" title="Open in the explorer">
          <Icon name="external" size={16} />
        </a>
      )}
    </span>
  );
}

export interface SpecRow {
  k: ReactNode;
  v: ReactNode;
}

type Falsy = null | false | undefined | '' | 0;

export function Spec({ rows, compact }: { rows: (SpecRow | Falsy)[]; compact?: boolean }) {
  return (
    <dl className={`spec${compact ? ' compact' : ''}`}>
      {rows.filter(Boolean).map((r, i) => {
        const row = r as SpecRow;
        // a Hex value's copy button is named after its row ("Copy Agent 0x5FC8...5707"), not "Copy value"
        const v =
          isValidElement(row.v) && row.v.type === Hex && typeof row.k === 'string' && !(row.v.props as { label?: string }).label
            ? cloneElement(row.v as ReactElement<{ label?: string }>, { label: row.k })
            : row.v;
        return (
          <div key={i}>
            <dt>{row.k}</dt>
            <dd>{v}</dd>
          </div>
        );
      })}
    </dl>
  );
}

export type StepState = 'pending' | 'active' | 'done' | 'error';

export function Procedure({ children }: { children: ReactNode }) {
  return <ol className="procedure">{children}</ol>;
}

export function Step({
  n,
  title,
  state,
  aside,
  children,
}: {
  n: number;
  title: ReactNode;
  state: StepState;
  aside?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <li className="step" data-state={state}>
      <span className="step-mark" aria-hidden="true">
        {state === 'done' ? <Icon name="check" size={18} /> : n}
      </span>
      <div className="step-body">
        <div className="step-title">
          <h3>
            <span className="sr-only">Step {n}: </span>
            {title}
          </h3>
          {aside}
          <span className="sr-only">({state === 'done' ? 'done' : state === 'active' ? 'current step' : state === 'error' ? 'needs attention' : 'not yet'})</span>
        </div>
        {children && <div className="step-content">{children}</div>}
      </div>
    </li>
  );
}

export function Figure({ n, caption, children, crop = true }: { n: string; caption: ReactNode; children: ReactNode; crop?: boolean }) {
  return (
    <figure className="figure">
      <div className={`plate${crop ? ' crop' : ''}`}>{children}</div>
      <figcaption className="figcaption">
        <b>Fig. {n}</b>
        <span>{caption}</span>
      </figcaption>
    </figure>
  );
}

const NOTE_ICON: Record<string, IconName> = { note: 'info', caution: 'alert', warning: 'alert', ok: 'check' };
const NOTE_WORD: Record<string, string> = { note: 'Note', caution: 'Caution', warning: 'Warning', ok: 'Done' };

/** a note; `alert` announces it at once (only for an error that was just raised, never for static guidance) */
export function Note({
  kind = 'note',
  title,
  alert,
  children,
}: {
  kind?: 'note' | 'caution' | 'warning' | 'ok';
  title?: string;
  alert?: boolean;
  children: ReactNode;
}) {
  return (
    <div className={`note ${kind}`} role={alert ? 'alert' : undefined}>
      <Icon name={NOTE_ICON[kind]!} size={18} />
      <div>
        <b className="kind">{title ?? NOTE_WORD[kind]}</b>
        {children}
      </div>
    </div>
  );
}

export function Mark({ tone = 'plain', children }: { tone?: 'plain' | 'good' | 'warn' | 'bad' | 'spot' | 'emu'; children: ReactNode }) {
  return <span className={`mark ${tone}`}>{children}</span>;
}

export function EmulatorMark({ compact }: { compact?: boolean }) {
  return (
    <span className={`mark emu${compact ? ' compact' : ''}`} title="An emulated device: demo keys, never put real funds behind it">
      {compact ? (
        <>
          <span className="full">EMULATOR - DEMO KEYS</span>
          <span className="short">EMU - DEMO KEYS</span>
        </>
      ) : (
        'EMULATOR - DEMO KEYS'
      )}
    </span>
  );
}

/** the way on: shown at the end of a setup page once its steps are done */
export function NextStep({ to, label, children }: { to: string; label: string; children?: ReactNode }) {
  return (
    <div className="next-step">
      {children && <p className="small">{children}</p>}
      <a className="btn primary" href={`#/${to}`}>
        Next: {label}
        <Icon name="chevronRight" size={16} />
      </a>
    </div>
  );
}

export function Button({
  busy,
  icon,
  variant,
  size,
  children,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  busy?: boolean;
  icon?: IconName;
  variant?: 'primary' | 'danger' | 'danger solid' | 'quiet';
  size?: 'small';
}) {
  return (
    <button
      type="button"
      className={['btn', variant, size].filter(Boolean).join(' ')}
      aria-busy={busy || undefined}
      {...rest}
      disabled={rest.disabled || busy}
    >
      {busy ? <Icon name="spinner" size={16} className="spin" /> : icon ? <Icon name={icon} size={16} /> : null}
      {children}
    </button>
  );
}

export function Field({
  label,
  hint,
  error,
  htmlFor,
  children,
}: {
  label: ReactNode;
  hint?: ReactNode;
  error?: string | null;
  htmlFor: string;
  children: ReactNode;
}) {
  // the hint / error is the input's description, and an error marks it invalid (announced with the field)
  const describedBy = error ? `${htmlFor}-err` : hint ? `${htmlFor}-hint` : undefined;
  const kids = Children.map(children, (c) =>
    isValidElement(c) && (c.props as { id?: string }).id === htmlFor
      ? cloneElement(c as ReactElement<Record<string, unknown>>, {
          ...(describedBy ? { 'aria-describedby': describedBy } : {}),
          'aria-invalid': error ? true : (c.props as Record<string, unknown>)['aria-invalid'],
        })
      : c,
  );
  return (
    <div className="field">
      <label htmlFor={htmlFor}>{label}</label>
      {kids}
      {error ? (
        <span className="err" id={`${htmlFor}-err`}>
          {error}
        </span>
      ) : hint ? (
        <span className="hint" id={`${htmlFor}-hint`}>
          {hint}
        </span>
      ) : null}
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <b>{title}</b>
      {children}
    </div>
  );
}
