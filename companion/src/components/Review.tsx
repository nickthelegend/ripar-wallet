// "What your device will show" (the firmware's review lines, predicted), and the verification report of a response.
import { type VerifyReport, firmwareToken } from '@ripar/protocol';
import { amountText } from '../lib/format';
import type { ReviewPreview } from '../lib/review-preview';
import { Icon } from './Icon';
import { Mark, Note } from './ui';

/**
 * Why the device shows "UNKNOWN TOKEN - decimals unverified" and base units: the firmware token table lists only
 * tokens it can vouch for (firmware v1.2: AUSD and MockUSD on Monad testnet, MON). Nothing when the device knows the
 * token.
 */
export function UnknownTokenNote({
  chainId,
  token,
  decimals,
  symbol,
  amounts = [],
}: {
  chainId: number;
  token: string;
  decimals: number | null;
  symbol: string | null;
  amounts?: bigint[];
}) {
  if (/^0x0{40}$/i.test(token) || token === 'native' || !/^0x[0-9a-fA-F]{40}$/.test(token) || firmwareToken(chainId, token)) return null;
  const ex = amounts.filter((a) => a > 0n).slice(0, 2);
  return (
    <Note title="UNKNOWN TOKEN on the device">
      <p>
        The device names only tokens in its own firmware table, so for {symbol ?? 'this token'} it shows UNKNOWN TOKEN -
        decimals unverified and raw base units
        {decimals !== null && ex.length > 0 && (
          <>
            {' '}
            ({ex.map((a) => `${amountText(a, decimals, symbol ?? '')} = ${a.toLocaleString('en-US')} base units`).join('; ')}, {decimals} decimals)
          </>
        )}
        . Check those base units on the device, and the token address against the one you expect.
      </p>
    </Note>
  );
}

export function ReviewPanel({ preview, footer }: { preview: ReviewPreview; footer?: string }) {
  return (
    <div className="lcd-review" role="group" aria-label={`Device review: ${preview.title}`}>
      <header>{preview.title}</header>
      <ol>
        {preview.lines.map((l, i) => (
          <li key={i} className={l.label ? undefined : 'full'}>
            {l.label && <span className="l">{l.label}</span>}
            <span className={`v ${l.tone}`}>{l.value}</span>
          </li>
        ))}
      </ol>
      <footer>{footer ?? 'press = PULSE + SIGN'}</footer>
    </div>
  );
}

export function VerifyPanel({ report, extra }: { report: Pick<VerifyReport, 'type' | 'checks' | 'result' | 'unverified'>; extra?: string }) {
  const tone = report.result === 'VERIFIED' ? 'good' : report.result === 'FAIL' ? 'bad' : 'warn';
  return (
    <section className="report" aria-label="Verification">
      <div className="report-head">
        <span className="small">
          <b>{report.type}</b> {extra ? <span className="muted">{extra}</span> : null}
        </span>
        <Mark tone={tone}>{report.result}</Mark>
      </div>
      <ul>
        {report.checks.map((c, i) => (
          <li key={i} className={c.ok ? 'ok' : 'fail'}>
            <Icon name={c.ok ? 'check' : 'cross'} size={15} />
            <span>{c.name}</span>
          </li>
        ))}
        {report.unverified.map((u, i) => (
          <li key={`u${i}`} className="fail">
            <Icon name="alert" size={15} />
            <span>not checked: {u}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
