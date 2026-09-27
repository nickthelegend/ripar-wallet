// "What your device will show" (the firmware's review lines, predicted), and the verification report of a response.
import type { VerifyReport } from '@ripar/protocol';
import type { ReviewPreview } from '../lib/review-preview';
import { Icon } from './Icon';
import { Mark } from './ui';

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
