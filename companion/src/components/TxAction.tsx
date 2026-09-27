// A chain write, stated before it is sent: what it does, the contract, the explicit gas limit. The courier wallet
// signs and pays; the write is simulated first so a revert is explained before any gas is spent.
import { useState } from 'react';
import { type WriteRequest, type WriteResult, type WriteStage, sendWrite } from '../lib/chain';
import { connectCourier, publicClientFor } from '../lib/clients';
import { errorText } from '../lib/format';
import { NETWORKS, explorerTxUrl } from '../lib/networks';
import { refreshSetup } from '../lib/setup';
import { useStore } from '../lib/store';
import { Icon } from './Icon';
import { Button, Hex, Spec } from './ui';

const STAGE_TEXT: Record<WriteStage, string> = {
  simulating: 'Simulating...',
  signing: 'Waiting for the courier wallet...',
  pending: 'Sent. Waiting for the block...',
  confirmed: 'Confirmed',
};

export function TxAction({
  write,
  label,
  onDone,
  disabled,
  variant = 'primary',
}: {
  write: WriteRequest;
  label: string;
  onDone?: (r: WriteResult) => void;
  disabled?: boolean;
  variant?: 'primary' | 'danger solid';
}) {
  const settings = useStore((s) => s.settings);
  const [stage, setStage] = useState<WriteStage | null>(null);
  const [hash, setHash] = useState<`0x${string}` | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<WriteResult | null>(null);
  const explorer = NETWORKS[settings.network]?.explorer ?? null;
  const busy = stage !== null && stage !== 'confirmed' && !error;

  const run = async () => {
    setError(null);
    setDone(null);
    setHash(null);
    try {
      const courier = await connectCourier(settings);
      const r = await sendWrite(publicClientFor(settings), courier, write, (s, h) => {
        setStage(s);
        if (h) setHash(h);
      });
      setDone(r);
      onDone?.(r);
      void refreshSetup(); // a write may have registered the device, deployed or funded the vault
    } catch (e) {
      setError(errorText(e));
      setStage(null);
    }
  };

  const txUrl = hash ? explorerTxUrl(explorer, hash) : null;
  return (
    <div className="tx">
      <div className="tx-head">{write.summary}</div>
      <Spec
        compact
        rows={[
          { k: 'Contract', v: <Hex value={write.to} explorer={explorer} /> },
          { k: 'Gas limit', v: <span className="data">{write.gas.toLocaleString('en-US')} (explicit; Monad charges the limit)</span> },
          { k: 'Courier', v: settings.courier === 'anvil' ? `anvil unlocked account ${settings.anvilAccount}` : 'injected wallet (pays gas only)' },
          hash && { k: 'Transaction', v: <Hex value={hash} copy /> },
        ]}
      />
      <div className="tx-foot">
        <Button variant={variant} busy={busy} onClick={run} disabled={disabled || !!done} icon={done ? 'check' : 'send'}>
          {done ? 'Sent' : label}
        </Button>
        {stage && !error && (
          <span className="stage" role="status">
            {stage === 'confirmed' ? <Icon name="check" size={16} style={{ color: 'var(--good)' }} /> : null}
            {STAGE_TEXT[stage]}
            {done && ` in block ${done.blockNumber}, gas used ${done.gasUsed.toLocaleString('en-US')}`}
          </span>
        )}
        {txUrl && (
          <a href={txUrl} target="_blank" rel="noreferrer" className="small">
            View transaction
          </a>
        )}
        {error && (
          <span className="small" role="alert" style={{ color: 'var(--bad)' }}>
            {error}
          </span>
        )}
      </div>
    </div>
  );
}
