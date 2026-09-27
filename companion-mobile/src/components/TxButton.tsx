import { useState } from 'react';
import { View } from 'react-native';
import { type WriteRequest, type WriteResult, type WriteStage, sendWrite } from '../lib/chain';
import { connectCourier, publicClientFor } from '../lib/clients';
import { errorText } from '../lib/format';
import { failed, succeeded } from '../lib/haptics';
import { NETWORKS, explorerTxUrl } from '../lib/networks';
import { useStore } from '../lib/store';
import { space } from '../theme';
import { Button } from './Button';
import { Note } from './Rows';
import { Mono, Text } from './Text';

const STAGE: Record<WriteStage, string> = {
  simulating: 'Checking it would succeed...',
  signing: 'Signing with the phone key...',
  pending: 'Waiting for the block...',
  confirmed: 'Confirmed',
};

/**
 * One chain write, relayed by the phone's hot key (the courier): simulated first so a revert is explained before any
 * gas is spent, sent with an explicit gas limit, awaited. What it does is said in words above the button.
 */
export function TxButton({
  write,
  label,
  onDone,
  variant = 'primary',
  disabled,
}: {
  write: WriteRequest;
  label: string;
  onDone?: (r: WriteResult) => void;
  variant?: 'primary' | 'secondary' | 'danger' | 'steel';
  disabled?: boolean;
}) {
  const settings = useStore((s) => s.settings);
  const [stage, setStage] = useState<WriteStage | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [hash, setHash] = useState<`0x${string}` | null>(null);
  const busy = stage !== null && stage !== 'confirmed';

  const run = async () => {
    setErr(null);
    setHash(null);
    try {
      const courier = await connectCourier(settings);
      const r = await sendWrite(publicClientFor(settings), courier, write, (s, h) => {
        setStage(s);
        if (h) setHash(h);
      });
      succeeded();
      onDone?.(r);
    } catch (e) {
      failed();
      setStage(null);
      const m = errorText(e);
      setErr(/insufficient funds|exceeds the balance|gas required exceeds/i.test(m) ? `${m}. The phone key needs testnet MON for gas (Settings > Phone key).` : m);
    }
  };

  const url = hash ? explorerTxUrl(NETWORKS[settings.network]?.explorer ?? null, hash) : null;
  return (
    <View style={{ gap: space.sm }}>
      <Text variant="bodySmall" tone="soft">
        {write.summary}
      </Text>
      <Button label={stage === 'confirmed' ? 'Done' : label} variant={variant} onPress={run} loading={busy} disabled={disabled || stage === 'confirmed'} full />
      {stage && stage !== 'confirmed' ? (
        <Text variant="bodySmall" tone="faint">
          {STAGE[stage]}
        </Text>
      ) : null}
      {hash ? <Mono small>{url ?? hash}</Mono> : null}
      {err ? (
        <Note tone="bad" title="Not sent">
          {err}
        </Note>
      ) : null}
    </View>
  );
}
