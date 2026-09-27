import { useRouter } from 'expo-router';
import * as Clipboard from 'expo-clipboard';
import { useMemo, useState } from 'react';
import { Pressable, StyleSheet, TextInput, View } from 'react-native';
import { isAddress } from 'viem';
import { AUSD_10143, toChecksumAddress } from '@ripar/protocol';
import { Address, Button, CameraScanner, Icon, Keypad, Label, Note, Pill, Sheet, Steps, Surface, Text, applyKey } from '../src/components';
import { useChain } from '../src/lib/chainState';
import { amountText, parseUnits } from '../src/lib/format';
import { tap } from '../src/lib/haptics';
import { addPayment, newPaymentId } from '../src/lib/payments';
import { deploymentOf, useStore } from '../src/lib/store';
import { ink, palette, radius, space, type } from '../src/theme';

interface Asset {
  id: 'native' | `0x${string}`;
  symbol: string;
  decimals: number;
  balance: bigint | null;
}

/** "ethereum:0xabc...@10143?..." or a bare address -> the address, else null */
function addressOf(text: string): `0x${string}` | null {
  const m = /(0x[0-9a-fA-F]{40})/.exec(text.trim());
  return m && isAddress(m[1]!, { strict: false }) ? toChecksumAddress(m[1]!) : null;
}

export default function Send() {
  const router = useRouter();
  const settings = useStore((s) => s.settings);
  const device = useStore((s) => s.device);
  const personal = useStore((s) => s.personal);
  const chain = useChain();
  const dep = deploymentOf(settings).deployment;

  const assets: Asset[] = useMemo(() => {
    const out: Asset[] = [];
    const tok = (addr: `0x${string}`, symbol: string) => {
      const t = chain.vault?.tokens.find((x) => x.address.toLowerCase() === addr.toLowerCase());
      out.push({ id: addr, symbol, decimals: 6, balance: t?.balance ?? null });
    };
    if (dep && !/^0x0{40}$/i.test(dep.mockUsd)) tok(dep.mockUsd, 'mUSD');
    out.push({ id: 'native', symbol: 'MON', decimals: 18, balance: chain.vault?.native ?? null });
    if (settings.chainId === 10143) tok(AUSD_10143, 'AUSD');
    return out;
  }, [chain.vault, dep, settings.chainId]);

  const [assetId, setAssetId] = useState<Asset['id']>(assets[0]?.id ?? 'native');
  const asset = assets.find((a) => a.id === assetId) ?? assets[0]!;
  const [amount, setAmount] = useState('0');
  const [payee, setPayee] = useState('');
  const [note, setNote] = useState('');
  const [scan, setScan] = useState(false);
  const [confirm, setConfirm] = useState(false);

  let base: bigint | null = null;
  let amountErr: string | null = null;
  try {
    base = parseUnits(amount, asset.decimals);
    if (base === 0n) amountErr = 'Enter an amount';
    else if (asset.balance !== null && base > asset.balance) amountErr = 'More than the vault holds';
  } catch (e) {
    amountErr = (e as Error).message;
  }
  const to = addressOf(payee);
  const toErr = payee.trim() && !to ? 'Not an address' : to && device && to.toLowerCase() === device.pinned.vault.toLowerCase() ? 'That is your own vault' : null;
  const ready = !!device && !!personal && chain.personalLive !== false && !!base && !amountErr && !!to && !toErr;

  if (!device || !personal) {
    return (
      <Sheet title="Send">
        <Note tone="info" title={device ? 'Sending is not set up yet' : 'No device paired'}>
          {device
            ? 'Payments from the vault are co-signed by your Ripar under a personal mandate. Sign it once, then every payment is one review, one pulse, one SIGN.'
            : 'Pair your Ripar first: the vault belongs to its key.'}
        </Note>
        <Button label={device ? 'Enable sending' : 'Pair your Ripar'} full style={{ marginTop: space.lg }} onPress={() => router.replace(device ? '/personal' : '/pair')} />
      </Sheet>
    );
  }

  if (confirm && to && base) {
    return (
      <Sheet
        title="Confirm payment"
        onClose={() => setConfirm(false)}
        footer={
          <Button
            label="Send to your Ripar"
            size="lg"
            full
            icon={<Icon name="shield" size={18} color={palette.primaryForeground} />}
            onPress={() => {
              const id = newPaymentId();
              addPayment({
                id,
                to,
                asset: asset.id,
                symbol: asset.symbol,
                decimals: asset.decimals,
                amount: base!.toString(),
                note: note.trim().slice(0, 140),
                nonce: '',
                requestUr: '',
                status: 'building',
                createdAt: Date.now(),
              });
              router.replace({ pathname: '/pay', params: { id } });
            }}
          />
        }
      >
        <View style={{ alignItems: 'center', gap: 4, marginBottom: space.xl }}>
          <Label>You send</Label>
          <Text style={[type.amount, { color: palette.foreground }]}>{amountText(base, asset.decimals, '').trim()}</Text>
          <Text variant="heading" tone="signal">
            {asset.symbol}
          </Text>
        </View>
        <Surface padded={16} style={{ gap: space.md }}>
          <Label>To</Label>
          <Address value={to} label="Payee" />
          <Label>From</Label>
          <Address value={device.pinned.vault} label="Your vault" tone="soft" />
          {note.trim() ? (
            <>
              <Label>Note (stays on this phone)</Label>
              <Text variant="bodySmall">{note.trim()}</Text>
            </>
          ) : null}
        </Surface>
        <Surface padded={16} style={{ marginTop: space.md, gap: space.md }}>
          <Label>How it is signed</Label>
          <Steps
            steps={[
              'Your Ripar decodes and shows this exact payment: amount, payee, your vault.',
              'Thumb on its pulse sensor until PULSE OK, then SIGN.',
              'This phone redeems the co-signed payment. Its key pays the gas; it cannot move funds without the SIGN.',
            ]}
          />
        </Surface>
        {chain.hot && chain.hot.balance === 0n && (
          <Note tone="warn" title="The phone key has no gas" style={{ marginTop: space.md }}>
            Send testnet MON to the phone key (Settings) before the last step.
          </Note>
        )}
      </Sheet>
    );
  }

  return (
    <Sheet
      title="Send from vault"
      footer={<Button label="Review" size="lg" full disabled={!ready} onPress={() => setConfirm(true)} />}
    >
      {chain.personalLive === false && (
        <Note tone="bad" title="Your personal mandate is dead" style={{ marginBottom: space.md }}>
          A PANIC or a revoke killed it. Sign a new one (Device tab or Enable sending) to send again.
        </Note>
      )}
      <View style={styles.assets}>
        {assets.map((a) => (
          <Pressable
            key={a.id}
            onPress={() => {
              tap();
              setAssetId(a.id);
              setAmount('0');
            }}
            accessibilityRole="radio"
            accessibilityState={{ selected: a.id === asset.id }}
            style={[styles.asset, a.id === asset.id && styles.assetOn]}
          >
            <Text variant="bodyMedium" style={{ color: a.id === asset.id ? palette.primaryForeground : palette.foreground }}>
              {a.symbol}
            </Text>
          </Pressable>
        ))}
      </View>

      <View style={{ alignItems: 'center', marginVertical: space.md }}>
        <Text style={[type.amount, { color: amount === '0' ? ink.faint : palette.foreground }]} numberOfLines={1} adjustsFontSizeToFit accessibilityLabel={`Amount ${amount} ${asset.symbol}`}>
          {amount}
          <Text style={[type.heading, { color: palette.primary }]}> {asset.symbol}</Text>
        </Text>
        <View style={{ flexDirection: 'row', gap: space.sm, alignItems: 'center', marginTop: space.sm }}>
          <Text variant="bodySmall" tone={amountErr && amount !== '0' ? 'danger' : 'soft'}>
            {amountErr && amount !== '0' ? amountErr : `Vault: ${asset.balance === null ? '—' : amountText(asset.balance, asset.decimals, asset.symbol)}`}
          </Text>
          {asset.balance !== null && asset.balance > 0n && (
            <Pill label="Max" tone="signal" onPress={() => setAmount(amountText(asset.balance!, asset.decimals, '').trim().replace(/,/g, ''))} />
          )}
        </View>
      </View>

      <View style={styles.payee}>
        <TextInput
          value={payee}
          onChangeText={setPayee}
          placeholder="Payee address 0x..."
          placeholderTextColor={ink.faint}
          autoCapitalize="none"
          autoCorrect={false}
          style={styles.input}
          accessibilityLabel="Payee address"
        />
        <Pressable
          onPress={async () => {
            tap();
            setPayee((await Clipboard.getStringAsync()).trim());
          }}
          accessibilityRole="button"
          accessibilityLabel="Paste address"
          hitSlop={8}
        >
          <Icon name="copy" size={20} color={palette.foreground} />
        </Pressable>
        <Pressable onPress={() => setScan((x) => !x)} accessibilityRole="button" accessibilityLabel="Scan an address QR" hitSlop={8}>
          <Icon name="scan" size={20} color={scan ? palette.primary : palette.foreground} />
        </Pressable>
      </View>
      {toErr ? (
        <Text variant="bodySmall" tone="danger" style={{ marginTop: 6 }}>
          {toErr}
        </Text>
      ) : null}
      {scan && (
        <View style={{ marginTop: space.md }}>
          <CameraScanner
            height={200}
            hint="Point at an address QR"
            onRead={(t) => {
              const a = addressOf(t);
              if (a) {
                setPayee(a);
                setScan(false);
              }
            }}
          />
        </View>
      )}
      <TextInput
        value={note}
        onChangeText={setNote}
        placeholder="Note for yourself (optional)"
        placeholderTextColor={ink.faint}
        maxLength={140}
        style={[styles.input, styles.note]}
        accessibilityLabel="Note"
      />

      <View style={{ marginTop: space.md }}>
        <Keypad onKey={(k) => setAmount((v) => applyKey(v, k, asset.decimals))} />
      </View>
    </Sheet>
  );
}

const styles = StyleSheet.create({
  assets: { flexDirection: 'row', gap: space.sm, justifyContent: 'center' },
  asset: { paddingHorizontal: space.lg, paddingVertical: 9, borderRadius: radius.pill, backgroundColor: palette.cardHigh, borderWidth: 1, borderColor: ink.hairline },
  assetOn: { backgroundColor: palette.primary, borderColor: palette.primary },
  payee: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: space.md,
    backgroundColor: palette.cardHigh,
    borderRadius: radius.lg,
    paddingHorizontal: space.md,
    borderWidth: 1,
    borderColor: ink.hairline,
  },
  input: { flex: 1, color: palette.foreground, fontFamily: 'GeistMono_400Regular', fontSize: 13, paddingVertical: 12 },
  note: {
    marginTop: space.sm,
    backgroundColor: palette.cardHigh,
    borderRadius: radius.lg,
    paddingHorizontal: space.md,
    fontFamily: 'Geist_400Regular',
    borderWidth: 1,
    borderColor: ink.hairline,
    flex: 0,
  },
});
