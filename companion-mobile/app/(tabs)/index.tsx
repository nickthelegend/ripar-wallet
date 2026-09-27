import { useRouter } from 'expo-router';
import { useEffect } from 'react';
import { Pressable, ScrollView, StyleSheet, useWindowDimensions, View } from 'react-native';
import Animated from 'react-native-reanimated';
import { formatEther } from 'viem';
import {
  Icon,
  IconCircle,
  Label,
  ListRow,
  Pill,
  Screen,
  SectionHead,
  Sparkline,
  Surface,
  Text,
  enterUpAfter,
} from '../../src/components';
import { iconOf } from '../../src/components/feedIcon';
import { useDeviceLink, useObservable } from '../../src/device/DeviceLinkProvider';
import { RADIO_ON_TEXT, WIFI_ON_TEXT, linkMeta } from '../../src/device/guide';
import { refreshChain, useChain } from '../../src/lib/chainState';
import { amountLabel, insightsOf, refreshFeed, useFeed } from '../../src/lib/feed';
import { amountText } from '../../src/lib/format';
import { tap } from '../../src/lib/haptics';
import { useStore } from '../../src/lib/store';
import { ink, palette, radius, space, type } from '../../src/theme';

const short = (a: string) => `${a.slice(0, 6)}…${a.slice(-4)}`;

function Action({ icon, label, onPress }: { icon: 'send' | 'receive' | 'scan' | 'device'; label: string; onPress: () => void }) {
  return (
    <Pressable onPress={onPress} onPressIn={tap} accessibilityRole="button" accessibilityLabel={label} style={({ pressed }) => [styles.action, pressed && { transform: [{ scale: 0.94 }] }]}>
      <IconCircle name={icon} dark size={52} />
      <Text variant="bodySmall" tone="onSignal" style={{ fontWeight: '600' }}>
        {label}
      </Text>
    </Pressable>
  );
}

export default function Home() {
  const router = useRouter();
  const { width } = useWindowDimensions();
  const device = useStore((s) => s.device);
  const personal = useStore((s) => s.personal);
  const linkChoice = useStore((s) => s.settings.link);
  const chainId = useStore((s) => s.settings.chainId);
  const deploymentsJson = useStore((s) => s.settings.deploymentsJson);
  const chain = useChain();
  const feed = useFeed();
  const { link, bleConn, wifiConn } = useDeviceLink();
  const status = useObservable(link?.status ?? null);

  useEffect(() => {
    if (feed.readAt === null && !feed.scanning) void refreshFeed();
  }, [feed.readAt, feed.scanning]);

  const vault = chain.vault;
  const stable = vault?.tokens.find((t) => t.symbol === 'mUSD') ?? vault?.tokens[0] ?? null;
  const insights = insightsOf(feed.items);
  const recent = feed.items.slice(0, 4);

  const setup: { done: boolean; label: string; icon: 'link' | 'device' | 'key' | 'wallet' | 'send'; go: () => void }[] = [
    { done: !!deploymentsJson, label: 'Load the Ripar deployment', icon: 'link', go: () => router.push('/network') },
    { done: !!device, label: 'Pair your Ripar', icon: 'device', go: () => router.push('/pair') },
    { done: chain.registered === true, label: 'Register the device on-chain', icon: 'key', go: () => router.push('/pair') },
    { done: vault?.deployed === true, label: 'Deploy your vault', icon: 'wallet', go: () => router.push('/pair') },
    { done: !!personal && chain.personalLive !== false, label: 'Enable sending (personal mandate)', icon: 'send', go: () => router.push('/personal') },
  ];
  const pending = setup.filter((x) => !x.done);

  const meta = linkMeta(linkChoice);
  const linkLabel =
    linkChoice === 'ble' ? (bleConn.state === 'connected' ? 'Bluetooth' : 'Bluetooth · offline') : linkChoice === 'wifi' ? (wifiConn.state === 'connected' ? 'Wi-Fi · testing' : 'Wi-Fi · offline') : meta.short;

  const onSend = () => {
    if (!device || !personal) router.push(device ? '/personal' : '/pair');
    else router.push('/send');
  };

  return (
    <Screen
      eyebrow={chainId === 143 ? 'Monad' : 'Monad testnet'}
      title="Your vault"
      action={
        <Pill
          label={device ? (meta.radio ? 'Not air-gapped' : 'Air-gapped') : 'No device'}
          tone={!device ? 'plain' : meta.radio ? 'warn' : 'good'}
          icon={meta.radio ? 'radio' : 'shield'}
          onPress={() => router.push('/(tabs)/device')}
        />
      }
      onRefresh={async () => {
        await Promise.all([refreshChain(), refreshFeed()]);
      }}
    >
      {/* the balance card: the one bright object on the screen */}
      <Animated.View entering={enterUpAfter(40)}>
        <Surface variant="signal" padded={20} radiusSize={28}>
          <View style={styles.cardTop}>
            <Pill
              label={device ? `Vault ${short(device.pinned.vault)}` : 'No vault yet'}
              icon="wallet"
              onDark
              mono={!!device}
              onPress={device ? () => router.push('/receive') : undefined}
            />
            <Pill label={linkLabel} icon={meta.icon} onDark />
          </View>
          <Label tone="onSignal" style={{ marginTop: space.xl, opacity: 0.8 }}>
            Vault balance
          </Label>
          {device ? (
            <>
              <Text style={[type.hero, { color: palette.primaryForeground }]} accessibilityLabel={`Balance ${stable ? amountText(stable.balance ?? 0n, stable.decimals, stable.symbol) : 'unknown'}`}>
                {stable?.balance !== null && stable?.balance !== undefined && stable.decimals !== null
                  ? amountText(stable.balance, stable.decimals, '').trim()
                  : chain.reading
                    ? '...'
                    : '—'}
                <Text style={[type.heading, { color: palette.primaryForeground }]}> {stable?.symbol ?? 'mUSD'}</Text>
              </Text>
              <Text variant="bodyMedium" tone="onSignal" style={{ opacity: 0.85 }}>
                {vault?.native !== null && vault?.native !== undefined ? `${Number(formatEther(vault.native)).toLocaleString('en-US', { maximumFractionDigits: 4 })} MON` : '— MON'}
                {vault?.deployed === false ? ' · vault not deployed yet' : ''}
              </Text>
            </>
          ) : (
            <Text style={[type.title, { color: palette.primaryForeground, marginTop: 4 }]}>Pair a Ripar to open your vault</Text>
          )}
          <View style={styles.actions}>
            <Action icon="send" label="Send" onPress={onSend} />
            <Action icon="receive" label="Receive" onPress={() => router.push(device ? '/receive' : '/pair')} />
            <Action icon="scan" label="Scan" onPress={() => router.push('/scan')} />
            <Action icon="device" label="Device" onPress={() => router.push('/(tabs)/device')} />
          </View>
        </Surface>
      </Animated.View>

      {linkChoice === 'ble' && (
        <Pressable onPress={() => router.push('/link')} style={[styles.radioWarn]} accessibilityRole="button" accessibilityLabel={`Not air-gapped. ${RADIO_ON_TEXT}`}>
          <Icon name="radio" size={18} color={palette.warn} />
          <View style={{ flex: 1, gap: 2 }}>
            <Text variant="label" tone="warn">
              Not air-gapped · radio on
            </Text>
            <Text variant="bodySmall" tone="soft">
              Bluetooth fallback is selected: the Ripar's radio is on while BLE LINK runs. Switch back to QR as soon as the camera reads again.
            </Text>
          </View>
        </Pressable>
      )}
      {linkChoice === 'wifi' && (
        <Pressable onPress={() => router.push('/link')} style={[styles.radioWarn]} accessibilityRole="button" accessibilityLabel={`Not air-gapped. ${WIFI_ON_TEXT}`}>
          <Icon name="wifi" size={18} color={palette.warn} />
          <View style={{ flex: 1, gap: 2 }}>
            <Text variant="label" tone="warn">
              Not air-gapped · Wi-Fi on · testing
            </Text>
            <Text variant="bodySmall" tone="soft">
              The Wi-Fi link is selected: the Ripar's Wi-Fi is on. For testing only: turn it off on the device and switch back to QR when you are done.
            </Text>
          </View>
        </Pressable>
      )}

      {pending.length > 0 && (
        <Animated.View entering={enterUpAfter(90)}>
          <SectionHead title="Finish setting up" action={<Text variant="bodySmall" tone="faint">{`${setup.length - pending.length}/${setup.length}`}</Text>} />
          <Surface padded={6}>
            {pending.slice(0, 3).map((x) => (
              <View key={x.label} style={{ paddingHorizontal: 10 }}>
                <ListRow icon={x.icon} iconTone="signal" title={x.label} onPress={x.go} />
              </View>
            ))}
          </Surface>
        </Animated.View>
      )}

      <SectionHead title="Quick" />
      <ScrollView horizontal showsHorizontalScrollIndicator={false} contentContainerStyle={{ gap: space.md, paddingRight: space.xl }} style={{ marginHorizontal: -space.xl, paddingLeft: space.xl }}>
        {[
          { icon: 'power' as const, label: 'Kill switch', tone: 'bad' as const, go: () => router.push('/scan') },
          { icon: 'agents' as const, label: 'Agent inbox', tone: 'info' as const, go: () => router.push('/(tabs)/agents') },
          { icon: 'bolt' as const, label: 'Phone gas', tone: 'warn' as const, go: () => router.push('/(tabs)/settings') },
          { icon: 'link' as const, label: 'Device link', tone: 'signal' as const, go: () => router.push('/link') },
        ].map((q) => (
          <Surface key={q.label} onPress={q.go} padded={14} style={{ width: 128 }} accessibilityLabel={q.label}>
            <IconCircle name={q.icon} tone={q.tone} size={40} />
            <Text variant="bodyMedium" style={{ marginTop: space.md }}>
              {q.label}
            </Text>
          </Surface>
        ))}
      </ScrollView>

      <SectionHead title="Insights" />
      <Surface variant="raised" padded={18}>
        <View style={styles.rowBetween}>
          <View>
            <Label>Payments, last 14 days</Label>
            <Text variant="stat" style={{ marginTop: 4 }}>
              {insights.total}
            </Text>
          </View>
          <Sparkline values={insights.daily} width={Math.min(170, width * 0.42)} height={48} />
        </View>
        <View style={styles.bars}>
          {[
            { label: 'You, co-signed', n: insights.byActor.you, color: palette.primary },
            { label: 'Agent, automatic', n: insights.byActor.agentAuto, color: palette.steel },
            { label: 'Agent, co-signed', n: insights.byActor.agentCosigned, color: palette.success },
          ].map((b) => (
            <View key={b.label} style={{ gap: 6 }}>
              <View style={styles.rowBetween}>
                <Text variant="bodySmall" tone="soft">
                  {b.label}
                </Text>
                <Text variant="bodySmall" style={{ fontVariant: ['tabular-nums'] }}>
                  {b.n}
                </Text>
              </View>
              <View style={styles.track}>
                <View style={[styles.fill, { backgroundColor: b.color, width: `${insights.total ? Math.round((b.n / insights.total) * 100) : 0}%` }]} />
              </View>
            </View>
          ))}
        </View>
      </Surface>

      <SectionHead
        title="Recent activity"
        action={
          <Text variant="bodySmall" tone="signal" onPress={() => router.push('/(tabs)/activity')} accessibilityRole="link">
            See all
          </Text>
        }
      />
      <Surface padded={6}>
        {recent.length === 0 ? (
          <View style={{ padding: space.lg }}>
            <Text variant="bodySmall" tone="soft">
              {feed.scanning ? 'Reading the chain...' : device ? 'Nothing yet. Payments, agent spends and kill-switch events show up here.' : 'Pair your Ripar to see its vault activity.'}
            </Text>
          </View>
        ) : (
          recent.map((i) => (
            <View key={i.id} style={{ paddingHorizontal: 10 }}>
              <ListRow
                icon={iconOf(i).icon}
                iconTone={iconOf(i).tone}
                title={i.title}
                subtitle={i.subtitle}
                value={i.amount ? amountLabel(i.amount) : undefined}
                valueTone={i.amount?.sign === '+' ? 'success' : 'default'}
                onPress={() => router.push({ pathname: '/activity/[id]', params: { id: i.id } })}
              />
            </View>
          ))
        )}
      </Surface>

      {status && linkChoice !== 'qr' && (
        <Text variant="bodySmall" tone="faint" style={{ marginTop: space.md }}>
          Device: {status.screen}
          {status.paired ? ' · paired' : ''}
        </Text>
      )}
    </Screen>
  );
}

const styles = StyleSheet.create({
  cardTop: { flexDirection: 'row', justifyContent: 'space-between', gap: space.sm, flexWrap: 'wrap' },
  actions: { flexDirection: 'row', justifyContent: 'space-between', marginTop: space['2xl'] },
  action: { alignItems: 'center', gap: 6, minWidth: 64 },
  rowBetween: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', gap: space.md },
  bars: { gap: space.md, marginTop: space.lg },
  track: { height: 6, borderRadius: 3, backgroundColor: ink.hairline, overflow: 'hidden' },
  fill: { height: 6, borderRadius: 3 },
  radioWarn: {
    flexDirection: 'row',
    gap: space.md,
    alignItems: 'center',
    marginTop: space.lg,
    padding: space.md,
    borderRadius: radius.lg,
    borderWidth: 1,
    borderColor: `${palette.warn}55`,
    backgroundColor: `${palette.warn}12`,
  },
});
