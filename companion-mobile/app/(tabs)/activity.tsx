import { useRouter } from 'expo-router';
import { useEffect, useState } from 'react';
import { useWindowDimensions, View } from 'react-native';
import { Label, ListRow, Pill, Screen, Sparkline, Surface, Text } from '../../src/components';
import { iconOf } from '../../src/components/feedIcon';
import { type FeedItem, amountLabel, insightsOf, refreshFeed, useFeed } from '../../src/lib/feed';
import { agoShort } from '../../src/lib/format';
import { useStore } from '../../src/lib/store';
import { space } from '../../src/theme';

type Filter = 'all' | 'you' | 'agent' | 'device' | 'in';

const FILTERS: { id: Filter; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'you', label: 'You' },
  { id: 'agent', label: 'Agents' },
  { id: 'device', label: 'Kill switch' },
  { id: 'in', label: 'Incoming' },
];

function matches(i: FeedItem, f: Filter): boolean {
  if (f === 'all') return true;
  if (f === 'in') return i.kind === 'TransferIn';
  if (f === 'device') return i.actor === 'device' || i.kind === 'LaneChanged';
  return i.actor === f;
}

export default function Activity() {
  const router = useRouter();
  const { width } = useWindowDimensions();
  const feed = useFeed();
  const device = useStore((s) => s.device);
  const [filter, setFilter] = useState<Filter>('all');

  useEffect(() => {
    if (feed.readAt === null && !feed.scanning) void refreshFeed();
  }, [feed.readAt, feed.scanning]);

  const items = feed.items.filter((i) => matches(i, filter));
  const insights = insightsOf(feed.items);

  return (
    <Screen eyebrow="Vault and device" title="Activity" onRefresh={refreshFeed}>
      <Surface variant="steel" padded={18}>
        <Label tone="onSteel">Payments · 14 days</Label>
        <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'flex-end', marginTop: 4 }}>
          <Text variant="hero" tone="onSteel">
            {insights.total}
          </Text>
          <Sparkline values={insights.daily} width={Math.min(190, width * 0.45)} height={52} color="#0B1520" />
        </View>
        <Text variant="bodySmall" tone="onSteel" style={{ opacity: 0.8 }}>
          {insights.byActor.you} by you · {insights.byActor.agentAuto} agent automatic · {insights.byActor.agentCosigned} agent co-signed
        </Text>
      </Surface>

      <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: space.sm, marginTop: space.xl, marginBottom: space.md }}>
        {FILTERS.map((f) => (
          <Pill key={f.id} label={f.label} tone={filter === f.id ? 'signal' : 'plain'} onPress={() => setFilter(f.id)} />
        ))}
      </View>

      {feed.scanning && (
        <Text variant="bodySmall" tone="faint" style={{ marginBottom: space.sm }}>
          Reading the chain... {Math.round(feed.progress * 100)}%
        </Text>
      )}
      <Surface padded={6}>
        {items.length === 0 ? (
          <View style={{ padding: space.lg }}>
            <Text variant="bodySmall" tone="soft">
              {!device ? 'Pair your Ripar to see its activity.' : feed.scanning ? 'Looking...' : 'Nothing in the scanned range.'}
            </Text>
          </View>
        ) : (
          items.map((i) => {
            const ic = iconOf(i);
            return (
              <View key={i.id} style={{ paddingHorizontal: 10 }}>
                <ListRow
                  icon={ic.icon}
                  iconTone={ic.tone}
                  title={i.title}
                  subtitle={i.subtitle}
                  value={i.amount ? amountLabel(i.amount) : undefined}
                  valueTone={i.amount?.sign === '+' ? 'success' : 'default'}
                  sub={i.at ? agoShort(i.at) : undefined}
                  onPress={() => router.push({ pathname: '/activity/[id]', params: { id: i.id } })}
                />
              </View>
            );
          })
        )}
      </Surface>
      {feed.fromBlock !== null && feed.toBlock !== null && (
        <Text variant="bodySmall" tone="faint" style={{ marginTop: space.md }}>
          Blocks {feed.fromBlock.toString()}–{feed.toBlock.toString()} scanned (Settings &gt; Advanced sets how far back).
          {feed.errors.length ? ` ${feed.errors.length} range(s) failed: ${feed.errors[0]}` : ''}
        </Text>
      )}
    </Screen>
  );
}
