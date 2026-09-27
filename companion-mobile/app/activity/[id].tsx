import { useLocalSearchParams } from 'expo-router';
import { Linking, View } from 'react-native';
import { Address, Button, IconCircle, Label, Note, Screen, Surface, Text } from '../../src/components';
import { amountLabel, feedItem } from '../../src/lib/feed';
import { utcText } from '../../src/lib/format';
import { NETWORKS, explorerTxUrl } from '../../src/lib/networks';
import { useStore } from '../../src/lib/store';
import { palette, space, type } from '../../src/theme';
import { iconOf } from '../../src/components/feedIcon';

const KIND_TEXT: Record<string, string> = {
  Payment: 'A payment from your vault, co-signed on your Ripar (HUMAN path) and relayed by this phone.',
  AutoSpend: 'An agent paid inside its mandate caps on its own (AUTO path). The PulseCosignEnforcer metered it.',
  HumanCosigned: 'A payment the enforcer accepted with your Ripar’s P-256 co-sign (HUMAN path).',
  TransferIn: 'Tokens arrived in your vault.',
  TransferOut: 'Tokens left your vault.',
  Panicked: 'A PANIC your Ripar signed was relayed: every mandate with a lower epoch is dead.',
  Revoked: 'A revoke your Ripar signed was relayed: that mandate is dead.',
  LaneChanged: 'The RiparSentinel changed the agent lane of your vault.',
  Verdict: 'Your Ripar’s verdict on an agent request was filed with the ERC-8004 reputation registry.',
  AgentShielded: 'An agent was reported through the reputation relay.',
};

export default function ActivityDetail() {
  const { id } = useLocalSearchParams<{ id: string }>();
  const network = useStore((s) => s.settings.network);
  // local payments update live; chain items are what the last scan found
  useStore((s) => s.payments);
  const item = id ? feedItem(id) : null;
  if (!item) {
    return (
      <Screen back title="Activity" tabs={false}>
        <Note tone="info">This entry is not in the last scan any more. Pull to refresh on Activity.</Note>
      </Screen>
    );
  }
  const ic = iconOf(item);
  const url = item.tx ? explorerTxUrl(NETWORKS[network]?.explorer ?? null, item.tx) : null;
  return (
    <Screen back eyebrow={item.kind} title={item.title} tabs={false}>
      <View style={{ alignItems: 'center', gap: space.md, marginBottom: space.xl }}>
        <IconCircle name={ic.icon} tone={ic.tone} size={64} />
        {item.amount && <Text style={[type.hero, { color: item.amount.sign === '+' ? palette.success : palette.foreground }]}>{amountLabel(item.amount)}</Text>}
        <Text tone="soft" style={{ textAlign: 'center' }}>
          {item.subtitle}
          {item.at ? ` · ${utcText(item.at)}` : ''}
        </Text>
      </View>
      <Text variant="bodySmall" tone="soft" style={{ marginBottom: space.lg }}>
        {KIND_TEXT[item.kind] ?? ''}
      </Text>
      <Surface padded={16} style={{ gap: space.md }}>
        {item.fields.map(([k, v]) => (
          <View key={k} style={{ gap: 3 }}>
            <Label>{k}</Label>
            {/^0x[0-9a-fA-F]{40,64}$/.test(v) ? <Address value={v} label={k} tone="soft" /> : <Text variant="bodySmall">{v}</Text>}
          </View>
        ))}
        {item.block !== null && (
          <View style={{ gap: 3 }}>
            <Label>Block</Label>
            <Text variant="bodySmall">{item.block.toString()}</Text>
          </View>
        )}
      </Surface>
      {url && <Button label="View on the explorer" variant="secondary" style={{ marginTop: space.lg }} onPress={() => void Linking.openURL(url)} />}
    </Screen>
  );
}
