import * as Clipboard from 'expo-clipboard';
import { useState } from 'react';
import { Share, useWindowDimensions, View } from 'react-native';
import { Address, Button, Icon, Label, Note, QrCode, Sheet, Text } from '../src/components';
import { useChain } from '../src/lib/chainState';
import { succeeded } from '../src/lib/haptics';
import { useStore } from '../src/lib/store';
import { palette, space } from '../src/theme';

export default function Receive() {
  const device = useStore((s) => s.device);
  const chainId = useStore((s) => s.settings.chainId);
  const chain = useChain();
  const { width } = useWindowDimensions();
  const [copied, setCopied] = useState(false);

  if (!device) {
    return (
      <Sheet title="Receive">
        <Note tone="info">Pair your Ripar first: your vault address follows from its key.</Note>
      </Sheet>
    );
  }
  const vault = device.pinned.vault;
  const net = chainId === 143 ? 'Monad' : 'Monad testnet';
  return (
    <Sheet title="Receive">
      <View style={{ alignItems: 'center', gap: space.lg }}>
        <QrCode text={vault} size={Math.min(width - 120, 260)} label={`Vault address ${vault}`} />
        <View style={{ alignSelf: 'stretch', gap: 6 }}>
          <Label>Your vault on {net}</Label>
          <Address value={vault} label="Vault address" />
        </View>
        <View style={{ flexDirection: 'row', gap: space.md, alignSelf: 'stretch' }}>
          <Button
            label={copied ? 'Copied' : 'Copy'}
            variant="secondary"
            style={{ flex: 1 }}
            icon={<Icon name={copied ? 'check' : 'copy'} size={18} color={palette.foreground} />}
            onPress={async () => {
              await Clipboard.setStringAsync(vault);
              succeeded();
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            }}
          />
          <Button
            label="Share"
            style={{ flex: 1 }}
            icon={<Icon name="share" size={18} color={palette.primaryForeground} />}
            onPress={() => void Share.share({ message: `My Ripar vault on ${net}: ${vault}` })}
          />
        </View>
        <Text variant="bodySmall" tone="soft">
          The vault is a smart account owned by your Ripar's key alone. Send MON or tokens on {net} only.
          {chain.vault?.deployed === false ? ' It is not deployed yet: funds sent now are safe (the address is fixed), and deploying it later makes them spendable.' : ''}
        </Text>
      </View>
    </Sheet>
  );
}
