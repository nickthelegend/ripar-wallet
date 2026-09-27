import * as Clipboard from 'expo-clipboard';
import { useState } from 'react';
import { Pressable, View } from 'react-native';
import { hexGroups } from '../lib/format';
import { tap } from '../lib/haptics';
import { palette, space } from '../theme';
import { Icon } from './Icon';
import { Mono, Text } from './Text';

/**
 * A full address (or hash), in 4-character groups: never shortened where the user decides something (the device
 * shows the full EIP-55 form too). Tap to copy.
 */
export function Address({ value, label, tone = 'default' }: { value: string; label?: string; tone?: 'default' | 'soft' }) {
  const [copied, setCopied] = useState(false);
  return (
    <Pressable
      onPress={async () => {
        tap();
        await Clipboard.setStringAsync(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 1400);
      }}
      accessibilityRole="button"
      accessibilityLabel={`${label ?? 'Value'} ${value}. Tap to copy.`}
      style={{ flexDirection: 'row', alignItems: 'flex-start', gap: space.sm }}
    >
      <Mono tone={tone === 'soft' ? 'soft' : 'default'} style={{ flex: 1 }}>
        {hexGroups(value).join(' ')}
      </Mono>
      <View style={{ paddingTop: 1 }}>
        {copied ? (
          <Text variant="label" tone="success">
            copied
          </Text>
        ) : (
          <Icon name="copy" size={15} color={palette.mutedForeground} />
        )}
      </View>
    </Pressable>
  );
}
