import { Pressable, StyleSheet, View } from 'react-native';
import { tap } from '../lib/haptics';
import { palette, radius, space } from '../theme';
import { Icon } from './Icon';
import { Text } from './Text';

const KEYS = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '.', '0', 'del'] as const;

export { applyKey } from '../lib/keypad';

export function Keypad({ onKey }: { onKey: (k: string) => void }) {
  return (
    <View style={styles.grid}>
      {KEYS.map((k) => (
        <Pressable
          key={k}
          onPressIn={tap}
          onPress={() => onKey(k)}
          accessibilityRole="button"
          accessibilityLabel={k === 'del' ? 'Delete' : k === '.' ? 'Decimal point' : k}
          style={({ pressed }) => [styles.key, pressed && { backgroundColor: palette.cardHigh, transform: [{ scale: 0.96 }] }]}
        >
          {k === 'del' ? <Icon name="backspace" size={24} color={palette.foreground} /> : <Text variant="title">{k}</Text>}
        </Pressable>
      ))}
    </View>
  );
}

const styles = StyleSheet.create({
  grid: { flexDirection: 'row', flexWrap: 'wrap', justifyContent: 'space-between', rowGap: space.sm },
  key: { width: '31.5%', height: 50, borderRadius: radius.lg, alignItems: 'center', justifyContent: 'center' },
});
