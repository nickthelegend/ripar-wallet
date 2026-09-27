import { CameraView, useCameraPermissions } from 'expo-camera';
import { useIsFocused } from 'expo-router';
import { StyleSheet, View } from 'react-native';
import { ink, palette, radius, space } from '../theme';
import { Button } from './Button';
import { Icon } from './Icon';
import { Text } from './Text';

/**
 * The phone's camera reading the device's answer QR. Every decoded frame is handed to `onRead` (the QrLink drops
 * repeats within 1 s). Only mounted while a round waits for an answer, and paused when the screen loses focus.
 */
export function CameraScanner({ onRead, height = 260, hint }: { onRead: (text: string) => void; height?: number; hint?: string }) {
  const [perm, request] = useCameraPermissions();
  const focused = useIsFocused();

  if (!perm) return <View style={[styles.box, { height }]} />;
  if (!perm.granted) {
    return (
      <View style={[styles.box, styles.center, { height, gap: space.md, padding: space.lg }]}>
        <Icon name="camera" size={28} color={palette.steel} />
        <Text variant="bodySmall" tone="soft" style={{ textAlign: 'center' }}>
          The camera reads the QR your Ripar shows. Nothing leaves the phone.
        </Text>
        <Button label={perm.canAskAgain ? 'Allow the camera' : 'Camera blocked: open settings'} size="sm" variant="secondary" onPress={() => void request()} />
      </View>
    );
  }
  return (
    <View style={[styles.box, { height }]}>
      {focused && (
        <CameraView
          style={StyleSheet.absoluteFill}
          facing="back"
          barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
          onBarcodeScanned={(r) => {
            if (r?.data) onRead(r.data);
          }}
        />
      )}
      <View style={[StyleSheet.absoluteFill, styles.center, { pointerEvents: 'none' }]}>
        <View style={styles.reticle} />
      </View>
      {hint ? (
        <View style={[styles.hint, { pointerEvents: 'none' }]}>
          <Text variant="bodySmall" style={{ color: palette.foreground }}>
            {hint}
          </Text>
        </View>
      ) : null}
    </View>
  );
}

const styles = StyleSheet.create({
  box: { borderRadius: radius.xl, overflow: 'hidden', backgroundColor: '#000', borderWidth: 1, borderColor: ink.hairline },
  center: { alignItems: 'center', justifyContent: 'center' },
  reticle: { width: '62%', aspectRatio: 1, borderRadius: radius.lg, borderWidth: 2, borderColor: palette.primary },
  hint: {
    position: 'absolute',
    left: space.md,
    right: space.md,
    bottom: space.md,
    padding: space.sm,
    borderRadius: radius.md,
    backgroundColor: 'rgba(13,14,16,0.72)',
  },
});
