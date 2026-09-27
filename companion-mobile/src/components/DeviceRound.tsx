// One request/answer round with the device, over whichever link is active. The screen hands it the request (null for
// a message the device starts itself: keys-only pairing QR, PANIC, revoke, reopen) and a verifier; this component
// shows the request (animated QR / Bluetooth progress / emulator), the device-side steps, the live device status where
// the link has one, reads the answer and calls onVerified with the verified result. The link helpers do the work
// (device/link.ts requestAndVerify); this is only their UI.
import type { BuiltRequest } from '@ripar/protocol';
import { useRouter } from 'expo-router';
import { useEffect, useRef, useState } from 'react';
import { StyleSheet, useWindowDimensions, View } from 'react-native';
import { useDeviceLink, useObservable } from '../device/DeviceLinkProvider';
import type { BleLink } from '../device/ble-link';
import { EmulatorPanel } from '../device/emulator/EmulatorPanel';
import { type RoundKind, liveGuide, refusalHelp, roundSteps, stepOfScreen } from '../device/guide';
import { DeviceCancelledError, DeviceLinkError, type DeviceLink, type DeviceStatus, type Verifier, requestAndVerify } from '../device/link';
import type { WifiLink } from '../device/wifi-link';
import { errorText } from '../lib/format';
import { failed, succeeded } from '../lib/haptics';
import { store, useStore } from '../lib/store';
import { palette, space } from '../theme';
import { Button } from './Button';
import { CameraScanner } from './CameraScanner';
import { Icon } from './Icon';
import { AnimatedQr } from './Qr';
import { Note, Pill, Steps } from './Rows';
import { Surface } from './Surface';
import { Label, Mono, Text } from './Text';

/** linkError: the request or the answer did not get through (link, timeout); otherwise the answer was refused */
type Phase = { kind: 'waiting' } | { kind: 'verified' } | { kind: 'error'; message: string; linkError: boolean };

export function DeviceRound<T>({
  request,
  verifier,
  onVerified,
  kind,
  runKey,
  title,
}: {
  request: BuiltRequest | null;
  verifier: Verifier<T>;
  onVerified: (result: T, ur: string) => void;
  kind: RoundKind;
  /** a new value starts a new round (e.g. the request's req-id) */
  runKey: string;
  title?: string;
}) {
  const { link, qr, bleConn, wifiConn, reconnectWifi } = useDeviceLink();
  const linkChoice = useStore((s) => s.settings.link);
  const wifiSaved = useStore((s) => s.settings.wifiHost);
  const router = useRouter();
  const { width } = useWindowDimensions();
  const [phase, setPhase] = useState<Phase>({ kind: 'waiting' });
  const [ignored, setIgnored] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [showCamera, setShowCamera] = useState(request === null);
  const verifierRef = useRef(verifier);
  verifierRef.current = verifier;
  const onVerifiedRef = useRef(onVerified);
  onVerifiedRef.current = onVerified;

  const status = useObservable(link?.status ?? null);
  const frames = useObservable(link?.kind === 'qr' ? qr.frames : null);
  // Bluetooth and Wi-Fi share the phases: waiting for SCAN, sending part i of n, sent
  const blePhase = useObservable(link?.kind === 'ble' ? (link as BleLink).phase : link?.kind === 'wifi' ? (link as WifiLink).phase : null);
  const wifiHealth = useObservable(link?.kind === 'wifi' ? (link as WifiLink).conn : null);
  const [reconnecting, setReconnecting] = useState(false);

  useEffect(() => {
    if (!link) return;
    const ctl = new AbortController();
    setPhase({ kind: 'waiting' });
    setIgnored(null);
    // an answer still on the device's screen counts again for a new round (QR camera, Wi-Fi /tx)
    (link as DeviceLink & { resetReads?: () => void }).resetReads?.();
    const v = verifierRef.current;
    requestAndVerify(link, request, v, {
      signal: ctl.signal,
      onIgnored: (_t, reason) => setIgnored(reason),
    }).then(
      ({ ur, result }) => {
        if (ctl.signal.aborted) return;
        stopPresenting(link);
        succeeded();
        setPhase({ kind: 'verified' });
        onVerifiedRef.current(result, ur);
      },
      (e) => {
        if (e instanceof DeviceCancelledError || ctl.signal.aborted) return;
        failed();
        setPhase({ kind: 'error', message: errorText(e), linkError: e instanceof DeviceLinkError });
      },
    );
    return () => {
      ctl.abort();
      stopPresenting(link);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [link, runKey, attempt]);

  const linkKind = link?.kind ?? linkChoice;
  const steps = roundSteps(kind, linkKind);
  const live = status ? liveGuide(status, kind, !!request) : null;
  const qrSize = Math.min(width - 80, 320);

  if (!link) {
    return (
      <Surface padded={20} style={{ gap: space.md }}>
        {linkChoice === 'ble' ? (
          <>
            <Note tone="warn" title="Bluetooth is not connected">
              {bleConn.state === 'error'
                ? `The last attempt failed: ${bleConn.message}`
                : 'Connect to your Ripar over Bluetooth first, or switch back to QR (the air-gapped default).'}
            </Note>
            <Button label="Connect over Bluetooth" icon={<Icon name="bluetooth" size={18} color={palette.primaryForeground} />} onPress={() => router.push('/link')} />
            <Button label="Use QR instead" variant="secondary" onPress={() => store.setSettings({ link: 'qr' })} />
          </>
        ) : linkChoice === 'wifi' ? (
          <>
            <Note tone="warn" icon="wifi" title="Wi-Fi link is not connected">
              {wifiConn.state === 'error'
                ? `The last attempt failed: ${wifiConn.message}`
                : wifiConn.state === 'connecting'
                  ? `Connecting to ${wifiConn.host}...`
                  : 'Connect to your Ripar over Wi-Fi first (testing only), or switch back to QR (the air-gapped default).'}
            </Note>
            {!!wifiSaved && (
              <Button
                label={`Reconnect ${wifiSaved}`}
                loading={reconnecting || wifiConn.state === 'connecting'}
                icon={<Icon name="wifi" size={18} color={palette.primaryForeground} />}
                onPress={() => {
                  setReconnecting(true);
                  reconnectWifi()
                    .catch(() => {})
                    .finally(() => setReconnecting(false));
                }}
              />
            )}
            <Button label="Wi-Fi setup" variant="secondary" onPress={() => router.push('/wifi')} />
            <Button label="Use QR instead" variant="secondary" onPress={() => store.setSettings({ link: 'qr' })} />
          </>
        ) : (
          <Text variant="bodySmall" tone="soft">
            Starting the emulator...
          </Text>
        )}
      </Surface>
    );
  }

  return (
    <View style={{ gap: space.lg }}>
      {title ? <Text variant="heading">{title}</Text> : null}

      {link.kind === 'qr' && request && frames && !showCamera && (
        <Surface padded={18} style={{ alignItems: 'center', gap: space.md }}>
          <Label>Show this to the Ripar's camera</Label>
          <AnimatedQr frames={frames} size={qrSize} />
          <Button
            label="The Ripar shows its answer"
            icon={<Icon name="camera" size={18} color={palette.primaryForeground} />}
            onPress={() => setShowCamera(true)}
            full
          />
        </Surface>
      )}

      {link.kind === 'qr' && (showCamera || !request) && phase.kind === 'waiting' && (
        <View style={{ gap: space.sm }}>
          <CameraScanner onRead={(t) => qr.cameraRead(t)} hint={kind === 'keys' ? 'Point at the pairing QR on the Ripar' : "Point at the Ripar's answer QR"} />
          {request && <Button label="Show the request QR again" variant="ghost" size="sm" onPress={() => setShowCamera(false)} />}
        </View>
      )}

      {(link.kind === 'ble' || link.kind === 'wifi') && (
        <Surface padded={18} style={{ gap: space.md }}>
          <View style={styles.rowBetween}>
            {link.kind === 'ble' ? <Pill label="Bluetooth fallback" icon="bluetooth" tone="info" /> : <Pill label="Wi-Fi · testing" icon="wifi" tone="info" />}
            <Pill label="Not air-gapped" icon="radio" tone="warn" />
          </View>
          {wifiHealth?.state === 'offline' && <Note tone="bad" title="The Ripar does not answer over Wi-Fi">{wifiHealth.message}</Note>}
          {wifiHealth?.state === 'locked' && <Note tone="bad" title="Wi-Fi link locked">{wifiHealth.message}</Note>}
          <DeviceStatusLine status={status} />
          {status?.note ? (
            <Text variant="bodySmall" tone="warn">
              Device: {status.note}
            </Text>
          ) : null}
          {blePhase?.kind === 'waiting-scan' && (
            <Note tone="warn" title="Press SIGN on the Ripar">
              The device accepts a request only while it is scanning: press SIGN once on its Home screen.
            </Note>
          )}
          {blePhase?.kind === 'sending' && (
            <Text variant="bodySmall" tone="soft">
              Sending part {blePhase.part} of {blePhase.of}
              {blePhase.round > 1 ? ` (again, round ${blePhase.round})` : ''}...
            </Text>
          )}
        </Surface>
      )}

      {link.kind === 'emulator' && <EmulatorPanel width={Math.min(width - 40, 360)} />}

      {live && (
        <Note tone={live.tone === 'bad' ? 'bad' : live.tone === 'good' ? 'good' : live.tone === 'warn' ? 'warn' : 'info'} icon="device">
          {live.text}
        </Note>
      )}

      <Surface padded={18} style={{ gap: space.md }}>
        <Label>On the Ripar</Label>
        <Steps steps={steps} current={status ? stepOfScreen(status.screen, kind) : undefined} />
      </Surface>

      {ignored && phase.kind === 'waiting' && (
        <Text variant="bodySmall" tone="faint">
          Ignored a QR: {ignored}
        </Text>
      )}

      {phase.kind === 'error' && (
        <View style={{ gap: space.md }}>
          <Note tone="bad" title={phase.linkError ? 'The round did not get through' : 'The answer was not accepted'}>
            {`${phase.message}${refusalHelp(phase.message) ? `\n${refusalHelp(phase.message)}` : ''}`}
          </Note>
          <Button label="Try again" variant="secondary" onPress={() => setAttempt((a) => a + 1)} />
        </View>
      )}
      {phase.kind === 'verified' && (
        <Note tone="good" title="Answer verified">
          Signatures checked against the request and your device's keys.
        </Note>
      )}
    </View>
  );
}

function stopPresenting(link: DeviceLink) {
  const l = link as DeviceLink & { stopPresenting?: () => void };
  l.stopPresenting?.();
}

/** one line: the device screen, pairing and scan progress from its live status */
export function DeviceStatusLine({ status }: { status: DeviceStatus | null }) {
  if (!status) {
    return (
      <Text variant="bodySmall" tone="faint">
        No status from the device yet.
      </Text>
    );
  }
  return (
    <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: space.sm, alignItems: 'center' }}>
      <Pill label={status.screen} tone="signal" icon="device" />
      <Pill label={status.paired ? 'paired' : 'not paired'} tone={status.paired ? 'good' : 'plain'} />
      {status.scan && status.scan.of > 0 ? <Pill label={`${status.scan.got}/${status.scan.of} parts`} tone="info" /> : null}
      {status.wifi ? <Pill label={`Wi-Fi ${status.wifi}${status.ip ? ` · ${status.ip}` : ''}`} tone={status.wifi === 'off' ? 'plain' : 'warn'} icon="wifi" /> : null}
      {status.fw ? <Mono small>{status.fw}</Mono> : null}
    </View>
  );
}

const styles = StyleSheet.create({
  rowBetween: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
});

