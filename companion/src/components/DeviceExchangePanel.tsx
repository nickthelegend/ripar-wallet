// One request/response round with the device, whatever the transport: Fig. A is the request QR the device's camera
// reads (looping multipart frames), Fig. B is the device itself (EMULATOR) or this computer's camera (hardware).
// The panel only carries bytes; the caller verifies the response.
import { type ReactNode, useEffect, useRef, useState } from 'react';
import { type ExchangeEvent, DeviceExchange } from '../device/transport';
import { useDevice, useEmuState } from '../device/DeviceContext';
import type { EmulatorHost } from '../device/emulator';
import { type RoundKind, deviceGuide } from '../device/guide';
import { useStore } from '../lib/store';
import { CameraReader } from './CameraReader';
import { EmulatorDevice } from './EmulatorDevice';
import { QrPlate } from './QrPlate';
import { Button, Figure } from './ui';

export interface ExchangeProps {
  /** request frames ([] = the device initiates: nothing to show, only read) */
  parts: string[];
  expect: string[];
  accept?: (ur: string) => boolean;
  onResponse: (ur: string) => void;
  /** restart the round when this changes (e.g. the request's req-id) */
  runKey: string;
  figA?: string;
  figB?: string;
  /** what this round asks of the device: picks the default instructions and the live "Next on the device" line */
  round: RoundKind;
  /** replaces the default instructions */
  instructions?: ReactNode;
}

/** the steps on the device for each kind of round (docs/FIRMWARE.md §5) */
export function RoundSteps({ round, emulator }: { round: RoundKind; emulator: boolean }) {
  const thumb = emulator ? 'click "Place thumb" (the pulse sensor)' : 'rest your thumb on the pulse sensor';
  const items: ReactNode[] =
    round === 'keys'
      ? [
          'On the Home screen, hold SIGN for 2 s until it shows RELEASE = PAIRING QR.',
          'Release. The device shows its public keys as a QR (nothing is signed, nothing is pinned). Do not keep holding: at 5 s the device PANICs.',
        ]
      : round === 'kill'
        ? [
            'PANIC (kills every mandate): on Home, hold SIGN for 5 s. Signed at once, no pulse.',
            'REVOKE the last mandate or REOPEN the lane: on Home hold 2 s and release (pairing QR), then hold 2 s for the device menu; press to move, hold 2 s to select, page through the review, then pulse + SIGN.',
            'This page reads the QR the device shows. Relay it at once: it is shown once.',
          ]
        : [
            'If the device still shows its previous answer, press SIGN once to go Home.',
            'On Home, press SIGN to scan the request in Fig. A. The device collects the looping parts.',
            round === 'cosign' ? (
              <>
                Read every line; press SIGN for the next page. To refuse, hold SIGN 2 s on the review: the device opens a
                second review, DENY + REPORT AGENT; page through it and press SIGN on its last page (no pulse needed).
              </>
            ) : (
              'Read every line of the review; press SIGN for the next page. Holding 2 s cancels.'
            ),
            `On the last page press SIGN once more, ${thumb} until PULSE OK, then press SIGN.`,
            'This page reads the answer QR from the device.',
          ];
  return (
    <ol className="small round-steps">
      {items.map((x, i) => (
        <li key={i}>{x}</li>
      ))}
    </ol>
  );
}

/** the live next step on the EMULATOR */
function NextOnDevice({ host, round, hasRequest }: { host: EmulatorHost; round: RoundKind; hasRequest: boolean }) {
  const s = useEmuState(host);
  if (!s) return null;
  const g = deviceGuide(s, round, hasRequest, host.fingerParams.on);
  if (!g.text) return null;
  return (
    <p className={`next-on-device ${g.tone}`} role="status" aria-live="polite">
      <b>Next on the device:</b> {g.text}
    </p>
  );
}

export function DeviceExchangePanel({ parts, expect, accept, onResponse, runKey, figA = 'A', figB = 'B', round, instructions }: ExchangeProps) {
  const dev = useDevice();
  const frameMs = useStore((s) => s.settings.frameMs);
  const transport = dev.transport;
  const [frame, setFrame] = useState<{ text: string | null; index: number; total: number }>({ text: null, index: 0, total: 0 });
  const [seen, setSeen] = useState<Set<number>>(new Set());
  const [log, setLog] = useState<string | null>(null);
  const [paste, setPaste] = useState('');
  const ex = useRef<DeviceExchange | null>(null);
  const logTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => {
    if (logTimer.current) clearTimeout(logTimer.current);
  }, []);
  const cb = useRef(onResponse);
  cb.current = onResponse;
  const acc = useRef(accept);
  acc.current = accept;

  useEffect(() => {
    if (!transport) return;
    const x = new DeviceExchange(transport, {
      parts,
      expect,
      frameMs,
      accept: (u) => (acc.current ? acc.current(u) : true),
    });
    ex.current = x;
    setSeen(new Set());
    setLog(null);
    const off = x.on((e: ExchangeEvent) => {
      if (e.kind === 'frame') {
        setFrame({ text: e.frame, index: e.index, total: e.total });
        setSeen((s) => (s.has(e.index) ? s : new Set(s).add(e.index)));
      } else if (e.kind === 'ignored') {
        // shown for a while only: once the user went Home the old QR is gone and so is the hint
        if (logTimer.current) clearTimeout(logTimer.current);
        logTimer.current = setTimeout(() => setLog(null), 10_000);
        setLog(
          parts.length > 0
            ? 'The device still shows an earlier QR (not the answer to this request): press SIGN on the device to go Home, then press again to scan.'
            : 'The device shows a QR that is not what this step reads: press SIGN on the device to go Home and start again.',
        );
      } else if (e.kind === 'response') {
        setFrame({ text: null, index: 0, total: 0 });
        setLog(null);
        cb.current(e.ur);
      }
    });
    x.start().catch(() => {});
    return () => {
      off();
      x.cancel();
      if (ex.current === x) ex.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [transport, runKey, frameMs]);

  const showQr = parts.length > 0;
  return (
    <div className="stack">
      {instructions ?? <RoundSteps round={round} emulator={dev.mode === 'emulator'} />}
      {dev.mode === 'emulator' && dev.emulator && <NextOnDevice host={dev.emulator} round={round} hasRequest={showQr} />}
      <div className={`exchange${showQr ? '' : ' solo'}`}>
        {showQr && (
          <Figure
            n={figA}
            caption={
              dev.mode === 'emulator'
                ? 'The request, as the device camera sees it. The EMULATOR scans these exact frames.'
                : "The request. Point the device's camera at this screen after pressing SIGN on its Home screen."
            }
          >
            <QrPlate frame={frame.text} index={frame.index} total={frame.total} seen={seen} frameMs={frameMs} idleText="Waiting for the device..." />
          </Figure>
        )}
        <Figure
          n={figB}
          caption={
            dev.mode === 'emulator'
              ? 'The emulated device. Use its SIGN key and pulse sensor exactly as on the hardware.'
              : "This computer's camera reads the device's answer QR."
          }
        >
          {dev.mode === 'emulator' ? (
            dev.emulator ? (
              <EmulatorDevice host={dev.emulator} />
            ) : (
              <div className="stack">
                <p className="small">{dev.emulatorStatus === 'error' ? `The emulator failed to start: ${dev.emulatorError}` : 'Starting the emulator...'}</p>
                {dev.emulatorStatus === 'error' && (
                  <Button onClick={() => void dev.bootEmulator()} icon="refresh">
                    Retry
                  </Button>
                )}
              </div>
            )
          ) : (
            <CameraReader transport={dev.hardware} />
          )}
        </Figure>
      </div>
      {log && (
        <p className="exchange-log" role="status">
          {log}
        </p>
      )}
      <details className="paste">
        <summary>Paste the device's QR text instead</summary>
        <div className="row">
          <textarea
            className="textarea data"
            aria-label="Response QR text (UR:RIPAR-...)"
            placeholder="UR:RIPAR-..."
            value={paste}
            onChange={(e) => setPaste(e.target.value)}
            rows={3}
          />
          <Button
            onClick={() => {
              ex.current?.read(paste);
              setPaste('');
            }}
            disabled={!paste.trim()}
          >
            Use this response
          </Button>
        </div>
      </details>
    </div>
  );
}
