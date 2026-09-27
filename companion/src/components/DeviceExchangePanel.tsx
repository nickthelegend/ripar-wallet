// One request/response round with the device, whatever the transport: Fig. A is the request QR the device's camera
// reads (looping multipart frames), Fig. B is the device itself (EMULATOR) or this computer's camera (hardware).
// The panel only carries bytes; the caller verifies the response.
import { type ReactNode, useEffect, useRef, useState } from 'react';
import { type ExchangeEvent, DeviceExchange } from '../device/transport';
import { useDevice } from '../device/DeviceContext';
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
  instructions?: ReactNode;
}

export function DeviceExchangePanel({ parts, expect, accept, onResponse, runKey, figA = 'A', figB = 'B', instructions }: ExchangeProps) {
  const dev = useDevice();
  const frameMs = useStore((s) => s.settings.frameMs);
  const transport = dev.transport;
  const [frame, setFrame] = useState<{ text: string | null; index: number; total: number }>({ text: null, index: 0, total: 0 });
  const [seen, setSeen] = useState<Set<number>>(new Set());
  const [log, setLog] = useState<string | null>(null);
  const [paste, setPaste] = useState('');
  const ex = useRef<DeviceExchange | null>(null);
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
        setLog(`Ignored a QR on the device's screen (${e.reason}). Waiting for the answer to this request.`);
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
      {instructions}
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
