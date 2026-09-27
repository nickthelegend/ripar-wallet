// Reads the device's response QR with this computer's camera (qr-scanner) and hands every decode to the hardware
// transport. The camera runs only while this view is mounted and started.
import QrScanner from 'qr-scanner';
import { useEffect, useRef, useState } from 'react';
import type { HardwareQrTransport } from '../device/transport';
import { Button } from './ui';

export function CameraReader({ transport, autoStart = false }: { transport: HardwareQrTransport; autoStart?: boolean }) {
  const video = useRef<HTMLVideoElement>(null);
  const scanner = useRef<QrScanner | null>(null);
  const [on, setOn] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [last, setLast] = useState<string | null>(null);

  const start = async () => {
    setError(null);
    if (!video.current) return;
    try {
      if (!(await QrScanner.hasCamera())) {
        setError('No camera found. Paste the QR text from any reader instead.');
        return;
      }
      scanner.current ??= new QrScanner(
        video.current,
        (r) => {
          setLast(r.data.slice(0, 24));
          transport.cameraRead(r.data);
        },
        { returnDetailedScanResult: true, preferredCamera: 'environment', maxScansPerSecond: 12 },
      );
      await scanner.current.start();
      setOn(true);
    } catch (e) {
      setError(`Camera unavailable: ${(e as Error).message ?? String(e)}`);
    }
  };

  const stop = () => {
    scanner.current?.stop();
    setOn(false);
  };

  useEffect(() => {
    if (autoStart) void start();
    return () => {
      scanner.current?.destroy();
      scanner.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="stack">
      <div className="camera">
        <video ref={video} muted playsInline aria-label="Camera view for the device's response QR" />
        {!on && <div className="off">Camera off. Start it, then hold the device's QR screen in front of it.</div>}
        {on && <div className="aim" aria-hidden="true" />}
      </div>
      <div className="row">
        {on ? (
          <Button onClick={stop} icon="pause" size="small">
            Stop camera
          </Button>
        ) : (
          <Button onClick={start} icon="camera" size="small" variant="primary">
            Start camera
          </Button>
        )}
        {last && <span className="xs muted">Last read: {last}...</span>}
      </div>
      {error && <p className="small" style={{ color: 'var(--bad)' }}>{error}</p>}
    </div>
  );
}
