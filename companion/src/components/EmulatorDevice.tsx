// The EMULATOR drawn as the device: graphite body, the 320 x 240 LCD painted from the firmware's own screen state,
// the SIGN key (press / hold 2 s / hold 5 s, by pointer or keyboard), and the pulse sensor window with a synthetic
// thumb. Always stamped EMULATOR - DEMO KEYS.
import { useEffect, useRef, useState } from 'react';
import { useEmuState } from '../device/DeviceContext';
import type { EmulatorHost } from '../device/emulator';
import { LCD_H, LCD_W, describeLcd, drawLcd } from '../device/lcd';
import { Icon } from './Icon';
import { EmulatorMark } from './ui';

const SCREEN_NAMES: Record<string, string> = {
  home: 'Home',
  homeHold: 'Hold (release = pairing QR, keep holding = PANIC)',
  scan: 'Scan',
  review: 'Review',
  pulse: 'Pulse',
  armed: 'Armed: press SIGN',
  qr: 'Response QR',
  message: 'Message',
  pairQr: 'Pairing QR (keys only)',
  menu: 'Device menu',
  fail: 'SELFTEST FAIL',
};

export function EmulatorDevice({ host, compact = false }: { host: EmulatorHost; compact?: boolean }) {
  const s = useEmuState(host);
  const canvas = useRef<HTMLCanvasElement>(null);
  const lastSeq = useRef(-1);
  const [down, setDown] = useState(false);
  const [downAt, setDownAt] = useState(0);
  const [holdMs, setHoldMs] = useState(0);
  const [bpm, setBpm] = useState(host.fingerParams.bpm || 72);
  const beat = s ? s.buzz.last === 'beat' && s.nowMs - s.buzz.lastAtMs < 160 : false;

  // paint the LCD whenever the firmware drew a new frame (and on beats, for the heart)
  useEffect(() => {
    const c = canvas.current;
    if (!c || !s) return;
    const dpr = Math.min(3, window.devicePixelRatio || 1);
    if (c.width !== LCD_W * dpr) {
      c.width = LCD_W * dpr;
      c.height = LCD_H * dpr;
      lastSeq.current = -1;
    }
    const key = s.display.seq * 2 + (beat ? 1 : 0);
    if (key === lastSeq.current) return;
    lastSeq.current = key;
    const g = c.getContext('2d');
    if (!g) return;
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    drawLcd(g, s.display, s, beat);
  }, [s, beat]);

  // hold meter
  useEffect(() => {
    if (!down) {
      setHoldMs(0);
      return;
    }
    const t = setInterval(() => setHoldMs(performance.now() - downAt), 50);
    return () => clearInterval(t);
  }, [down, downAt]);

  const downRef = useRef(false);
  const press = () => {
    if (downRef.current) return;
    downRef.current = true;
    setDown(true);
    setDownAt(performance.now());
    host.keyDown();
  };
  const release = () => {
    if (!downRef.current) return;
    downRef.current = false;
    setDown(false);
    host.keyUp();
  };

  if (!s) return null;
  const fingerOn = host.fingerParams.on;
  const cells = Array.from({ length: 10 }, (_, i) => (i + 1) * 500 <= holdMs);

  return (
    <div className="device">
      <div className="device-body" data-key={down ? 'down' : 'up'} data-finger={fingerOn ? 'on' : 'off'} data-beat={beat ? 'on' : 'off'}>
        <span className="device-sign" aria-hidden="true" />
        <span className="device-lens" aria-hidden="true" />
        <div className="device-screen">
          <canvas ref={canvas} width={LCD_W} height={LCD_H} aria-hidden="true" />
        </div>
        <span className="device-sensor" aria-hidden="true">
          <i />
        </span>
        <span className="device-stamp emu" aria-hidden="true">
          EMULATOR
        </span>
      </div>
      <p className="sr-only" aria-live="polite">
        {describeLcd(s.display)}
      </p>

      {!compact && (
        <div className="device-controls">
          <div className="sign-key">
            <button
              type="button"
              data-down={down}
              aria-pressed={down}
              aria-describedby="sign-help"
              onPointerDown={(e) => {
                e.currentTarget.setPointerCapture(e.pointerId);
                press();
              }}
              onPointerUp={release}
              onPointerCancel={release}
              onLostPointerCapture={release}
              onKeyDown={(e) => {
                if ((e.key === ' ' || e.key === 'Enter') && !e.repeat) {
                  e.preventDefault();
                  press();
                }
              }}
              onKeyUp={(e) => {
                if (e.key === ' ' || e.key === 'Enter') {
                  e.preventDefault();
                  release();
                }
              }}
              onBlur={release}
            >
              SIGN
            </button>
            <div className="hold-meter" aria-hidden="true">
              {cells.map((lit, i) => (
                <i key={i} className={lit ? (i >= 4 ? 'lit panic' : 'lit') : undefined} />
              ))}
            </div>
            <div className="hold-scale" id="sign-help">
              <span>press</span>
              <span>2 s hold</span>
              <span>5 s PANIC</span>
            </div>
          </div>
          <div className="finger">
            <button
              type="button"
              className="toggle"
              aria-pressed={fingerOn}
              onClick={() => host.setFinger({ on: !fingerOn, bpm })}
            >
              <Icon name="finger" />
              {fingerOn ? 'Thumb on sensor' : 'Place thumb'}
            </button>
            <label className="bpm">
              <span>
                <Icon name="heart" size={14} /> {bpm} bpm
              </span>
              <input
                type="range"
                min={40}
                max={180}
                value={bpm}
                aria-label="Synthetic pulse, beats per minute"
                onChange={(e) => {
                  const v = Number(e.target.value);
                  setBpm(v);
                  if (fingerOn) host.setFinger({ bpm: v });
                }}
              />
            </label>
          </div>
        </div>
      )}

      <div className="device-status">
        <EmulatorMark />
        <span>Screen: {SCREEN_NAMES[s.screen] ?? s.screen}</span>
        <span>{s.paired ? `Paired to ${s.context.chain}` : 'Not paired'}</span>
        {s.pulse.sensorOn && <span>Pulse {s.pulse.finger ? `${Math.round(s.pulse.bpm)} bpm, ${s.pulse.beats}/${s.pulse.minBeats} beats` : 'no finger'}</span>}
      </div>
    </div>
  );
}
