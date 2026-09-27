// 2 Device: hardware (this camera + an animated QR) or the in-page EMULATOR (the real firmware in WASM).
import { PageHead } from '../App';
import { CameraReader } from '../components/CameraReader';
import { EmulatorDevice } from '../components/EmulatorDevice';
import { Button, EmulatorMark, Figure, Hex, Note, Spec } from '../components/ui';
import { useDevice, useEmuState } from '../device/DeviceContext';

const KEYS: [string, string, string, string][] = [
  ['Home', 'scan a request', 'release = pairing QR (keys only); keep holding = device menu', 'PANIC, signed at once'],
  ['Review', 'next page; on the last page: continue to PULSE', 'co-sign review: DENY; other reviews: cancel', '-'],
  ['Pulse', 'ignored', 'cancel', '-'],
  ['Armed', 'SIGN (only while the pulse is live)', 'cancel', '-'],
  ['QR / message', 'done, back to Home', 'done', '-'],
  ['Device menu', 'next item (REVOKE, REOPEN, BACK)', 'select', '-'],
];

export function Device() {
  const dev = useDevice();
  const s = useEmuState(dev.emulator);
  return (
    <div className="page">
      <PageHead
        no="2"
        title="Device"
        lede="Choose the signer. The physical Ripar reads requests with its camera and answers with one QR; the EMULATOR runs the same firmware in this page and is fed the very same QR frames."
      />
      <fieldset className="options" style={{ border: 0, padding: 0, margin: 0 }}>
        <legend className="sr-only">Signer</legend>
        <label className="option">
          <input type="radio" name="mode" checked={dev.mode === 'hardware'} onChange={() => dev.setMode('hardware')} />
          <b>Ripar hardware</b>
          <span>Air-gapped. The request loops as an animated QR on this screen; this computer's camera reads the answer.</span>
        </label>
        <label className="option">
          <input type="radio" name="mode" checked={dev.mode === 'emulator'} onChange={() => dev.setMode('emulator')} />
          <b>
            EMULATOR <EmulatorMark />
          </b>
          <span>The firmware compiled to WebAssembly, with a synthetic thumb. For demos only: its keys live in this browser.</span>
        </label>
      </fieldset>

      {dev.mode === 'emulator' ? (
        <section className="section">
          <h2>The emulated device</h2>
          <div className="cols-wide">
            <Figure n="2.1" caption="Ripar EMULATOR. The LCD is drawn from the firmware's own screen state.">
              {dev.emulator ? (
                <EmulatorDevice host={dev.emulator} />
              ) : (
                <p className="small">{dev.emulatorStatus === 'error' ? `The emulator failed to start: ${dev.emulatorError}` : 'Starting the emulator...'}</p>
              )}
            </Figure>
            <div className="stack">
              <Note kind="warning" title="Demo keys">
                <p>
                  The emulated device keeps its seed in this browser's storage. Anyone with access to this browser
                  profile can copy it. Never put real funds behind an EMULATOR vault.
                </p>
              </Note>
              {s && (
                <Spec
                  rows={[
                    { k: 'K1 (owner)', v: <Hex value={s.k1} /> },
                    { k: 'Keys', v: dev.emulator?.mode === 'demo-seed' ? 'public demo seed (make_request DEMO_SEED)' : 'random seed, this browser only' },
                    { k: 'Firmware id', v: <code>{s.firmwareId}</code> },
                    { k: 'Pinned', v: s.paired ? s.context.chain : 'not paired' },
                    s.paired && s.context.vault && { k: 'Pinned vault', v: <Hex value={s.context.vault} /> },
                    s.paired && { k: 'Panic floor', v: s.context.minEpoch },
                    s.paired && { k: 'Reopen nonce', v: s.context.reopenNonce },
                    s.paired && { k: 'Device time', v: s.context.notBeforeUtc },
                    { k: 'Self-test', v: s.selftest.passed ? 'passed' : 'FAILED' },
                  ]}
                />
              )}
              <div className="row">
                <Button
                  variant="danger"
                  icon="refresh"
                  busy={dev.emulatorStatus === 'loading'}
                  onClick={() => {
                    if (confirm('Erase the emulated device (new random keys)? Its pairing and vault are lost.')) void dev.resetEmulator('random');
                  }}
                >
                  New device, random keys
                </Button>
                <Button
                  icon="refresh"
                  busy={dev.emulatorStatus === 'loading'}
                  onClick={() => {
                    if (confirm('Replace the emulated device with the public demo-seed device?')) void dev.resetEmulator('demo-seed');
                  }}
                >
                  Demo-seed device
                </Button>
              </div>
            </div>
          </div>
        </section>
      ) : (
        <section className="section">
          <h2>Camera check</h2>
          <p>
            Start the camera and hold the device's Home screen QR (hold SIGN 2 s, release) in front of it. The Pair page
            uses the same reader.
          </p>
          <div style={{ maxWidth: 520, marginTop: 16 }}>
            <Figure n="2.1" caption="This computer's camera. Only QR text is read; nothing is recorded.">
              <CameraReader transport={dev.hardware} />
            </Figure>
          </div>
        </section>
      )}

      <section className="section">
        <h2>Screens and the SIGN key</h2>
        <p>
          One key does everything. A press or a hold only acts on the screen where it began. Every screen except Home
          returns to Home after 120 s.
        </p>
        <div className="ledger-wrap" style={{ marginTop: 16 }}>
          <table className="ledger keys-table">
            <thead>
              <tr>
                <th scope="col">Screen</th>
                <th scope="col">Press</th>
                <th scope="col">Hold 2 s</th>
                <th scope="col">Hold 5 s</th>
              </tr>
            </thead>
            <tbody>
              {KEYS.map((r) => (
                <tr key={r[0]}>
                  {r.map((c, i) => (
                    <td key={i}>{c}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
