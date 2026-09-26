# Ripar Wallet v1: air-gapped, pulse-verified hardware signer

A camera-shaped, air-gapped signer for the **Monad Metropolis** hackathon. The same shell later becomes a digital camera.

- The **camera** reads a transaction QR.
- The **screen** shows what you're about to sign.
- Your **thumb** rests on a **MAX30102 pulse sensor**. The device signs only while a real heartbeat is present *and* you press **SIGN**. It then shows the signature as a QR.

![renders](model/renders/sheet.png)

## What's here

| Path | What |
|---|---|
| `print/bambu/` | **Sliced, ready-to-print P1S files**: `FitTest_P1S.gcode.3mf` (about 40 min) and `RiparWallet_P1S.gcode.3mf` (about 1 h 50 min, 54 g PLA) |
| `print/stl/` | STLs for the Bambu P1S, pre-oriented: Front_Shell, Back_Shell, Sign_Pin, and 2 fit-test coupons |
| `print/step/` | STEP files of every printable part plus the full assembly (for Fusion, FreeCAD or sharing) |
| `print/PRINTING.md` | Slicer settings, what to measure first, assembly order, fixes |
| `docs/WIRING.md` | Header pinout from the Waveshare schematic, free GPIOs, and every connection |
| `model/RiparWallet.SLDASM` | SolidWorks 2026 assembly: native parts plus component stand-ins |
| `model/parts/*.SLDPRT` | Native SolidWorks parts (feature trees built by script) |
| `model/renders/` | Renders; `sheet.png` is the overview |
| `model/interference_report.json` | SolidWorks interference detection result |
| `cad/` | The parametric CAD pipeline (Python → SolidWorks COM) |
| `research/` | CAD design reviews (fit, printability, assembly) and researched part dimensions |

## The enclosure

- **Size:** 100 × 62 × 32 mm, landscape, camera-shaped.
- **Two shells, no screws.** They meet at a parting line 13 mm behind the screen.
  - A 1.26 mm lip on the front shell slides into a rebate in the back shell.
  - A 0.25 mm ramped **snap bead** clicks into a groove.
  - To open, put a fingernail in the notch on the bottom seam.
- **The board stays put with no fasteners.** The Waveshare ESP32-S3-LCD-2 sits glass-first against the screen window, located by the top and left walls plus two printed fences. Four flat pegs in the back shell press on its M2 SMT nuts when you close it.
- **Every other part drops into a printed cradle:**
  - 18650 cell: saddles plus hold-down ribs;
  - TP4056 USB-C: cradle;
  - 12 mm latching power switch: square cradle with a floor stop;
  - MAX30102: pocket with a 0.7 mm skin and a 10 × 8 mm chamfered thumb window, backed by two posts;
  - INMP441: slide-in rails under the top wall with a Ø1.5 port;
  - buzzer: U-cradle behind a 7-hole grille.
- **The camera looks out through a 33° lens hood.** The OV5640 sits on the back of the board, and the hood is sized so even the 68° diagonal field of view isn't clipped. It doubles as the QR scanner.
- **Lettering:** "RIPAR WALLET" is debossed on the top and bottom faces, and "RIPAR" on the lens face.
- **Checked in SolidWorks:** interference detection found **0 unexpected collisions**. The only hits are header pins inside their jumper plugs, which is correct, plus sub-0.03 mm³ contact slivers at the TP4056 port. All STLs are watertight.

**Change a dimension:** edit `cad/design.py`, then run:

```bash
python cad/make_all.py
```

That rebuilds the parts, the assembly, the interference check, the STL/STEP exports, the sliced P1S files and the renders, in about 15–20 min.

- **Requirements:**
  - Windows with **SolidWorks 2026** at its default install path;
  - **Bambu Studio** at `D:\Program Files\Bambu Studio` (edit `BS` in `cad/slice_bambu.py` if yours is elsewhere);
  - Python 3 with `pywin32`, `numpy`, `trimesh`, `Pillow`.
- It uses its own SolidWorks session; run only one SolidWorks at a time.

## Monad Metropolis

- **Track:** 04, Trust, Identity & AI Infrastructure.
- **Pitch:** a camera-shaped, air-gapped signer that puts a live human thumb between AI agents and your money.
  - An AI agent holds a scoped MetaMask delegation on Monad and spends inside its mandate by itself.
  - Anything bigger, to a new payee, or after the risk sentinel trips, needs a P-256 co-signature from Ripar. Monad's precompile at `0x0100` checks it (about 6,900 gas).
  - Ripar produces that signature only after it has decoded the request itself and felt a live pulse.
- **Sponsor integrations we plan:**

| Bounty | What we build |
|---|---|
| Qwen 3.8 Max | the treasury agent itself |
| Privy | server wallet whose owner quorum is the device's P-256 key, plus gas sponsorship |
| Nansen | payee risk classes that force a second pulse |
| Mera | PRF-encrypted agent memory |
| Chainlink CRE | sentinel that can only *close* the autonomous lane |
| Envio | HyperIndex trust dashboard |
| Alchemy | RPC plus webhooks |

**Fallback if camera QR scanning is unreliable:** request files on the TF card, plus a clearly labelled browser emulator of the device.
