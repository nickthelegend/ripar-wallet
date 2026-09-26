# Ripar Wallet v1: air-gapped, pulse-verified hardware signer

A camera-shaped, air-gapped signer for the **Monad Metropolis** hackathon. The same shell later becomes a digital camera.

- The **camera** reads a transaction QR.
- The **screen** shows what you're about to sign.
- Your **thumb** rests on a **MAX30102 pulse sensor**. The device signs only while a real heartbeat is present *and* you press **SIGN**. It then shows the signature as a QR.

![renders](model/renders/sheet.png)

## What's here

| Path | What |
|---|---|
| `print/bambu/` | **Sliced, ready-to-print P1S file**: `RiparWallet_ALL_P1S.gcode.3mf`, with every part on one plate (about 2 h 23 min, 69.5 g PLA) |
| `print/stl/` | STLs for the Bambu P1S, pre-oriented: Front_Shell, Back_Shell, Sign_Pin, and 2 fit-test coupons |
| `print/step/` | STEP files of every printable part plus the full assembly (for Fusion, FreeCAD or sharing) |
| `print/PRINTING.md` | Slicer settings, what to measure first, assembly order, fixes |
| `docs/WIRING.md` | Header pinout from the Waveshare schematic, free GPIOs, and every connection |
| `docs/RiparWallet_Build_Guide.pdf` | The whole build in one PDF: print, wire, assemble, test, flash |
| `firmware/` | ESP32-S3 firmware (PlatformIO, Arduino-ESP32): source, host tests, companion tools |
| `docs/FIRMWARE.md` | Firmware build, flashing, screens and keys, walkthrough, security model |
| `docs/PROTOCOL.md` | Byte-level device ↔ companion ↔ contract protocol (BC-UR, CBOR, EIP-712) |
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

## The firmware

- **Keys, generated on the device.** K1 (secp256k1, BIP-32 `m/44'/60'/0'/0/0`) owns the vault and signs only MetaMask delegation mandates. P1 (P-256, SLIP-10 `m/7951'/0'`) signs co-signatures, deny, PANIC, revoke, reopen and Privy requests. Both use RFC 6979 with low-s.
- **Air-gapped.** Wi-Fi and Bluetooth are never initialised, and the linked binary contains no radio symbols. Requests and replies move only as (animated) BC-UR QR codes, scanned by the OV5640 with quirc.
- **Signs only what it shows.** Every EIP-712 digest is rebuilt from the decoded fields on screen. SIGN arms only after the last review row has been shown and while the pulse still counts as live (at least 5 beats in 8 s, 40–180 bpm).
- **Refuses unsafe requests**, showing the exact reason. For example, it refuses:
  - a mandate without the pulse co-sign caveat;
  - a chain or contract that wasn't pinned at pairing;
  - unknown calldata or caveats;
  - a token it can't show;
  - any Privy change outside the allowlist.
- **One key.** SIGN (BOOT) supports press, hold 2 s and hold 5 s. A press or hold only works on the screen where it started. On Home, holding 5 s triggers PANIC.

```bash
cd firmware
pio run -e ripar -t upload                  # build + flash over the board's USB-C
python test/host/run_host_tests.py          # 9 host suites vs. an independent Python reference
python tools/make_request.py selftest       # companion tool: build -> simulate -> verify
```

- **Verified on the PC:** the clean build uses RAM 11.7 % and flash 11.0 %. All 9 host test suites pass (11,777 checks), and the radio symbol scan finds nothing.
- **Not yet run on a real board.** See [docs/FIRMWARE.md](docs/FIRMWARE.md#known-limitations) for what is still open. In short: the enforcer and MockUSD addresses are filled in after deployment, the seed isn't encrypted yet, and the crypto isn't constant-time.

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
