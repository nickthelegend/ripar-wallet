# Ripar Wallet v1: print and assembly guide (Bambu Lab P1S)

## Ready to print (already sliced for the P1S)

| File in `print/bambu/` | What's on the plate | Time | Filament |
|---|---|---|---|
| `RiparWallet_ALL_P1S.gcode.3mf` | **Everything on one plate**: Front_Shell + Back_Shell (back row), FitTest_Front + FitTest_Back + 3 × Sign_Pin (front row) | about 2 h 23 min | 69.5 g |

The two fit-test coupons come off the same plate. Try the board, the USB-C cables and the lid click on them before you assemble the real shells.

- **Slicer settings baked in:** Bambu Lab P1S, 0.4 nozzle, **Bambu PLA Basic**, 0.16 mm layers, 3 walls, 15 % gyroid, **Textured PEI plate**, no supports, auto brim.
- **To print:** open the file in Bambu Studio. It opens already sliced. Click **Print plate**, pick your P1S, and check the plate type. You can also copy the file to the P1S's microSD card and start it from the printer screen.
- **Different filament or plate** (PETG, PLA Matte, Cool Plate): open the file, change the filament or plate in Bambu Studio, and press **Slice plate** before printing.
- **Plate preview:** `RiparWallet_ALL_P1S_plate.png` shows the layout. Every part is spaced at least 20 mm from the next and clear of the P1S's excluded front-left corner.

Everything is in `print/stl/` and is **already oriented for printing**: the flat face sits on the bed, so import and slice with no rotation needed. `print/step/` has the same parts as STEP files (Bambu Studio imports those too) plus the full assembly.

| File | Qty | Orientation (as exported) | Notes |
|---|---|---|---|
| `FitTest_Front.stl` | 1 (optional, print first) | screen face down | Left end only, about 20 min. Checks board fit, both USB-C ports, SIGN/RST holes and the lip. |
| `FitTest_Back.stl` | 1 (optional) | lens face down | Snaps onto FitTest_Front. Checks the bead "click". |
| `Front_Shell.stl` | 1 | **screen face down** | About 22 g of PLA. |
| `Back_Shell.stl` | 1 | **lens face down** | About 32 g. |
| `Sign_Pin.stl` | 1 (print 3, it's tiny) | standing on its flat end | Presses the board's BOOT key (GPIO0) = **SIGN / NEXT**. |

## Slicer settings (Bambu Studio)

- **Material:** PLA Basic or PLA Matte (PETG also works; the fits allow for it).
  - Print **both shells in black or dark matte**. The dark front makes the screen pop and blocks ambient light around the pulse sensor.
  - A light-coloured lens hood causes flare, which hurts QR scanning.
  - If you charge at the TP4056's default 1 A, print the Front_Shell in **PETG**: the charger dissipates 1–2 W next to it. Alternatively, swap its R_PROG resistor to 2.4 kΩ, which charges at 0.5 A and runs cool.
- **Layers:** 0.16 mm ("0.16mm Optimal"). In the pre-sliced file the Sign_Pins use the plate settings, which is fine at their size. If you slice them yourself, use 0.12 mm, 100 % infill and a 3 mm brim.
- **Walls and infill:** 3 walls, 15 % gyroid.
- **Supports: OFF.** The design avoids support:
  - the screen and thumb windows have chamfers on the bed face;
  - the lens cone is 33° from vertical;
  - the port recesses and the square switch opening (12.3 mm) are short flat bridges, which the P1S handles;
  - the Sign_Pin's flange is coned.
- **Sign_Pin:** print it on a 3 mm brim.
- **Plate:** textured PEI. The sliced files use auto brim. If you slice yourself, use brim only if the first layer lifts at the corners; the rounded edges usually hold.
- **Elephant foot:** keep the Bambu default of 0.15. The screen window needs a crisp bottom edge.
- **Seam:** set to *Back* or *Aligned*. The seam shadow-line chamfer hides the split-line anyway.

## Before the full print: check the fit (about 40 min, both coupons)

Print `FitTest_Front` and `FitTest_Back`, then check:

1. **Board slides in.** Put the ESP32 board glass-down into FitTest_Front. The USB-C should line up with the upper stadium opening, and a USB-C cable should click in fully.
2. **SIGN pin works.** Drop the Sign_Pin in from the inside. Pushing it should click the BOOT key.
3. **Shells click together.** Press FitTest_Back onto FitTest_Front; it should click and hold. It should come apart with a fingernail.
   - Too loose: in `cad/design.py` raise `BEAD` (0.25 → 0.35).
   - Too tight: lower it (→ 0.15), or raise `LIP_CLR`.
   - Then run `python cad/make_all.py`; about 15–20 minutes later new STLs and sliced files appear in `print/`.

## Before you close it up: measure your parts

These were designed from datasheets and typical module sizes. Measure yours with calipers, and if one differs by more than about 0.3 mm, change `cad/design.py` and rebuild.

| Part | `design.py` value | Designed for |
|---|---|---|
| Big latching switch | `SW = dict(body=12.0, body_h=12.0, cap_d=12.0)` | 12×12 mm self-locking, housing ≤ 12 mm tall, cap Ø ≤ 12 mm; inserted from outside through a 12.3 mm square opening |
| MAX30102 board | `MAX = dict(l=20.3, w=15.3, ...)` | up to 20.3 × 15.3 mm, header soldered on the **back** |
| INMP441 | `MIC = dict(d=14.2, ...)` | about 14 mm round board, no header (wires soldered) |
| 18650 | `BAT_D = 19.0`, bay `BAT_CAV_L = 71` | wrapped cell with tape, wires on both ends. Max Ø incl. tape/wire = 19.3 mm; length with tabs ≤ 69.5 mm |
| TP4056 USB-C | `TP = dict(l=28.0, w=17.3, t=1.2 ...)` | 28 × 17.3 mm, 1.0–1.6 mm PCB |
| Buzzer | `BUZ = dict(d=12.0, h=9.5, ...)` | 12 mm active or passive |

## Assembly (no screws, no glue)

1. **Solder first.**
   - Wires on the INMP441 (no header).
   - Buzzer leads.
   - The switch's two terminals.
   - Cell → TP4056 **B+ / B−**. Use a cell with tabs; don't solder straight onto the can.
   - TP4056 **OUT+** → latching switch → **BAT +** of the board's MX1.25 plug. TP4056 **OUT−** → **BAT −**.
2. **Front shell** (screen face down on the table):
   1. Drop the **Sign_Pin** into its hole from the inside, flange inside.
   2. Lay the **ESP32 board** glass-down in the window pocket: USB-C to the **left**, board edges against the **top and left walls**, inside the right-hand and bottom fences. Pushing it into the left end presses the SIGN pin; that's normal.
   3. Lay the **TP4056** in its cradle at the bottom-left: bare side toward the screen, USB-C into the **lower** left opening. Two keepers in the back shell hold it down when you close the case.
   4. Press the **MAX30102** into the thumb-pad pocket, sensor toward the window.
      - Solder its header on the **back** side, along the **lower** long edge.
      - The wires leave through the open right side.
3. **Back shell** (lens face down):
   1. Lay the **18650** in the saddles, wires out through the slots at each end.
   2. **Big switch, installed from outside:**
      1. Solder two wires to COM and NO of one pole.
      2. Feed them in through the **square opening in the top face** and out through the cradle floor.
      3. Push the switch in from outside until it sits on the floor ring.
      4. Press the blue cap on last.
      - If it's loose, wrap one layer of Kapton tape around the body.
      - Route its wires away from the area right under the switch floor.
   3. Slide the **INMP441** into the rails under the top wall: the side with the tiny hole goes against the wall, the chip faces into the box. A keeper on the front shell stops it sliding out.
   4. Drop the **buzzer** into the U-cradle at the right end, sound hole facing the grille. A keeper on the front shell holds it down.
4. **Camera.** Check that the OV5640 is taped flat on the back of the board, where Waveshare mounts it (over the TF slot). The lens hood in the back shell has a 10 mm mouth, so centre the lens by eye.
5. Plug in the jumper wires (table in `docs/WIRING.md`). **Keep every wire away from the rim** so the lid can't pinch it.
6. **Close.** Line the shells up, then press all the way round until the bead clicks. The four flat pegs in the back shell land on the board's M2 nuts and hold the screen against the window.
   - If the seam stays open by a hair with the board fitted, raise `PEG_GAP` from 0.1 to 0.2.
7. **Open.** Put a fingernail or coin in the notch on the bottom seam (right side) and twist.
8. **Never plug both USB-C ports at once.** The board's port powers it even with the switch OFF.

## If something is off

| Symptom | Fix in `cad/design.py` |
|---|---|
| Lid won't stay closed | `BEAD` +0.1 |
| Lid too hard to close | `BEAD` −0.1, or `LIP_CLR` +0.05 |
| Board loose in the window | `FENCE_CLR` 0.2 → 0.1 |
| Pegs press the screen too hard, or it rattles | `PEG_GAP` (0.10) up or down |
| USB-C cable doesn't seat | raise `USB_RECESS` depth (2.0 → 2.2; the wall web is only 0.6 mm) |
| Big switch cap rubs, or body too tight | `SW_CRADLE_CLR` +0.1 (opening = body + 2 × clearance) |

Then run `python cad/make_all.py` (SolidWorks 2026 + Bambu Studio) to rebuild every part, the assembly, the interference check, the exports, the sliced P1S files and the renders.
