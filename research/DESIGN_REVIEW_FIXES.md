**Lead mechanical review: Ripar Wallet v1, before the first print**

I checked all three reviews against `design.py` and `parts_shell.py`, and sectioned the `_stl_cache` STLs in memory. I edited no files and wrote nothing to disk.

Derived values used below: XI 47.4, YI 28.4, OX −20.11, SW_Z −22.5, Z_STANDOFF_END −9.8, X_PLUNGER −45.64, PCB X −45.92..2.30, TP_USB_Z −6.00.

## (1) Accepted issues, ranked, with edits

**1. BLOCKER: the power switch cannot be installed** (fit 1, print, use 1)
- The cradle is a closed 12.3 mm square tube (Z −28.65..−16.35). The only openings are the Ø12.6 hole in the top wall and the 10.5 mm opening in the floor ring. A 12 × 12 body cannot pass either one, because its diagonal is 16.97 mm.
- Sections at Y 22, 15.6 and 29 confirm this.
- The tube roof (−15.15) also touches the lip's inner face at Y 28.4 with zero gap. The section at Z −15.3 shows a distance of 0.
- Fix: the switch goes in from outside through a square opening the size of the tube, and sits on the floor ring. The roof is trimmed to clear the lip.
- `parts_shell.py` 285–299. Add after the `z_lo` block:
  ```python
  z_hi = min(zc + a + t, zs - D.LIP_H - 0.3)          # -15.8: roof clears the front lip
  ```
  - In both `cradle()` and `floor()`:
    `s.rrect(sw["x"], (zc + a + t + z_lo) / 2, 2 * (a + t), (zc + a + t) - z_lo, 0)` → `s.rrect(sw["x"], (z_hi + z_lo) / 2, 2 * (a + t), z_hi - z_lo, 0)`
  - Line 299:
    `b.cut("y", D.H / 2, D.YI - 0.2, lambda s: s.circle((sw["x"], zc), sw["hole_d"] / 2), "Switch_Hole")` → `b.cut("y", D.H / 2, D.YI - 0.2, lambda s: s.rrect(sw["x"], zc, 2 * a, 2 * a, 0.3), "Switch_Hole")   # insert from outside, leads first`
- The top of the opening becomes a flat 12.3 mm bridge. The 6 pins pass the 10.5 floor opening.
- PRINTING 3.2 becomes: "Solder two wires to the switch (COM and NO of one pole). Feed them in through the square opening in the top face and out through the cradle floor. Push the switch in from outside until it sits on the floor. Press the cap on last. If the switch is loose, wrap one layer of Kapton tape around the body."

**2. MAJOR: the peg tips cannot find the M2 nut bores** (fit 2, print)
- The tips are flat Ø1.4 going into a 1.567 mm thread minor diameter, so they only self-capture within 0.08 mm radially. The lid closes blind.
- The board can float +0.2 / −0.39 mm in X and ±0.3 / 0.2 mm in Y, and PRINTING step 2.2 tells the user to push it into a corner.
- A tip that misses holds the lid about 1.5 mm open.
- Delete the tips. The fences and walls already locate the board, and the Ø4.2 shoulders on the nuts are unaffected.
  - `design.py` 130: `PEG_TIP_L = 1.6` → `PEG_TIP_L = 0.0                    # tips removed: cannot find the M2 bore blind`
  - `parts_shell.py` 250: prefix the `Peg_Tips` boss with `if D.PEG_TIP_L > 0:` and indent it.
- PRINTING 2.2 becomes: "…USB-C to the left, board against the top wall and the right-hand fence (pushing it into the left end presses the SIGN pin)."

**3. MAJOR: the TP4056 has nothing under it in Z** (fit 5, use 2)
- The rails only touch its bare face. Nothing sits behind the module, so it can drop 3.32 mm: from the receptacle bottom at −7.63 onto the cell top at −10.95.
- The port then drops out of line with its opening (−3.75..−8.25). PRINTING's "clip" does not exist.
- Fix: add keepers in `back_shell()` right after `Cell_Stops` (after line 264):
  ```python
  xs0 = D.BAT_X0 - D.BAT_STOP_T / 2
  b.boss("z", z_stop, D.TP_Z_FRONT - 1.6 - 0.1,              # -4.87: clears a PCB up to 1.6 thick
         lambda s: [s.rrect(xs0, y, D.BAT_STOP_T, 2.0, 0) for y in (D.TP_Y0 + 1.4, D.TP_Y1 - 1.4)], "TP_Keepers")
  ```
  - The keepers land at X −45.5..−44.3, Y −26.8..−24.8 and −12.3..−10.3. That is 1.8 mm clear of the receptacle (Y −23.02..−14.08) and inside the stop's footprint.
- PRINTING 2.3: "Clip" → "Lay".

**4. MAJOR: the USB-C plugs are stopped too far in front of both receptacles, and the TP recess is too narrow for common overmolds** (fit 4)
- Board setback: 1.3 mm, or 1.5 when the plug pushes the board onto its fence.
- TP setback: 1.3–2.6 mm. The project's own limit is ≤ 0.5 mm.
- The TP recess is 12.4 wide with r3.4 corners. A 12 × 6 r1.5 overmold hits its corners by 0.24 mm.
- `design.py` 156: `TP_X0 = -XI + 0.30 + TP["usb_over"]                  # PCB left edge (USB face 0.3 off wall)` → `TP_X0 = -XI + 0.20                                  # PCB edge 0.2 off the wall; receptacle reaches into the wall hole`
  - The USB-C shell is obround, so its front fits the 9.8 × 4.5 stadium hole.
- `design.py` 168: `USB_RECESS = (13.0, 7.2, 1.6)` → `USB_RECESS = (13.0, 7.2, 2.0)      # 0.6 web; board setback 0.9, TP ~0-0.3`
- `parts_shell.py` 205–206 → `lambda s: (s.rrect(uy, uz, rw, rh, 1.2), s.rrect(ty, D.TP_USB_Z, rw, rh, 1.2))`
- `parts_shell.py` 162: `s.rrect(tx1 + 0.5 + 0.5, …)` → `s.rrect(tx1 + 0.3 + 0.5, …)            # right end, 0.3 slack`
- If the FitTest cable still won't click in the board port, cut the board recess through the wall (`rd = D.T_WALL`).

**5. MAJOR: the snap latch window (0.10 mm) is in series with other 0.10 mm hard stops** (fit 3)
- The bead's catch face is at −13.9 and the groove's top edge at −13.8, so the bead only latches if the seam closes to within 0.10 mm.
- The lip end has 0.10 mm to the rebate floor, and the peg shoulder has 0.10 mm to the nut.
- Layer rounding alone (seam 18.92/19.08, Z_FIN 1.48/1.64, peg 22.12) makes the peg gap −0.04..+0.28.
- `parts_shell.py` 241: `b.cut("z", zs, zs - D.LIP_H - 0.1, …` → `b.cut("z", zs, zs - D.LIP_H - 0.3, …`
- `design.py` 38: `GROOVE_Z = (Z_SPLIT - 0.8, Z_SPLIT - 1.8)` → `GROOVE_Z = (Z_SPLIT - 0.7, Z_SPLIT - 1.8)   # 0.2 latch window`
  - I used 0.2 rather than fit's 0.3 to limit axial lid rattle to 0.2 mm.
  - If the FitTest seam is held open with the board in, raise `PEG_GAP` from 0.1 to 0.2 first.

**6. MAJOR: the buzzer is loose; its cradle block floats and touches the lip** (fit 6 and 8, print, use 8)
- The U is open toward the seam and nothing in the front shell holds the buzzer. It can rise about 15 mm.
- The block floats 0.1 mm above the lens wall (confirmed at X=45: nothing between −30.0 and −29.9) and is attached only to the right wall.
- The block top (−14) touches the lip face at X 47.4 with zero gap.
- `parts_shell.py` 323–324 →
  ```python
  z0, z1 = D.Z_BIN, zs - D.LIP_H - 0.3
  s.rrect(bz["y"], (z0 + z1) / 2, 2 * rb + 2.4, z1 - z0, 0)
  ```
- `front_shell()`, before `p.material`:
  ```python
  z_bt = D.BUZ_Z - D.BUZ["bore"] / 2 + D.BUZ["d"]            # -16.7
  b.boss("z", D.Z_FIN, z_bt + 0.3, lambda s: s.rrect(D.XI - 2.5, D.BUZ["y"], 1.2, 8.0, 0), "Buzzer_Keeper")
  ```

**7. MAJOR: the INMP441 can slide about 10 mm toward the screen** (fit 7, use 7)
- The rails end at −16 and nothing in the front shell stops the board, so its port leaves the Ø1.5 hole.
- `front_shell()`:
  ```python
  b.boss("z", D.Z_FIN, D.MIC_Z + D.MIC["d"] / 2 + 0.3,       # -15.1
         lambda s: s.rrect(D.MIC["x"], D.YI - 0.6, 6.0, 1.2, 0), "Mic_Keeper")
  ```
- The keeper sits at X 13..19, clear of the rails at 7.55..9.55 and 22.45..24.45.
- Set `MIC["t"]` from measurement (see section 3).

**8. MAJOR: the MAX30102 posts sit on the header row and support only one end** (use 5)
- A 7-pin header is 17.78 mm long, so it must run along the 20.3 mm edge. It has to be the lower edge (Y≈4.6), because on the upper edge its dupont housings would hit the switch tube.
- The post at (20.15, 4.65) lands on that row.
- Both posts are at the X 20.15 end, so the thumb load at X 29 tilts the module.
- `parts_shell.py` 346 → `lambda s: [s.circle((m["x"] + sx * (m["l"] / 2 - 1.3), m["y"]), 1.2) for sx in (-1, 1)], "MAX_Posts")`
  - This puts the posts at (20.15, 11) and (37.85, 11), clear of the fence and the switch floor (Y ≥ 15.05).
  - Keep the top at `z_mod_back - 0.3`.
- Solder the switch wires so they don't hang at X 36.6..39 below Y 12.

**9. MINOR: the back-shell pry notch cuts through the rim** (print, use 10)
- The notch (d 1.0) meets the groove (inset 0.85). My X=38 section shows a detached 0.2 × 0.7 mm strip at Y −30..−29.8, and the bead loses its catch over 8 mm.
- Delete `parts_shell.py` 357–360.
- `design.py` 219 → `PRY = dict(x=38.0, w=8.0, h=1.8, d=1.2)   # front shell only`

**10. MINOR: the Sign_Pin press depth depends on layer rounding, and it prints with a flat flange overhang** (fit 10, print)
- `design.py` 171: `flange_t=0.8, nub_gap=0.39` → `flange_t=0.84, nub_gap=0.32`
  - At 0.2 + 0.12·n layers, the flange top lands at 4.64 and the tip at 5.24, both exact layer boundaries. Press depth is 0.32.
  - Press depth does not change when the board shifts in X, because the PCB edge and the plunger move together.
- `parts_shell.py` 378 → `b.boss("x", x_in + pn["flange_t"], x_in, lambda s: s.circle(yz, pn["flange_d"] / 2), "Flange", draft=40, draft_out=False)`
- `parts_shell.py` 381: `0.4` → `0.2`. Print it with a 3 mm brim.

**11. MUST DO before printing: docs and exports**
- `print/stl` has no FitTest STLs and `print/step` is empty, but PRINTING starts with the FitTest. `model/parts` has no FitTest SLDPRT either. Run the full `make_all.py`, then confirm there are 5 STLs and 6 STEP files.
- `print_list.csv` should say "switch opening = 12.3 mm bridge".
- PRINTING:
  - Remove the claim that every overhang is 45° or less.
  - Change the 18650 limit from 19.6 to ≤ BAT_D + 0.3 = 19.3.
  - Update steps 2.2, 2.3 and 3.2 as above.
- `design.py`:
  - Comments on lines 41/42: 47.6 → 47.4, 28.6 → 28.4.
  - Line 137 comment: "max cell incl. tape/wire = BAT_D + 0.3".
- WIRING:
  - "With the switch OFF the board is dead" is false while the board's own USB-C is plugged in. Add "never plug both USB-C ports at once", as the plan says.
  - If the MAX board's pull-ups go to 1.8 V, move its jumper to 3.3 V. Otherwise SDA/SCL idle at 2.55 V against the ESP32-S3's 2.475 V input threshold.
  - Add a 1N4148 across the buzzer when it is driven by the S8050.
  - Name the switch terminals as COM and NO of one pole.

**12. MINOR: print Back_Shell in black or dark matte PLA, and deal with charger heat** (fit 12, use 4)
- A light hood causes flare, which lowers QR contrast.
- The TP4056 dissipates 1.3–2 W at 1 A inside a sealed PLA box. Either swap R_PROG to 2.4 kΩ (0.5 A) or print Front_Shell in PETG.

**13. Optional, cosmetic: the top lettering starts at the corner round**
- `parts_shell.py` 350: `(-45.0, …)` → `(-43.5, …)`

## (2) Rejected

- **U-slot switch cradle open toward the seam, with a front-shell keeper (fit 1, use 1):** the stem has to pass through the top wall. Sliding the switch in along −Z drags the stem through the rim and the 0.6 mm web above the hole. Tilting it in is blocked by the floor ledges and the pins. `hole_d` 12.9 no longer matters.
- **Chamfered peg tips (fit 2):** they capture the nut, but then four pins sit in four M2 bores with 0.08 mm radial clearance each. That is tighter than the SMT nut placement and the print position tolerances, so the pegs bind.
- **BEAD 0.35 (print):** the CAD understates real engagement. The rim face is an inner contour and prints inward; the bead is an outer contour and prints outward. On a closed full-perimeter ring, 0.3 mm or more of interference risks a lid that won't close. Tune it with the FitTest, as PRINTING already says.
- **45° Bead_Release (use 10):** it weakens retention on a wallet lid, and the pry notch already handles opening.
- **BUZ bore 12.2 (fit 6, use 8):** the U is an inner contour that already prints about 12.2. The keeper handles retention.
- **BAT_X0 −42.8 (fit 9):** the wire can bend inside the 3 mm slot. Moving the stop would also move the base the TP keepers stand on.
- **MAX posts at 0.05 mm gap (fit 11):** each post is a 26 mm PLA column (about 600 N/mm axially) in a ±0.2 mm stack. Up to 0.15 mm of interference means tens of newtons on the MAX board and the snap. Keep 0.3 mm, and add foam if needed.
- **MAX single rib (print):** it has the same header collision at the closed end as the current posts.
- **TP short "that the DW01 can't interrupt" (use 2):** on DW01/FS8205 boards, IN− (the USB shell) is OUT−, and the FETs sit between OUT− and B−. The same mistake invalidates use 3's claim that two chargers bypass protection.
- **Seal the board USB-C now (use 3):** you need the port to flash v1. Handle the security side in firmware with eFuses (disable USB-Serial-JTAG, disable download mode, secure boot). Only the documentation fix is accepted.
- **Switch_Guard and SIGN dimple (use 6):**
  - The guard is an outward boss on a wall that prints vertically, so it needs support, and its bottom (−30.1) runs into the R2.5 round.
  - The dimple nicks the USB recess (Y 17.04 vs 17.09).
  - Holding GPIO0 while powering on enters download mode on any ESP32; that is not a mechanical defect.
- **MIC t=1.6 with a 2.6 mm slot (use 7):** a 1.0 mm board would sit 1.6 mm off the wall and leak sound. Measure instead.
- **Vents, fillet-to-chamfer, HOOD_T 1.6, GPIO19 for the mic:** these are cosmetic or depend on sealing the USB port, so they are not needed before the first print.

## (3) Measure your own parts

| Part | What to measure | `design.py` key |
|---|---|---|
| Latching switch | Body width | `SW["body"]` |
| Latching switch | Housing height (sets the floor) | `SW["body_h"]` |
| Latching switch | Stem free height, cap height and travel. Aim for the cap about travel + 0.5 mm proud of the top face when OFF. | `SW["body_h"]` |
| Latching switch | If the fit is loose | `SW_CRADLE_CLR` (0.15 → 0.10) |
| TP4056 | PCB length (the right fence now has only 0.3 mm slack) | `TP["l"]` |
| TP4056 | PCB width | `TP["w"]` |
| TP4056 | PCB thickness | `TP["t"]` |
| TP4056 | Receptacle overhang past the PCB edge | `TP["usb_over"]` |
| TP4056 | Check nothing taller than 0.5 mm sits 1.7–2.9 mm in from the USB edge, next to the long edges | (no key) |
| 18650 | Diameter including tape and any wire lying on the screen side | `BAT_D` (limit is BAT_D + 0.3) |
| 18650 | Length with tabs | `BAT_L` (≤ 69.5 mm) |
| MAX30102 | Board size and bare PCB thickness | `MAX["l"]`, `MAX["w"]`, `MAX["t"]` |
| MAX30102 | Header on the lower long edge. Back side clear at the short-edge midpoints (±8.85 mm from the centre). | (no key) |
| INMP441 | Board diameter | `MIC["d"]` |
| INMP441 | PCB thickness plus any solder bump or gasket on the port face | `MIC["t"]` |
| Buzzer | Diameter and height | `BUZ["d"]`, `BUZ["h"]` |
| USB-C cables | Overmold must be ≤ about 12.6 × 6.8 mm | `USB_RECESS` |
| Board stack | Tune after the FitTest | `PEG_GAP` |