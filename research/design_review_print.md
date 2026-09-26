- **BLOCKER: the power switch cannot be installed** (Back_Shell `Switch_Cradle`, `Switch_Floor`, `Switch_Hole`; `cad/parts_shell.py` lines 280-299)
  - **What is wrong:**
    - a = 12/2 + 0.15 = 6.15 and t = 1.2. `SW_Z` = (−13 − 2.5 − 0.3 + (−32 + 2.5 + 0.3))/2 = −22.5.
    - The cradle is a square tube closed on all four sides. Inside it is 2a = 12.3 × 12.3 (X 29.85..42.15, Z −28.65..−16.35). It runs from Y = YI = 28.4 down to y_floor = 28.4 − 12 − 0.15 = 16.25.
    - The floor ring under the tube leaves an opening of 2a − 1.8 = 10.5 mm. The top-wall hole is Ø12.6.
    - A 12 × 12 body cannot pass the 10.5 opening from inside. It cannot pass the Ø12.6 hole from outside either, because its diagonal is 12√2 = 16.97.
    - STL Y-sections confirm this: at Y=22 the tube is a closed 12.3 square, at Y=15.6 the opening is 10.5 square, and at Y=29 the hole is Ø12.6.
  - **Two further problems in the same area:**
    - The round Ø12.6 hole is in a wall that stands vertical when printed. Its crown is an overhang approaching 90° (part of the 172 mm² overhang cluster at print z 14.3–15.8). The cap is Ø12.0, so there is only 0.3 mm per side. Crown droop plus the usual 0.1–0.2 mm undersize on holes means the cap will rub.
    - The tube roof reaches −15.15. That touches the front-shell lip's inner face (Y = 28.4, lip down to −15.5) with 0 clearance, confirmed in STL sections at Z −15.4.
  - **Fix:**
    - Change line 299 so the switch goes in from outside, through a square opening that matches the tube, and rests on the floor ring:
      `b.cut("y", D.H / 2, D.YI - 0.2, lambda s: s.rrect(sw["x"], zc, 2 * a, 2 * a, 0.5), "Switch_Hole")`
    - The top of the opening becomes a flat 12.3 mm bridge at −16.35, level with the tube roof and 0.75 mm below the rebate floor.
    - The pins (±4.5, ±2.5) still pass the 10.5 opening. Feed the soldered leads through before pushing the switch in.
    - In both `cradle()` and `floor()`, replace `(zc + a + t)` with `min(zc + a + t, zs - D.LIP_H - 0.3)` (= −15.8) to clear the lip.
    - Update PRINTING.md step 3.2.
    - If you want to keep the round hole instead: the floor ring has to become snap catches, and the hole needs a flat-topped teardrop (45° sides, roof 2·6.3·(√2−1) = 5.2 mm wide).

- **MAJOR: the peg tips cannot reliably find the M2 nuts** (`Peg_Tips`, `parts_shell.py` lines 250-251; `PEG_TIP_D`/`PEG_TIP_L` in `design.py`)
  - **What is wrong:**
    - The tip is Ø1.4 and the M2 internal minor diameter is 1.567. That gives only (1.567 − 1.4)/2 = 0.08 mm radial capture.
    - The board can move ±0.25 mm in each direction. In X that is 0.30 (USB face to left wall) + 0.20 (`FENCE_CLR`) = 0.5 mm; in Y it is 0.30 (top wall) + 0.20 = 0.5 mm. The two shells can also shift ±0.14 (`LIP_CLR`).
    - So misalignment can reach about 0.39 mm. The tips are flat-ended and the lid closes blind.
    - A tip that misses lands on the nut face with PEG_TIP_L − PEG_GAP = 1.6 − 0.1 = 1.5 mm interference. The lid then will not snap, or the tip breaks.
    - The tips are also the last 1.6 mm of 20.1 mm columns, printed at 1.53 mm² per layer (print z 22.1–23.7). They will overheat and come out blobby and oversize.
  - **Fix:**
    - Delete the `Peg_Tips` boss and set `PEG_TIP_L = 0.0`. The Ø4.2 shoulders already sit 0.1 mm behind the nuts, and the fences locate the board.
    - If you want a locator, make it a cone: `PEG_TIP_L = 1.0` and add `draft=25, draft_out=False` to the boss. The top is then Ø1.4 − 2·1.0·tan25 = 0.47, which captures ±0.55 mm.

- **MAJOR: the buzzer cradle block floats 0.1 mm above the lens wall and touches the lip** (`Buzzer_Cradle_Block`, lines 321-325)
  - **What is wrong:**
    - z0 = max(zc − rb − 1.2, Z_BIN) = max(−22.5 − 6.2 − 1.2, −30) = −29.9, which leaves a 0.1 mm gap.
    - The block's underside is 5 × 14.8 mm (X 42.4..47.4, Y −25.4..−10.6), about 74 mm². It is attached only to the right wall.
    - The STL shows a 74.0 mm² flat, horizontal overhang at print z 2.10, above the floor at 2.00. At 0.16 mm layers there is about 0.16 mm of air under the first block layer, so it will sag or curl, with a risk of the nozzle hitting it.
    - The block top is at zs − 1.0 = −14.0, inside the lip's Z range (−13..−15.5). Both 1.2 mm U walls touch the lip's inner face (X = 47.4) with 0 clearance, confirmed in STL sections at Z −14..−15.4.
  - **Fix:** in `buz_cradle()`, set `z0 = D.Z_BIN` and `z1 = zs - D.LIP_H - 0.3`, then use `s.rrect(bz["y"], (z0 + z1) / 2, 2 * rb + 2.4, z1 - z0, 0)`. The buzzer top (−28.7 + 12 = −16.7) is still inside the U.

- **MAJOR: `MAX_Posts` are Ø2.4 × 26.1 mm needles** (lines 345-347)
  - **What is wrong:**
    - z_mod_back = −1.6 + (1.6 − 0.7) − 1.2 − 0.1 − 1.6 = −3.6, so the posts end at −3.9. Measured from Z_BIN = −30 they are 26.1 mm tall, a slenderness of 10.9:1. They stick 9.1 mm past the parting plane.
    - In the lens-down print, from z 23.7 to 28.1 (about 28 layers), these two 4.5 mm² islands are the only thing printing. The printer cannot meet its minimum layer time, so the tips soften and wobble.
    - Each post has only 0.3 mm clearance to the `MAX_Fence` and sits 0.3 mm behind the MAX PCB it is meant to support. The research guideline is at least 3 mm for posts that carry load.
  - **Fix:** merge the two posts into one rib along the closed end:
    ```python
    xp, yp = m["x"] - m["l"] / 2 + 1.3, m["w"] / 2 - 1.3          # 20.15, 6.35
    b.boss("z", D.Z_BIN, z_mod_back - 0.3,
           lambda s: s.slot((xp, m["y"] - yp), (xp, m["y"] + yp), 1.2), "MAX_Posts")
    ```
    - The rib is 2.4 × 15.1 mm, about 35 mm² per layer (roughly 4× more).
    - It keeps 0.3 mm clearance to the fence inner faces at X 18.65 and Y 3.15 / 18.85.
    - Check that the back of your MAX board is clear in the 2.5 mm strip at the closed end. The current posts already assume both corners of that strip are clear.

- **MAJOR: the snap bead only engages by 0.11 mm** (`BEAD`, `LIP_CLR` in `design.py`)
  - **What is wrong:**
    - The bead crest sits at inset (RIM_T + LIP_CLR) − BEAD = (1.2 + 0.14) − 0.25 = 1.09. The rim's inner face is at 1.2, so the overlap is 1.2 − 1.09 = 0.11 mm.
    - The lip can shift ±0.14 sideways, so a 0.11 mm shift unhooks one side. That is within normal FDM tolerance of ±0.1–0.2.
  - **Printability of the bead and groove is fine:**
    - The bead shoulder is a 0.25 mm flat, horizontal overhang ring (76.9 mm² at print z 13.90), which is less than one 0.42 mm line.
    - The groove roof is 0.35 mm.
    - The rim at the groove is 1.2 − 0.35 = 0.85 mm, which is 2 lines.
  - **Fix:**
    - Set `BEAD = 0.35`, giving 0.21 mm overlap.
    - The crest at 0.99 still clears the groove floor (0.85) by 0.14, so the snap is unloaded when closed and PLA creep is not an issue.
    - The ramp becomes atan(0.35/0.8) = 23.6°, and the shoulder overhang 0.35 mm, still under one line.
    - Confirm with FitTest.

- **MINOR: the back-shell pry notch cuts through the rim and leaves a sliver thinner than one line** (lines 358-360; `PRY`)
  - **What is wrong:**
    - The notch depth d = 1.0 is more than the rim at the groove (0.85). Its Z range (−13.0..−14.2) overlaps `GROOVE_Z` (−13.8..−14.8).
    - This makes an 8 × 0.4 mm through-slot at Z −13.8..−14.2. Above it, a wall only 1.2 − 1.0 = 0.2 mm thick (0.1 mm where `Rim_LeadIn` cuts in) spans the 8 mm.
    - The STL confirms it: at Z −13.5 the strip is Y −30.0..−29.8, and at −13.9 there is no material between X 34 and 42.
    - The slicer will drop or string that sliver, and the bead loses its catch over those 8 mm.
  - **Fix:** delete the back-shell `Pry_Notch` and make the front-shell notch provide the gap: `PRY = dict(x=38.0, w=8.0, h=1.8, d=1.2)`. That leaves 1.4 mm of the 2.6 mm front wall, and the notch is open at the top in print.

- **MINOR: `Sign_Pin` stands on a Ø2.4 foot and has a flat 1.1 mm flange overhang** (lines 378, 381)
  - **What is wrong:**
    - The 0.4 `End_Chamfer` on the Ø3.2 end leaves a Ø2.4 foot (4.66 mm² in the STL) under a part 5.17 mm tall.
    - At z 3.8 the Ø5.4 flange overhangs the shaft by (5.4 − 3.2)/2 = 1.1 mm, fully horizontal (a 14.84 mm² flat ring).
    - That drooping face is the one that seats against the wall.
  - **Fix:**
    - Change the flange to `b.boss("x", x_in + pn["flange_t"], x_in, lambda s: s.circle(yz, pn["flange_d"] / 2), "Flange", draft=40, draft_out=False)`.
      - At the wall its radius is 2.7 − 0.8·tan40 = 2.03, so the underside becomes a 40° cone plus a 0.43 mm step.
      - It still bears on the wall from r 1.8 (hole edge) to r 2.03.
    - Reduce the chamfer from 0.4 to 0.2, giving a Ø2.8 foot (6.2 mm²).
    - Use a 3 mm brim.

- **MINOR: the bed-face edge rounds overhang up to 85°** (`Round_Front` R2.0 at line 118, `Round_Back` R2.5 at line 235)
  - **What is wrong:**
    - The STL has 428 mm² (front, print z 0–0.47) and 531 mm² (back, z 0–0.58) steeper than 45°.
    - Between layers 1 and 2 the outline steps out by 0.41 mm on the front (inset 1.39 → 0.98) and 0.47 mm on the back (1.83 → 1.37). That is about one line over air, so expect a slightly drooped bottom edge.
    - This contradicts PRINTING.md's claim that every overhang is 45° or less.
  - **Fix (optional, cosmetic):** use `p.chamfer(edges_at_z(p, 0.0), 1.0, name="Chamfer_Front")` and `p.chamfer(edges_at_z(p, zb), 1.2, name="Chamfer_Back")`. Keep `R_BACK` in `design.py`, because `SW_Z` uses it.

- **MINOR: the print docs and exports are wrong or incomplete**
  - **What is wrong:**
    - `print_list.csv` says the switch hole is self-supporting. It is not (see the switch finding).
    - PRINTING.md claims every overhang is 45° or less; the buzzer block, bead, Sign_Pin flange and bed-edge rounds above are not.
    - PRINTING.md says to push the switch into the cradle, which is impossible.
    - PRINTING.md lists `FitTest_Front.stl` and `FitTest_Back.stl`, but `print/stl` contains only three files.
    - `print/step` is empty, although both documents reference `step/*.step`.
    - The `design.py` comments give XI as 47.6 and YI as 28.6; the actual values are 47.4 and 28.4.
  - **Fix:** after the switch fix, re-export including the FitTest STLs and the STEP files, then correct the text.

- **MINOR: the top lettering is jammed into the corner** (`Txt_Top`, line 350)
  - **What is wrong:** in the STL, "RIPAR WALLET" spans X −44.84..11.1. The plan-view corner round (RC 5) starts at |X| = 45, so the "T" begins 0.16 mm from where the corner round starts.
  - **Fix:** change the origin from `(-45.0, ...)` to `(-43.5, ...)`. The text then spans X −43.34..12.6, still 1.9 mm clear of the Ø3.0 mic countersink (which starts at X 14.5).

**Checked and fine:**
- **STLs:** all three are watertight and manifold (one body each, every edge shared by exactly two faces, no zero-area faces).
- **Lens cone and hood:** the lens cone is 33° and the hood's outer cone narrows upward, so neither needs support.
- **Windows:** the screen window has a 30° draft and the MAX window a 45° chamfer on the bed face, which hides elephant foot.
- **MAX skin:** it prints as 4 layers (0.2 + 3×0.16 = 0.68 mm).
- **Port recesses and holes:** the recess roofs are 6.2 mm flat bridges anchored on three sides, and the stadium-hole roofs are 5.7 mm.
- **Walls:**
  - A scan for features under 0.8 mm found nothing in Front_Shell. In Back_Shell it found only the pry-notch sliver above, the tips of the 18650 saddle horns, and the pointed tips inside letters.
  - The lip is 1.26 mm, fences 1.2 / 1.0 mm, and the hood 1.2 mm.
- **Text:**
  - Stroke widths are 1.4–1.8 mm (top, 4.2 mm), 1.8–2.5 mm (bottom, 5.5 mm) and 2.0–2.6 mm (lens face, 6 mm).
  - The letter recess roofs on the bed face are bridges no wider than 2.6 mm.

Files are in `cad/` and `print/stl/`. No project files were changed and CAD was not run. I did write one small helper script, `(local scratch file, not included)`, in the scratchpad on C: to section the STLs; nothing was written to D:.