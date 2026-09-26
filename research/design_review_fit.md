- **1. BLOCKER: the 12x12 latching switch cannot be installed** (`parts_shell.py` 280–299)
  - **What's wrong:** `Switch_Cradle` is a closed square tube, and I confirmed this by sectioning the Back_Shell STL at Y=22.
    - Walls sit at X 28.65–43.35, Z −30.0 to −15.15. The pocket is 12.3 x 12.3 (X 29.85–42.15, Z −28.65 to −16.35) and it is closed on the +Z side as well.
    - The two ways in are the 12.6 mm round hole in the top wall and the 10.5 x 10.5 opening in `Switch_Floor` (2a − 1.8 = 12.3 − 1.8).
    - The switch body is 12 x 12. A 12x12 square needs a 16.97 mm circle to pass (12√2), and it is wider than 10.5. So it cannot enter from either side. PRINTING step 3.2 ("push up into the cradle") is impossible.
  - **Secondary:** the 12.6 mm hole is in a wall that prints vertically. About 8.9 mm of its top arc is a bridge steeper than 45°, and the cap has only 0.3 mm clearance per side, so expect the cap to rub.
  - **Fix:** open the cradle and the floor toward the seam as a U, the same way the buzzer and mic mounts are done, and cap the U from the front shell.
    ```python
    # back_shell(): replace cradle()/floor() and their bosses
    ztop = min(zc + a + t, zs - D.LIP_H - 0.3)     # -15.8, also clears the lip (finding 8)
    def u_ring(s, inner):
        s.poly([(sw["x"]-a-t, z_lo), (sw["x"]+a+t, z_lo), (sw["x"]+a+t, ztop), (sw["x"]+inner, ztop),
                (sw["x"]+inner, zc-inner), (sw["x"]-inner, zc-inner), (sw["x"]-inner, ztop), (sw["x"]-a-t, ztop)])
    b.boss("y", D.YI, y_floor, lambda s: u_ring(s, a), "Switch_Cradle")
    b.boss("y", y_floor, y_floor - 1.2, lambda s: u_ring(s, a - 0.9), "Switch_Floor")
    # front_shell(): keeper, ends 0.3 mm above the body face at zc+6 = -16.5
    b.boss("z", D.Z_FIN, D.SW_Z + D.SW["body"]/2 + 0.3,
           lambda s: s.rrect(D.SW["x"], D.YI - D.SW["body_h"]/2, 8.0, 1.2, 0), "Switch_Keeper")
    ```
    - Also set `SW["hole_d"]` to 12.9.
    - The dummy switch assumes the cap stands 3.0 mm proud when OFF. The research target is travel + 0.5, which is 3.5–4.5 mm. Measure the real cap before printing.

- **2. MAJOR: the peg tips cannot find the M2 nut bores** (`parts_shell.py` 248–251)
  - **What's wrong:**
    - A flat Ø1.4 tip in a Ø1.6 bore only self-captures within (0.8 − 0.7) = 0.10 mm of radial offset.
    - The board can sit 0.30 off in X (USB face at −47.10, wall at −47.40) and 0.20 the other way (right fence 2.50 vs PCB 2.30). In Y it is 0.30 (PCB 28.10 vs wall 28.40) and 0.20 (fence −7.12 vs −6.92).
    - PRINTING step 2.2 says to push the board into the top-left corner. That offsets every nut by (−0.30, +0.30), which is 0.42 mm radial.
    - Each tip then lands on the nut face and holds the lid about 1.6 mm open (the tip length).
    - The left wall is not a reliable X stop either. A standard 8.94 x 3.26 receptacle shell fits through the 9.8 x 4.1 stadium hole, so the real −X stop is the loose SIGN-pin flange (0.68 mm away) or the PCB edge (1.48 mm).
  - **Fix:**
    - Add right after `Peg_Tips`: `p.chamfer(edges_at_z(p, z_peg + D.PEG_TIP_L), 0.45, name="Peg_Tip_Chamfer", quiet=True)`. This raises the capture radius to 0.8 − 0.25 = 0.55 mm, which is more than 0.42.
    - Change PRINTING step 2.2 to "centre the board between the walls and fences".
    - Do not change `OX`. Moving it by δ reduces the SIGN-pin press depth by the same δ.

- **3. MAJOR: the snap's latch window (0.10 mm) is in series with three 0.10 mm hard stops** (`design.py` 36–38; `parts_shell.py` 241)
  - **What's wrong:**
    - The bead's catch face is at Z_SPLIT − 0.9 = −13.9 and the groove edge at −13.8. The bead latches only if the seam closes to within 0.10 mm.
    - Three other stops each have only 0.10 mm clearance:
      - Peg shoulder −9.9 vs nut end −9.8.
      - Lip end −15.5 vs rebate floor −15.6.
      - Seam faces.
    - At 0.2 + n·0.16 mm layers, surfaces shift:
      - Back shell rim: 19.0 prints as 18.92 or 19.08.
      - Peg shoulder: 22.1 prints as 22.12.
      - Front shell Z_FIN: 1.6 prints as 1.48 or 1.64.
    - So the peg gap = (11.36…11.52) − 8.20 − (3.04…3.20) = −0.04 to +0.28. Adding ±0.1 for nut and LCD tolerance gives −0.14 to +0.38.
    - At −0.14 the seam stands 0.14 open and the bead never engages.
    - The bead itself has 0.11 mm radial undercut (crest at inset 1.09 vs rim face at 1.20, confirmed in the STL) and 0.24 mm clearance in the groove, which is fine.
  - **Fix:**
    - `GROOVE_Z = (Z_SPLIT - 0.6, Z_SPLIT - 1.8)` gives a 0.3 mm latch window.
    - Rebate: `b.cut("z", zs, zs - D.LIP_H - 0.3, ...)`.
    - Keep `PEG_GAP = 0.10`, so up to 0.2 mm of peg interference still latches. The trade-off is that the lid may have up to 0.3 mm axial play when the pegs are short.

- **4. MAJOR: USB-C plugs are stopped too far in front of both receptacles** (`design.py` 168; `parts_shell.py` 205–206)
  - **Setback from the recess floor to the receptacle face:**

    | Port | Receptacle face | Recess floor | Setback |
    |---|---|---|---|
    | Board | −47.10 | −50 + 1.6 = −48.40 | 1.30 mm |
    | TP4056, nominal | −47.10 | −48.40 | 1.30 mm |
    | TP4056, pushed onto the right stop (−17.80 − 28.0 − 0.8 = −46.60) | −46.60 | −48.40 | 1.80 mm |
    | TP4056, worst case (l 27.5, overhang 0.5) | −45.80 | −48.40 | 2.60 mm |

    The project's own guideline is ≤ 0.5 mm.
  - **Recess shape:**
    - The recess corner radius is rh/2 − 0.2 = 3.4 on a 7.2 mm height, so it is almost a stadium.
    - The TP recess is only rw − 0.6 = 12.4 wide, against a 12.35 mm maximum overmold.
    - A 12.0 x 6.0 overmold with 1.5 mm corners clashes by 0.24 mm in the TP recess corners: √(1.7² + 1.3²) + 1.5 = 3.64 > 3.4.
  - **Fix:**
    - `USB_RECESS = (13.0, 7.2, 2.0)`. This leaves a 0.6 mm web and a 0.9 mm setback.
    - In `USB_Recess` use corner radius `1.2` for both recesses, and width `rw` (not `rw - 0.6`) for the TP.
    - Then fix the TP slack (finding 5).
    - If the fit test still does not click, cut the recess through the wall (`rd = D.T_WALL + 0.6`, delete the stadium holes). That gives a 0.3 mm setback.

- **5. MAJOR: the TP4056 is not held in Z and has 0.5 mm of X slack** (`parts_shell.py` 150–164)
  - **What's wrong:**
    - The rails only touch the bare face at −3.17. The fences stop at −4.97 and have no catch; the "clip" in PRINTING does not exist.
    - Behind the module, the receptacle bottom is at −7.63 and the cell front at −10.95, so the module can fall 3.3 mm.
    - The plug is centred at −6.00 (for t = 1.2), and its lower edge is only 0.95 mm above the opening's lower edge (−8.25). Any sag over 0.95 mm puts the port out of line with the opening.
    - The right-end stop is `tx1 + 0.5`, so the plug pushes the module 0.5 mm deeper (see finding 4).
  - **Fix:**
    ```python
    # back_shell(), after Cell_Stops: fingers outside the receptacle band (Y -23.0..-14.1)
    xs0 = D.BAT_X0 - D.BAT_STOP_T / 2
    b.boss("z", z_stop, D.TP_Z_FRONT - 1.6 - 0.1,         # -4.87: clears a 1.6 mm PCB
           lambda s: [s.rrect(xs0, y, D.BAT_STOP_T, 2.0, 0) for y in (D.TP_Y0 + 1.4, D.TP_Y1 - 1.4)], "TP_Hold")
    ```
    - In `tp_fence`: `s.rrect(tx1 + 0.1 + 0.5, ...)`, with `TP["l"]` and `TP["usb_over"]` set from caliper measurements.

- **6. MAJOR: the buzzer is loose** (`parts_shell.py` 321–332; `design.py` 187)
  - **What's wrong:**
    - The U is 12.4 wide for a 12.0 body, 0.2 mm per side.
    - The pocket is only 5.0 deep (X 42.4–47.4) for a 9.5 mm body, so 4.5 mm hangs into the cavity.
    - The U is open toward +Z up to −13.5. The buzzer's top is at −28.7 + 12.0 = −16.7.
    - The front shell has no feature at X > 40, so the buzzer can lift or tilt about 3 mm and slide in −X, held only by its leads.
  - **Fix:**
    ```python
    # front_shell()
    z_bt = D.BUZ_Z - D.BUZ["bore"]/2 + D.BUZ["d"]          # -16.7
    b.boss("z", D.Z_FIN, z_bt + 0.3, lambda s: s.rrect(D.XI - 2.5, D.BUZ["y"], 1.2, 8.0, 0), "Buzzer_Keeper")
    ```
    - Also set `BUZ["bore"]` to 12.2 so it holds by friction.

- **7. MAJOR: the INMP441 can slide out of its rails toward the screen** (`parts_shell.py` 300–316)
  - **What's wrong:**
    - The rails end at zs − 3 = −16.0. The board spans −29.6 to −15.4 and nothing in the front shell stops +Z movement.
    - The lips (inner edges at X 9.55 and 22.45, a 12.9 mm opening) only grip the Ø14.2 round board where its chord exceeds 12.9, which is within ±√(7.1² − 6.45²) = ±2.97 mm of its centre.
    - So the board can travel about 9 mm, and the port ends up far from the Ø1.5 hole. It will rattle even in the wallet build, where the mic is fitted but not wired.
    - The PCB slot is t + 0.15 = 1.15 mm, while the research gives 1.0–1.6 mm thick boards.
  - **Fix:**
    ```python
    # front_shell()
    b.boss("z", D.Z_FIN, D.MIC_Z + D.MIC["d"]/2 + 0.3,     # -15.1
           lambda s: s.rrect(D.MIC["x"], D.YI - 0.6, 6.0, 1.2, 0), "Mic_Keeper")
    ```
    - Set `MIC["t"]` to the measured PCB thickness.

- **8. MINOR: the front-shell lip touches back-shell features with zero clearance** (`parts_shell.py` 324, 327, 290)
  - **What's wrong:**
    - The STL at Y = −25, Z −14.2 to −15.3 shows the buzzer block at X 42.41–47.40 and the lip starting at 47.41, over 14.8 x 1.5 mm.
    - The switch cradle ends at Y 28.40 and the lip starts at 28.41, over Z −15.15 to −15.5.
    - The lip's inner face is an inner contour, which prints 0.1–0.2 mm small. That gives local interference, pushes the lip outward and roughly doubles the bead interference there.
  - **Fix:**
    - In `buz_cradle`: `zs - 1.0` becomes `zs - D.LIP_H - 0.5`.
    - In `buz_u`: `top = zs - D.LIP_H - 0.3`.
    - The cradle is already handled by `ztop` in finding 1.

- **9. MINOR: the battery bay fits a cell up to 19.30 mm, not 19.6 as documented** (`design.py` 135–140; PRINTING table)
  - **What's wrong:**
    - The saddle arc bottom is at BAT_Z − 10.15 = −29.95. The rib tips are at BAT_Z − 10.15 + BAT_D + 0.3 = −10.65.
    - So the maximum diameter is 19.30, not the ~19.6 in the comment and in PRINTING. A 19.5 mm taped cell plus a wire folded along it jams three ribs and stops the lid closing.
    - At the left end, the gap from the stop's outer face (−45.5) to the wall (−47.4) is only 1.9 mm for the wire's 90° turn. The research asks for 4–6 mm.
  - **Fix:**
    - Set `BAT_D` to the measured wrapped diameter; the ribs are derived from it.
    - Change the comment and PRINTING to "≤ BAT_D + 0.3".
    - `BAT_X0 = -42.8` gives a 3.4 mm channel. The right stop moves to 28.2–29.4, which is still clear of the buzzer at X ≥ 37.9.

- **10. MINOR: the SIGN-pin press depth depends on layer rounding** (`design.py` 171)
  - **What's wrong:**
    - The flange stops on the PCB edge. So press depth = (−45.92 − (−46.60)) − 0.39 = 0.29, which is nub length 0.57 minus the 0.28 plunger recess.
    - At 0.12 mm layers (0.2 first layer), the flange top prints at 4.52 or 4.64 and the nub top at 5.12 or 5.24.
    - So the nub comes out 0.48–0.72 mm and the press depth 0.20–0.44. A side tact switch has about 0.25 ± 0.1 mm of travel, so it may either fail to click or bottom out.
    - Separately, the nub clears the PCB back face by only 0.205 mm (−7.505 vs −7.3), and the shaft has 0.2 mm radial play.
  - **Fix:** `PIN = dict(..., flange_t=0.84, nub_gap=0.32)`.
    - The flange top then prints at 4.64 and the nub top at 5.24, both exact layer boundaries.
    - Nub length becomes 0.60 and press depth (0.64 − 0.32) = 0.32.

- **11. MINOR: the MAX30102 floats and its IC sits below the skin surface** (`parts_shell.py` 345–347)
  - **What's wrong:**
    - The ledges end at −2.0, so the IC top is at −2.0 + 1.55 = −0.45: 0.45 mm below the face, inside the 10 x 8 window. The research target is flush to 0.3 mm proud.
    - The posts stop at z_mod_back − 0.3 = −3.9, and nothing preloads the module. It floats 0.3 mm, or 0.9 mm with a 1.0 mm PCB, since `t = 1.6` is assumed.
    - So the IC can end up 0.45–1.35 mm below the thumb, which lets in more ambient light and LED crosstalk.
  - **Fix:**
    - `MAX_Posts` top: `z_mod_back - 0.3` becomes `z_mod_back - 0.05`.
    - Set `MAX["t"]` to the measured bare PCB thickness, since the posts land on the bare corners.

- **12. MINOR: the lens hood is sized correctly but printed in light filament**
  - **Checked OK:**
    - Lens top is at −16.2. The 4.8–6.5 mm module range puts it at −15.0 to −16.7, which is 1.8–3.5 mm clear of the hood lip at −18.5.
    - For the 68° diagonal FOV (34° half), the ray envelope at the lens face is 1.25 + 15.8·tan34° = 11.9 mm, against a bore of 5 + 13.5·tan33° = 13.77 mm. At the mouth it is 2.8 vs 5.0, so centring by eye within about ±1.8 mm is fine.
  - **Issue:**
    - The bore cone faces the scene directly and sits only about 1.9 mm outside the FOV. The hood wall is about 1.0 mm normal thickness (1.2·cos 33°).
    - `C_SHELL_B` and the renders show a light back shell, and PRINTING only asks for a dark front shell. Light PLA scatters and leaks light, which causes flare and lowers QR contrast.
  - **Fix:** in PRINTING, require black or dark matte PLA for `Back_Shell` (or blacken the bore), and optionally set `HOOD_T = 1.6`.

Checked with no issue:
- **LCD bezel overlap:** left 5.00, right 1.40, top and bottom 1.60 mm. The window sits 0.4 mm outside the active area.
- **RST pinhole:** Ø1.3 at Y 1.11, Z −8.31, 1.76 mm from the plunger.
- **TP4056 port Z vs PCB thickness 1.0–1.6 mm:** the receptacle centre moves from −5.80 to −6.40, inside the −3.75 to −8.25 opening.
- **Switch floor-stop formula:** `YI − body_h − 0.15` is correct once `body_h` is measured.
- **Interference report:** only the expected header pins inside the dupont housings.