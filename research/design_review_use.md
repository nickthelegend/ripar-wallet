- **1. BLOCKER: the power switch can't be installed.**
  - **What:** The cradle is a closed square tube. Its only openings are too small for the 12 mm switch body.
    - Tube half-width `a = body/2 + SW_CRADLE_CLR = 6.0 + 0.15 = 6.15`.
    - Lens side: `zc - a - t = -22.5 - 6.15 - 1.2 = -29.85`, which is within 0.8 of `Z_BIN = -30`, so `z_lo` snaps to -30 and the tube merges into the lens wall.
    - Seam side: the tube is closed at `zc + a + t = -15.15`.
    - From below, the `Switch_Floor` opening is `2a - 1.8 = 10.5`, smaller than the 12.0 body.
    - From outside, the Ø12.6 `Switch_Hole` is smaller than the body diagonal, 12·√2 = 16.97.
    - I sectioned `_stl_cache/Back_Shell` at Y=22 and Y=15.6 and it is closed on all four sides.
  - **Why:** PRINTING step 3.2, "push the switch up into the square cradle", can't be done.
  - **Fix:** Open the tube toward the seam, then hold the switch with a tongue from the front shell.
    - In `back_shell()`, after `Switch_Floor`:
      ```python
      b.cut("z", zs, zc, lambda s: s.rrect(sw["x"], (D.YI + y_floor) / 2, 2 * a, D.YI - y_floor, 0), "Switch_Slot")
      b.cut("z", zs, zc, lambda s: s.rrect(sw["x"], y_floor - 0.6, 2 * a - 1.8, 1.2, 0), "Switch_Pin_Slot")
      ```
    - In `front_shell()`:
      ```python
      b.boss("z", D.Z_FIN, D.SW_Z + D.SW["body"] / 2 + 0.3, lambda s: s.rrect(D.SW["x"], D.YI - 6.0, 8.0, 1.6, 0), "Switch_Keeper")
      ```
      This ends at Z -16.2, 0.3 mm from the body's seam-side face.
    - PRINTING 3.2: "slide the switch in from the seam side, pins first".

- **2. MAJOR: nothing holds the TP4056 on its lens side, and when it drops, the charge port no longer lines up with its opening.**
  - **What:**
    - `TP_Rails` only support the screen side (Z -1.6 to -3.17).
    - `TP_Fence` ends at `-3.17 - 1.2 - 0.6 = -4.97`.
    - The back shell has nothing over X -46.3 to -18.3 (section at X=-32 confirms).
    - The USB shell bottom is at `-3.17 - 1.2 - 3.26 = -7.63`. The cell top is at `BAT_Z - (20.3-19)/2 + 9.5 = -10.95`. So the module can drop 3.32 mm.
    - `TP_USB_HOLE` spans `-6.0 ± 2.25 = -3.75..-8.25`. After the drop the receptacle sits at -7.7 to -10.95, so the plug can't enter.
    - PRINTING says "Clip the TP4056", but there is no clip.
    - The dropped receptacle shell (IN− = B−, X -47.1 to -39.75) lands over the left cell end (X -43.05). If that end is the + tab, B+ is shorted to B−. That short is on the cell side, where the DW01 can't interrupt it.
  - **Fix:** Extend the left cell stop up to the PCB back face, on both sides of the receptacle. In `back_shell()`, after `Cell_Stops`:
    ```python
    z_tp = D.TP_Z_FRONT - D.TP["t"] - 0.15   # -4.52
    b.boss("z", z_stop, z_tp, lambda s: [s.rrect(D.BAT_X0 - D.BAT_STOP_T/2, yc, D.BAT_STOP_T, 3.0, 0)
                                         for yc in (D.TP_Y0 + 1.7, D.TP_Y1 - 1.7)], "TP_Keepers")
    ```
    - The fingers sit at X -45.5 to -44.3 and Y -27.0 to -24.0 and -13.1 to -10.1, about 1 mm clear of the receptacle at Y -23.02 to -14.08.
    - PRINTING: measure the TP PCB and set `TP["t"]` from it, change "Clip" to "Lay", and add "cell negative end to the left".

- **3. MAJOR: the board's data USB-C is open on the outside next to the charge-only port.**
  - **What:**
    - `holes()` cuts the board's USB-C opening (9.8 × 4.1 at Y 10.59) plus the RST pinhole (Ø1.3). It sits 29.1 mm from the TP port (Y -18.55).
    - The plan (`research/judge_merge.md` §9) put that port behind a hatch and said "Never charge through the TP4056 and the board's USB-C at the same time".
  - **Why it matters:**
    - The port exposes native USB-JTAG. With SIGN (GPIO0) and RST both reachable from outside, anyone can enter ROM download mode.
    - Both chargers can run at once.
    - If both cables go to one PC or hub, the two USB grounds join TP IN− (= B−) to the board GND (= OUT−). That bypasses the DW01A/FS8205A low-side FETs, so the cell loses its protection while both are plugged in.
    - WIRING.md says "With the latching switch OFF the board is dead". That's false whenever the board's own USB-C is plugged in.
  - **Fix:** In `front_shell()`:
    - Remove the board `rrect` from `USB_Recess`.
    - Remove `stadium(s, (uy, uz), *D.USB_HOLE)` and the `RST_HOLE_D` circle from `holes()`.
    - Add a knock-out for development only:
      ```python
      b.cut("x", xl + 0.4, xl + D.T_WALL + 0.6, lambda s: stadium(s, (uy, uz), *D.USB_HOLE), "USB_Knockout")
      ```
    - Update WIRING's power notes and PRINTING fit-test step 1.

- **4. MAJOR: the charger runs at 1 A inside a sealed PLA box, next to the cell.**
  - **What:**
    - Charging dissipates `(5.0 - 3.7) × 1.0 = 1.3 W`, and 2.0 W at a 3.0 V cell.
    - The chip (to Z -5.97) is 4.98 mm from the cell.
    - The PLA rails touch the PCB.
    - There are no vents. The plan also asked for an OV5640 vent.
    - The project's research (`parts_dimensions.json`, TP4056 entry) says the module reaches 60–70 °C and PLA softens at 55–60 °C. It recommends PETG or R_PROG 2 kΩ, plus vent slots. PRINTING.md says PLA.
  - **Fix:**
    - Change R_PROG from 1.2 kΩ to 2.4 kΩ. `I = 1200 V / R_PROG = 0.5 A`, about 0.65 W.
    - PRINTING: print Front_Shell in PETG.
    - Optional vents in `front_shell()`:
      ```python
      b.cut("y", -D.H/2, -D.YI + 0.1, lambda s: [s.rrect(x, -8.5, 1.2, 6.0, 0.6) for x in (-40.0, -35.0, -30.0, -25.0)], "TP_Vents")
      ```

- **5. MAJOR: the MAX30102 is backed only at its left end, and those posts probably hit its header.**
  - **What:**
    - `MAX_Posts` sit at `x = 29 - 10.15 + 1.3 = 20.15`, `y = 11 ± 6.35`.
    - The thumb load at x=29 is 8.85 mm away. The right end (x 37.85–39.15) only has the front ledges, which resist outward motion, not inward.
    - So the module pivots away from the window, and sags with the screen facing up.
    - A 7-pin header needs 7 × 2.54 = 17.78 mm, so it must run along the 20.3 mm edge. PRINTING puts it on the back.
    - If centred, its plastic spans x 20.11–37.89 at y ≈ 3.35 + 1.27 = 4.62. The post (x 18.95–21.35, top 0.3 mm below the PCB) lands on that 2.5 mm header body.
  - **Fix:** Put the posts at the middle of the two short edges, clear of both long-edge header positions:
    ```python
    [s.circle((m["x"] + sx*(m["l"]/2 - 1.3), m["y"]), 1.2) for sx in (-1, 1)]
    ```
    That gives (20.15, 11) and (37.85, 11). The second post clears the switch cradle, which starts at y 15.05.

- **6. MAJOR (ergonomics): the power latch sits where the right index finger rests, and SIGN is on the far end.**
  - **What:**
    - `SW["x"] = 36` on the top face is directly above the thumb window at x=29, i.e. the shutter position.
    - One press of a latching switch (250–400 gf) turns the device off in the middle of signing.
    - SIGN is on the left end face (X -50, 1.2 mm proud) and is pressed along +X by the other hand. The plan wanted SIGN under the right index, with the thumb staying on the pad until SIGN is pressed.
    - The +X push shoves the device into the right hand exactly when the pulse reading must be steady.
    - GPIO0 is a strapping pin. If the left hand's grip holds SIGN while the latch is switched on, the chip boots into download mode and the screen stays blank.
  - **Fix:**
    - In `back_shell()`, after `Switch_Hole`, add a guard ring around the cap:
      ```python
      b.boss("y", D.H/2, D.H/2 + 2.0, lambda s: (s.circle((sw["x"], zc), 7.6), s.circle((sw["x"], zc), sw["hole_d"]/2 + 0.4)), "Switch_Guard")
      ```
    - Set `PIN["proud"] = 0.0` and add a dimple so the pin sits flush:
      ```python
      b.cut("x", xl, xl + 0.8, lambda s: s.circle((D.Y_BOOT, D.Z_PIN), 3.0), "Pin_Dimple")
      ```
    - Firmware: ignore SIGN if it is held at boot.

- **7. MAJOR: the INMP441 slot is too thin, nothing stops the mic sliding out, and its wires exit at the seam.**
  - **What:**
    - Slot height = `mc["t"] + 0.15 = 1.15 mm` (wall to lip, Y 28.4 to 27.25).
    - The research lists INMP441 PCBs at 1.0–1.6 mm. Solder on the through-hole pads bulges 0.3–0.8 mm on the hole face, and there's no room for the recommended 0.5–1 mm gasket.
    - The rails end at `zs - 3 = -16.0` and the board edge is at `-22.5 + 7.1 = -15.4`. The front shell has nothing there, so the mic can slide 13.8 mm toward the screen.
    - Its wires leave that edge against the top wall, 0.2 mm below the rebate floor (-15.6), which is a pinch risk at the lip.
  - **Fix:**
    - design.py: `MIC t=1.6`.
    - `Mic_Lips`: from `D.YI - (mc["t"] + 1.0)` to `D.YI - (mc["t"] + 1.9)`. `Mic_Rails`: to `D.YI - (mc["t"] + 1.9)`. The slot becomes 2.6 mm.
    - In `front_shell()`:
      ```python
      b.boss("z", D.Z_FIN, D.MIC_Z + D.MIC["d"]/2 + 0.3, lambda s: s.rrect(D.MIC["x"], D.YI - 0.8, 6.0, 1.6, 0), "Mic_Keeper")
      ```
      This ends at -15.1. Fit the mic with its pad rows parallel to the rails.

- **8. MAJOR: nothing holds the buzzer once the shells are closed.**
  - **What:**
    - The U-pocket bore is 12.4 against a 12.0 body, and it is open toward the seam up to -13.5.
    - The cradle block is 5 mm deep (X 42.4–47.4) for a 9.5 mm body.
    - The front shell has no feature at that X.
    - After closing, the buzzer can rise from -16.5 to -1.6: it rattles and leaves the grille.
    - Its 7.6 mm-pitch leads (Y -21.8 / -14.2) point at the right cell wire slot (Y -20.55 to -15.55).
  - **Fix:**
    - In `front_shell()`:
      ```python
      b.boss("z", D.Z_FIN, D.BUZ_Z + D.BUZ["d"]/2 + 0.3, lambda s: s.rrect(D.XI - 4.5, D.BUZ["y"], 5.0, 2.0, 0), "Buzzer_Keeper")
      ```
      This ends at -16.2, inside the pocket void.
    - `BUZ bore` from 12.4 to 12.2.
    - PRINTING: trim the leads to 3 mm and heat-shrink them.

- **9. MAJOR (WIRING.md): the MAX30102's I2C pull-ups can hold the shared bus near the ESP32's input threshold.**
  - **What:**
    - The project's research notes many purple MAX30102 boards pull SDA/SCL up to 1.8 V. WIRING wires them straight to GPIO47/48, which carry the board's 3.3 V 4.7 k pull-ups and the IMU.
    - With equal 4.7 k resistors the idle-high level is `(3.3 + 1.8)/2 = 2.55 V`. ESP32-S3 VIH(min) is `0.75 × 3.3 = 2.475 V`, a 75 mV margin.
    - About `(3.3 - 1.8)/9.4k = 0.16 mA` per line back-feeds the module's 1.8 V LDO.
  - **The rest of the GPIO table:**
    - It is internally consistent: each camera signal appears once, no GPIO is reused, and 0x57 doesn't clash with 0x6B.
    - I couldn't check it against the schematic, because `cad/vendor` only has the mechanical PDF.
    - "Only 18/43/44 are free" holds only while GPIO19/20 are kept for USB. With the port sealed (finding 3), put INMP441 SD on GPIO19 and keep the buzzer on 18.
  - **Fix (WIRING.md):**
    - Set the MAX board's pull-up jumper to 3.3 V, or remove its SDA/SCL pull-ups.
    - Add a 1N4148 across the buzzer when it is driven through the S8050.
    - Name the switch terminals as COM + NO of one pole.

- **10. MINOR: the snap uses a square catch, and the back-shell pry notch cuts through the rim.**
  - **What:**
    - The bead reaches inset `1.34 - 0.25 = 1.09` against the rim at 1.2, so 0.11 mm engagement.
    - Both faces are flat: the bead top at -13.9 and the groove top at -13.8. The research says 45–60° for a lid meant to open by hand.
    - The back-shell `Pry_Notch` (d 1.0) leaves 1.2 - 1.0 = 0.2 mm of rim, minus the 0.3 lead-in chamfer. Between Z -13.8 and -14.2 it meets the groove (inset 0.85–1.5), leaving an 8 × 0.4 mm through-slot.
    - The X=38 section shows a 0.1 mm floating strip that won't print.
  - **Fix:**
    - Delete the back-shell `Pry_Notch`.
    - `PRY h=1.6`, so the front notch alone runs Z -13 to -11.4.
    - `GROOVE_Z = (Z_SPLIT - 0.6, Z_SPLIT - 1.8)`.
    - After `Bead`, add a 45° release face:
      ```python
      b.boss("z", D.BEAD_Z[0], D.BEAD_Z[0] + D.BEAD, lambda s: ring(s, o_lip - D.BEAD, o_lip + 0.6), "Bead_Release", draft=45, draft_out=False)
      ```

- **11. MINOR: two overhangs conflict with "Supports OFF".**
  - **Sign_Pin:** The print STL stands on the Ø2.4 chamfered end, with the Ø5.4 flange at z = 1.2 + 2.6 = 3.8. That is a flat 1.1 mm ring overhang.
  - **Switch_Hole:** It is a Ø12.6 horizontal hole in a wall that stands vertical in the lens-down print, with no teardrop. Sag of 0.2–0.4 mm is about the same as the 0.3 radial cap clearance, so the cap will likely rub.
  - **Fix:**
    - Make the flange a cone:
      ```python
      b.boss("x", x_in + pn["flange_t"], x_in, lambda s: s.circle(yz, pn["flange_d"]/2), "Flange", draft=45, draft_out=False)
      ```
      with `PIN flange_t=1.1, nub_gap=0.19`. The cone seats 0.2 mm into the Ø3.6 hole.
    - Add a second cut giving the switch hole a flat-top teardrop (45° flanks, 5.2 mm flat roof):
      ```python
      s.poly([(x - 0.707*r, zc + 0.707*r), (x - 0.414*r, zc + r), (x + 0.414*r, zc + r), (x + 0.707*r, zc + 0.707*r)])
      ```
      with `r = 6.3`.

**Checked and fine:**
- **Board with the dupont wires attached:** it drops in with the wires on. The pegs clear the end housings by 1.27 and 1.32 mm, and the lens hood clears both header rows at Z -23.8.
- **Sign_Pin fit:** the 1.48 mm wall-to-PCB gap takes flange 0.8 + nub 0.57 + gap 0.39.
- **Wire paths across the seam:** the lip is flush with the inner walls, so wires crossing the seam away from the walls aren't pinched.