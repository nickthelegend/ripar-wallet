"""
Printable parts of Ripar Wallet v1 (wallet edition), built as native
SolidWorks features from design.py:

    Front_Shell   screen side  (print screen-face down)
    Back_Shell    lens side    (print lens-face down)
    Sign_Pin      presses the board's BOOT key (GPIO0) = SIGN / NEXT

All coordinates are device coordinates (see design.py).
"""
import math
import os
import time

import numpy as np

import design as D
from swlib import Part, unit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PARTS = os.path.join(ROOT, "model", "parts")

AX = {"x": (1, 0, 0), "y": (0, 1, 0), "z": (0, 0, 1)}
BASE = {"x": "Right Plane", "y": "Top Plane", "z": "Front Plane"}
# sketch frames: (u, v) per plane axis -> sketch coordinates are
#   z-planes (x, y)   x-planes (y, z)   y-planes (x, z)
FRAME = {"z": ((1, 0, 0), (0, 1, 0)), "x": ((0, 1, 0), (0, 0, 1)), "y": ((1, 0, 0), (0, 0, 1))}


# =============================================================================
# small builder layer on top of swlib
# =============================================================================
class B:
    def __init__(self, name):
        self.p = Part(name)
        self.n = 0

    def plane(self, axis, v):
        if abs(v) < 1e-9:
            return BASE[axis]
        name = "P%s_%s" % (axis.upper(), ("%+.2f" % v).replace("+", "p").replace("-", "m").replace(".", "_"))
        if not self.p.has_feature(name):
            self.p.plane_offset(BASE[axis], abs(v), name, flip=v < 0)
        return name

    def sketch(self, axis, v, draw, tag):
        u, w = FRAME[axis]
        o = np.zeros(3)
        o["xyz".index(axis)] = v
        s = self.p.sketch(self.plane(axis, v), origin=o, u=u, v=w)
        draw(s)
        self.n += 1
        return s.close("%s_Sk%d" % (tag, self.n))

    def boss(self, axis, v0, v1, draw, tag, **kw):
        t = time.time()
        sk = self.sketch(axis, v0, draw, tag)
        d = np.array(AX[axis], float) * np.sign(v1 - v0)
        f = self.p.extrude_toward(sk, abs(v1 - v0), d, name=tag, **kw)
        trace("boss", tag, t)
        return f

    def cut(self, axis, v0, v1, draw, tag, **kw):
        t = time.time()
        sk = self.sketch(axis, v0, draw, tag)
        d = np.array(AX[axis], float) * np.sign(v1 - v0)
        f = self.p.cut_toward(sk, abs(v1 - v0), d, name=tag, **kw)
        trace("cut", tag, t)
        return f

    def text(self, axis, v, origin_uv, u, w, txt, h, tag, depth=D.TXT_DEPTH, width_factor=1.0):
        o = np.zeros(3)
        o["xyz".index(axis)] = v
        s = self.p.sketch(self.plane(axis, v), origin=o, u=u, v=w)
        s.text(origin_uv, txt, h, font=D.FONT, width_factor=width_factor)
        self.n += 1
        sk = s.close("%s_Sk%d" % (tag, self.n))
        inward = -np.cross(unit(u), unit(w))
        f = self.p.cut_toward(sk, depth, inward, name=tag)
        lo, hi = np.full(3, 1e9), np.full(3, -1e9)
        from swlib import V, FaceInfo
        for fc in V(f.GetFaces) or []:
            fi = FaceInfo(fc)
            lo, hi = np.minimum(lo, fi.bmin), np.maximum(hi, fi.bmax)
        print("  %-12s box %s .. %s" % (tag, np.round(lo, 2), np.round(hi, 2)), flush=True)
        return lo, hi


def trace(kind, tag, t0):
    if os.environ.get("RIPAR_TRACE"):
        print("    %-5s %-24s %6.1fs" % (kind, tag, time.time() - t0), flush=True)


def inset(p):
    """distance of a point (x, y) inside the outer rounded-rectangle outline"""
    x, y = abs(p[0]), abs(p[1])
    cx, cy = D.W / 2 - D.RC, D.H / 2 - D.RC
    if x > cx and y > cy:
        return D.RC - math.hypot(x - cx, y - cy)
    return min(D.W / 2 - x, D.H / 2 - y)


def outline(s, off):
    """outer outline offset inward by `off`"""
    s.rrect(0, 0, D.W - 2 * off, D.H - 2 * off, D.RC - off)


def stadium(s, c, w, h):
    """obround w x h centred at c (long axis along sketch u)"""
    r = h / 2.0
    if w <= h:
        s.circle(c, r)
    else:
        s.slot((c[0] - (w / 2 - r), c[1]), (c[0] + (w / 2 - r), c[1]), r)


def edges_at_z(p, z, tol=1e-3):
    t = time.time()
    out = [e for e in p.edges() if all(abs(pt[2] - z) < tol for pt in e.pts())]
    trace("edges", "z=%.2f (%d)" % (z, len(out)), t)
    return out


# =============================================================================
# FRONT SHELL
# =============================================================================
def front_shell():
    b = B("Front_Shell")
    p = b.p
    zs = D.Z_SPLIT
    # --- body, screen-face round, cavity ----------------------------------
    b.boss("z", 0.0, zs, lambda s: outline(s, 0), "Body")
    p.fillet(edges_at_z(p, 0.0), D.R_FRONT, name="Round_Front")
    b.cut("z", zs, D.Z_FIN, lambda s: outline(s, D.T_WALL), "Cavity")
    # --- lip + snap bead ---------------------------------------------------
    o_lip = D.RIM_T + D.LIP_CLR

    def ring(s, a, c):
        outline(s, a)
        outline(s, c)
    b.boss("z", zs, zs - D.LIP_H, lambda s: ring(s, o_lip, D.T_WALL), "Lip")
    lip_end = [e for e in edges_at_z(p, zs - D.LIP_H) if all(inset(pt) < o_lip + 0.3 for pt in e.pts())]
    p.chamfer(lip_end, D.LIP_CHAMFER, name="Lip_Chamfer", quiet=True)
    # bead: full height at BEAD_Z[0], ramps to flush toward the free end (lead-in)
    ramp = math.degrees(math.atan(D.BEAD / (D.BEAD_Z[0] - D.BEAD_Z[1])))
    b.boss("z", D.BEAD_Z[0], D.BEAD_Z[1], lambda s: ring(s, o_lip - D.BEAD, o_lip + 0.6), "Bead",
           draft=ramp, draft_out=False)
    # --- screen window (active area + margin, chamfered outward) -----------
    x0, x1, y0, y1 = D.WIN_OUT
    r_out = D.WIN_R + D.T_FRONT * math.tan(math.radians(D.WIN_DRAFT))
    b.cut("z", 0.0, -(D.T_FRONT + 0.3),
          lambda s: s.rrect((x0 + x1) / 2, (y0 + y1) / 2, x1 - x0, y1 - y0, r_out),
          "Screen_Window", draft=D.WIN_DRAFT, draft_out=False)
    # --- board locating fences (the top and left walls locate the other edges)
    px0, px1, py0, py1 = D.PCB
    fz = D.FENCE_Z_END

    def fences(s):
        c = D.FENCE_CLR
        t = D.FENCE_T
        s.rrect(px1 + c + t / 2, (py0 + py1) / 2 + 1.0, t, (py1 - py0) - 4.0, 0)       # right edge
        s.rrect((px0 + px1) / 2 + 1.5, py0 - c - t / 2, (px1 - px0) - 6.0, t, 0)       # bottom edge
    b.boss("z", D.Z_FIN, fz, fences, "Board_Fence")
    # --- TP4056 charger cradle --------------------------------------------
    tx0, tx1 = D.TP_X0, D.TP_X0 + D.TP["l"]
    ty0, ty1 = D.TP_Y0, D.TP_Y1
    c = 0.15

    def tp_rails(s):
        s.rrect((tx0 + tx1) / 2, ty0 + 1.0, tx1 - tx0 - 3.0, 1.2, 0)
        s.rrect((tx0 + tx1) / 2, ty1 - 1.0, tx1 - tx0 - 3.0, 1.2, 0)
    b.boss("z", D.Z_FIN, D.TP_Z_FRONT, tp_rails, "TP_Rails")
    z_tp_fence = D.TP_Z_FRONT - D.TP["t"] - 0.6

    def tp_fence(s):
        s.rrect((tx0 + tx1) / 2 + 2.0, ty1 + c + 0.5, tx1 - tx0 - 4.0, 1.0, 0)          # top
        s.rrect(tx1 + 0.3 + 0.5, (ty0 + ty1) / 2, 1.0, ty1 - ty0 - 2.0, 0)             # right end (0.3 slack)
        s.rrect((tx0 + tx1) / 2 + 2.0, (ty0 - c + (-D.YI)) / 2, tx1 - tx0 - 4.0, ty0 - c + D.YI, 0)  # bottom
    b.boss("z", D.Z_FIN, z_tp_fence, tp_fence, "TP_Fence")
    # --- ribs that hold the 18650 down against the back-shell saddles ------
    z_cell_front = D.BAT_Z - (D.BAT_CAV_D - D.BAT_D) / 2 + D.BAT_D / 2

    def bat_ribs(s):
        for x in D.BAT_RIB_X:
            s.rrect(x, D.BAT_Y, D.BAT_RIB_T, 12.0, 0)
    b.boss("z", D.Z_FIN, z_cell_front + D.BAT_RIB_GAP, bat_ribs, "Cell_Ribs")
    # --- MAX30102 thumb pad ------------------------------------------------
    m = D.MAX
    relief = D.T_FRONT - 0.7                           # leaves a 0.7 mm skin over the module
    b.cut("z", D.Z_FIN, D.Z_FIN + relief,
          lambda s: s.rrect(m["x"], m["y"], m["l"] - 1.0, m["w"] - 1.0, 1.0), "MAX_Relief")
    wl, ww = m["win"]
    b.cut("z", 0.0, D.Z_FIN - 0.2,
          lambda s: s.rrect(m["x"], m["y"], wl, ww, m["win_r"]), "MAX_Window")
    ch = [e for e in edges_at_z(p, 0.0)
          if all(abs(pt[0] - m["x"]) < wl / 2 + 0.05 and abs(pt[1] - m["y"]) < ww / 2 + 0.05 for pt in e.pts())]
    p.chamfer(ch, m["win_chamfer"], name="MAX_Window_Chamfer", quiet=True)
    z_pcb_front = D.Z_FIN + relief - m["comp_h"] - 0.1      # components sit under the 0.7 mm skin
    z_mod_back = z_pcb_front - m["t"]

    def max_ledges(s):
        for sx in (-1, 1):
            for sy in (-1, 1):
                s.rrect(m["x"] + sx * (m["l"] / 2 - 0.6), m["y"] + sy * (m["w"] / 2 - 0.6), 1.6, 1.6, 0)
    b.boss("z", D.Z_FIN + relief, z_pcb_front, max_ledges, "MAX_Ledges")

    def max_fence(s):
        c, t = 0.2, 1.2
        L, Wd = m["l"] + 2 * c, m["w"] + 2 * c
        xa, xi, xe = m["x"] - L / 2 - t, m["x"] - L / 2, m["x"] + L / 2 - 2.0   # U open toward +X (wires)
        yti, ybi = m["y"] + Wd / 2, m["y"] - Wd / 2
        s.poly([(xa, yti + t), (xe, yti + t), (xe, yti), (xi, yti), (xi, ybi), (xe, ybi), (xe, ybi - t),
                (xa, ybi - t)])
    b.boss("z", D.Z_FIN, z_mod_back - 0.6, max_fence, "MAX_Fence")
    # --- left wall: board USB-C, SIGN pin, RST pinhole, charge USB-C -------
    xl = -D.W / 2
    uy, uz = D.USB_C[1], D.USB_C[2]
    ty = (D.TP_Y0 + D.TP_Y1) / 2
    rw, rh, rd = D.USB_RECESS
    b.cut("x", xl, xl + rd, lambda s: (s.rrect(uy, uz, rw, rh, 1.2),
                                       s.rrect(ty, D.TP_USB_Z, rw, rh, 1.2)), "USB_Recess")

    def holes(s):
        stadium(s, (uy, uz), *D.USB_HOLE)
        stadium(s, (ty, D.TP_USB_Z), *D.TP_USB_HOLE)
        s.circle((D.Y_BOOT, D.Z_PIN), D.PIN_HOLE_D / 2)
        s.circle((D.Y_RST, D.Z_PIN), D.RST_HOLE_D / 2)
    b.cut("x", xl, xl + D.T_WALL + 0.6, holes, "Left_Ports")
    # --- keepers that stop the buzzer and the mic walking toward the screen ----
    z_bt = D.BUZ_Z - D.BUZ["bore"] / 2 + D.BUZ["d"]                      # top of the seated buzzer
    b.boss("z", D.Z_FIN, z_bt + 0.3, lambda s: s.rrect(D.XI - 2.5, D.BUZ["y"], 1.2, 8.0, 0), "Buzzer_Keeper")
    b.boss("z", D.Z_FIN, D.MIC_Z + D.MIC["d"] / 2 + 0.3,
           lambda s: s.rrect(D.MIC["x"], D.YI - 0.6, 6.0, 1.2, 0), "Mic_Keeper")
    # --- shadow line at the seam ------------------------------------------------
    seam = [e for e in edges_at_z(p, zs) if all(inset(pt) < 0.05 for pt in e.pts())]
    p.chamfer(seam, D.SEAM_CHAMFER, name="Seam_Shadow", quiet=True)
    # --- pry notch across the seam (bottom face) ----------------------------
    pr = D.PRY
    b.cut("y", -D.H / 2, -D.H / 2 + pr["d"],
          lambda s: s.rrect(pr["x"], zs + pr["h"] / 2, pr["w"], pr["h"], 0), "Pry_Notch")
    p.material("PLA")
    p.color(D.C_SHELL_F)
    return p


# =============================================================================
# BACK SHELL
# =============================================================================
def back_shell():
    b = B("Back_Shell")
    p = b.p
    zs = D.Z_SPLIT
    zb = -D.D
    b.boss("z", zs, zb, lambda s: outline(s, 0), "Body")
    p.fillet(edges_at_z(p, zb), D.R_BACK, name="Round_Back")
    b.cut("z", zs, D.Z_BIN, lambda s: outline(s, D.T_WALL), "Cavity")

    def ring(s, a, c):
        outline(s, a)
        outline(s, c)
    b.cut("z", zs, zs - D.LIP_H - 0.3, lambda s: ring(s, D.RIM_T, D.T_WALL), "Rebate")
    b.cut("z", D.GROOVE_Z[0], D.GROOVE_Z[1], lambda s: ring(s, D.RIM_T - D.GROOVE_D, D.RIM_T + 0.3), "Groove")
    lead = [e for e in edges_at_z(p, zs) if all(abs(inset(pt) - D.RIM_T) < 0.05 for pt in e.pts())]
    p.chamfer(lead, 0.3, name="Rim_LeadIn", quiet=True)
    seam = [e for e in edges_at_z(p, zs) if all(inset(pt) < 0.05 for pt in e.pts())]
    p.chamfer(seam, D.SEAM_CHAMFER, name="Seam_Shadow", quiet=True)
    # --- board pegs: flat shoulders land on the M2 SMT nuts (walls + fences locate XY)
    z_peg = D.Z_STANDOFF_END - D.PEG_GAP
    b.boss("z", D.Z_BIN, z_peg, lambda s: [s.circle(tuple(c), D.PEG_D / 2) for c in D.STANDOFFS], "Board_Pegs")
    if D.PEG_TIP_L > 0:
        b.boss("z", z_peg, z_peg + D.PEG_TIP_L,
               lambda s: [s.circle(tuple(c), D.PEG_TIP_D / 2) for c in D.STANDOFFS], "Peg_Tips")
    # --- 18650 saddles, end stops, cell cavity ------------------------------
    def saddles(s):
        top = D.BAT_Y + D.BAT_CAV_D / 2 - 0.5
        for x in D.SADDLE_X:
            s.rrect(x, (-D.YI + top) / 2, D.SADDLE_T, top + D.YI, 0)
    b.boss("z", D.Z_BIN, D.SADDLE_TOP, saddles, "Cell_Saddles")
    z_stop = D.BAT_Z + 3.0

    def stops(s):
        top = D.BAT_Y + 8.0
        for x in (D.BAT_X0 - D.BAT_STOP_T / 2, D.BAT_X1 + D.BAT_STOP_T / 2):
            s.rrect(x, (-D.YI + top) / 2, D.BAT_STOP_T, top + D.YI, 0)
    b.boss("z", D.Z_BIN, z_stop, stops, "Cell_Stops")
    xs0 = D.BAT_X0 - D.BAT_STOP_T / 2
    b.boss("z", z_stop, D.TP_Z_FRONT - 1.6 - 0.1,               # stop the TP4056 dropping (PCB up to 1.6)
           lambda s: [s.rrect(xs0, y, D.BAT_STOP_T, 2.0, 0) for y in (D.TP_Y0 + 1.4, D.TP_Y1 - 1.4)],
           "TP_Keepers")
    b.cut("z", z_stop, D.BAT_Z - 3.0,
          lambda s: [s.rrect(x, D.BAT_Y, 3.0, D.BAT_WIRE_SLOT, 0)
                     for x in (D.BAT_X0 - D.BAT_STOP_T / 2, D.BAT_X1 + D.BAT_STOP_T / 2)], "Cell_Wire_Slots")
    b.cut("x", D.BAT_X0, D.BAT_X1, lambda s: s.circle((D.BAT_Y, D.BAT_Z), D.BAT_CAV_D / 2), "Cell_Cavity")
    # --- lens hood + bore + bezel groove -----------------------------------
    lx, ly = D.LENS_XY
    tn = math.tan(math.radians(D.HOOD_DRAFT))
    r_boss = D.HOOD_BORE_R + D.HOOD_T + (D.HOOD_TOP_Z - D.Z_BIN) * tn
    b.boss("z", D.Z_BIN, D.HOOD_TOP_Z, lambda s: s.circle((lx, ly), r_boss), "Lens_Hood",
           draft=D.HOOD_DRAFT, draft_out=False)
    r_bore = D.HOOD_BORE_R + (D.HOOD_TOP_Z - zb) * tn
    b.cut("z", zb, D.HOOD_TOP_Z + 0.01, lambda s: s.circle((lx, ly), r_bore), "Lens_Bore",
          draft=D.HOOD_DRAFT, draft_out=False)
    b.cut("z", zb, zb + D.LENS_RING_D,
          lambda s: (s.circle((lx, ly), D.LENS_RING_R[1]), s.circle((lx, ly), D.LENS_RING_R[0])), "Lens_Bezel")
    # --- big latching power switch: cradle hanging from the top wall -------
    sw = D.SW
    a = sw["body"] / 2 + D.SW_CRADLE_CLR
    t = D.SW_CRADLE_T
    zc = D.SW_Z
    z_lo = zc - a - t
    if z_lo - D.Z_BIN < 0.8:
        z_lo = D.Z_BIN
    z_hi = min(zc + a + t, zs - D.LIP_H - 0.3)            # roof clears the front-shell lip

    def cradle(s):
        s.rrect(sw["x"], (z_hi + z_lo) / 2, 2 * (a + t), z_hi - z_lo, 0)
        s.rrect(sw["x"], zc, 2 * a, 2 * a, 0)
    y_floor = D.YI - sw["body_h"] - D.SW_CRADLE_CLR
    b.boss("y", D.YI, y_floor, cradle, "Switch_Cradle")

    def floor(s):
        s.rrect(sw["x"], (z_hi + z_lo) / 2, 2 * (a + t), z_hi - z_lo, 0)
        s.rrect(sw["x"], zc, 2 * a - 1.8, 2 * a - 1.8, 0.5)
    b.boss("y", y_floor, y_floor - 1.2, floor, "Switch_Floor")
    # square opening = cradle bore: push the switch in from OUTSIDE, leads first, onto the floor ring
    b.cut("y", D.H / 2, D.YI - 0.2, lambda s: s.rrect(sw["x"], zc, 2 * a, 2 * a, 0.3), "Switch_Hole")
    # --- INMP441 mic: slide-in rails on the top wall (open toward the seam) -
    mc = D.MIC
    half = mc["d"] / 2 + 0.15

    z_r0, z_r1 = D.Z_BIN, zs - 3.0           # rails run from the lens wall toward the seam

    def mic_rails(s):
        for sx in (-1, 1):
            s.rrect(mc["x"] + sx * (half + 0.6), (z_r0 + z_r1) / 2, 1.2, z_r1 - z_r0, 0)
    b.boss("y", D.YI, D.YI - (mc["t"] + 1.0), mic_rails, "Mic_Rails")

    def mic_lips(s):
        for sx in (-1, 1):
            s.rrect(mc["x"] + sx * (half - 0.2), (z_r0 + z_r1) / 2, 1.2, z_r1 - z_r0, 0)
    b.boss("y", D.YI - (mc["t"] + 0.15), D.YI - (mc["t"] + 1.0), mic_lips, "Mic_Lips")
    b.cut("y", D.H / 2, D.YI - 0.2, lambda s: s.circle((mc["x"], zc), mc["hole_d"] / 2), "Mic_Hole")
    b.cut("y", D.H / 2, D.H / 2 - mc["csk"], lambda s: s.circle((mc["x"], zc), mc["csk_d"] / 2), "Mic_Csk")
    # --- buzzer: U-cradle on the right wall + sound holes ------------------
    bz = D.BUZ
    rb = bz["bore"] / 2

    def buz_cradle(s):
        # U open toward the seam (+Z): printable without support
        z0, z1 = D.Z_BIN, zs - D.LIP_H - 0.3
        s.rrect(bz["y"], (z0 + z1) / 2, 2 * rb + 2.4, z1 - z0, 0)
    b.boss("x", D.XI, D.XI - 5.0, buz_cradle, "Buzzer_Cradle_Block")
    def buz_u(s):
        top = zs - 0.5
        s.line((bz["y"] - rb, top), (bz["y"] - rb, zc))
        s.arc3((bz["y"] - rb, zc), (bz["y"], zc - rb), (bz["y"] + rb, zc))
        s.line((bz["y"] + rb, zc), (bz["y"] + rb, top))
        s.line((bz["y"] + rb, top), (bz["y"] - rb, top))
    b.cut("x", D.XI + 0.01, D.XI - 5.0, buz_u, "Buzzer_Pocket")

    def buz_holes(s):
        s.circle((bz["y"], zc), bz["hole_d"] / 2)
        for k in range(6):
            a6 = math.radians(60 * k)
            s.circle((bz["y"] + bz["pitch"] * math.cos(a6), zc + bz["pitch"] * math.sin(a6)), bz["hole_d"] / 2)
    b.cut("x", D.W / 2, D.XI - 0.2, buz_holes, "Buzzer_Holes")
    b.cut("x", D.XI, D.W / 2 - bz["thin_to"], lambda s: s.circle((bz["y"], zc), 5.0), "Buzzer_Chamber")
    # --- MAX30102 back-up post (takes the thumb load) -----------------------
    m = D.MAX
    z_mod_back = D.Z_FIN + (D.T_FRONT - 0.7) - m["comp_h"] - 0.1 - m["t"]
    # two posts on the PCB corners of the closed end (regulators sit mid-board on the back)
    b.boss("z", D.Z_BIN, z_mod_back - 0.3,
           lambda s: [s.circle((m["x"] + sx * (m["l"] / 2 - 1.3), m["y"]), 1.2) for sx in (-1, 1)],
           "MAX_Posts")                                   # short-edge midpoints: off the header row
    # --- lettering ------------------------------------------------------------
    zt = D.SW_Z
    lo, hi = b.text("y", D.H / 2, (-43.5, -zt - D.TXT_TOP_H / 2), (1, 0, 0), (0, 0, -1), D.BRAND,
                    D.TXT_TOP_H, "Txt_Top")
    L_bot = (hi[0] - lo[0]) * D.TXT_BOT_H / D.TXT_TOP_H
    zc_top = (lo[2] + hi[2]) / 2
    b.text("y", -D.H / 2, (-L_bot / 2, -zt - D.TXT_BOT_H / 2 + (zc_top - zt) * D.TXT_BOT_H / D.TXT_TOP_H), (-1, 0, 0), (0, 0, -1), D.BRAND,
           D.TXT_BOT_H, "Txt_Bottom")
    b.text("z", zb, (-44.0, 17.0), (-1, 0, 0), (0, 1, 0), D.TXT_BACK, D.TXT_BACK_H, "Txt_Back", depth=0.8)
    p.material("PLA")
    p.color(D.C_SHELL_B)
    return p


# =============================================================================
# SIGN PIN (separate, tiny): pressed from outside, pushes the BOOT key
# =============================================================================
def sign_pin():
    b = B("Sign_Pin")
    p = b.p
    pn = D.PIN
    yz = (D.Y_BOOT, D.Z_PIN)
    x_out = -D.W / 2 - pn["proud"]
    x_in = -D.XI
    x_tip = D.X_PLUNGER - pn["nub_gap"]
    b.boss("x", x_out, x_in, lambda s: s.circle(yz, pn["shaft_d"] / 2), "Shaft")
    b.boss("x", x_in + pn["flange_t"], x_in, lambda s: s.circle(yz, pn["flange_d"] / 2), "Flange",
           draft=40, draft_out=False)                         # coned underside: prints without support
    b.boss("x", x_in + pn["flange_t"], x_tip, lambda s: s.circle(yz, pn["nub_d"] / 2), "Nub")
    outer = [e for e in p.edges() if e.is_circle and abs(e.center[0] - x_out) < 1e-3]
    p.chamfer(outer, 0.2, name="End_Chamfer", quiet=True)      # flat end: stand it on a 3 mm brim
    p.material("PLA")
    p.color((0.20, 0.45, 0.95))
    return p


def _fit_test(builder, name):
    """left end only (USB ports, SIGN pin, board corner, lip + bead): ~20 min print"""
    p = builder()
    p.name = name
    s = p.sketch("Front Plane")
    s.rrect(D.FIT_TEST_X + 60.0, 0, 120.0, 120.0, 0)
    s.close("FitTest_Sk")
    p.cut("FitTest_Sk", through_both=True, name="FitTest_Trim")
    return p


def fit_test_front():
    return _fit_test(front_shell, "FitTest_Front")


def fit_test_back():
    return _fit_test(back_shell, "FitTest_Back")


BUILDERS = {"Front_Shell": front_shell, "Back_Shell": back_shell, "Sign_Pin": sign_pin,
            "FitTest_Front": fit_test_front, "FitTest_Back": fit_test_back}
