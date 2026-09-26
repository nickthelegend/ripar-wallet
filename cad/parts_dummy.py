"""
Component stand-ins (device coordinates) used for the assembly, interference
detection and renders.  The ESP32 board is modelled in parts_board.py from the
boxes measured on Waveshare's STEP; everything here is an envelope of the purchased part.
"""
import math

import design as D
from parts_shell import B


def _box(s, x0, x1, y0, y1):
    s.rrect((x0 + x1) / 2, (y0 + y1) / 2, abs(x1 - x0), abs(y1 - y0), 0)


def dupont_harness():
    """straight female jumper housings on both 14-pin headers"""
    b = B("Dupont_Harness")
    bd = D.BOARD

    def pins(s):
        for hx in bd["header_x"]:
            for k in range(14):
                by = bd["header_y"][0] + 1.27 + 2.54 * k
                c = D.b2d(hx, by)
                s.rrect(c[0], c[1], 2.4, 2.4, 0)
    b.boss("z", D.Z_HEADER_BODY_END, D.Z_DUPONT_END, pins, "Housings")
    b.p.color((0.08, 0.08, 0.08))
    return b.p


def camera():
    b = B("Camera_OV5640")
    lx, ly = D.LENS_XY
    cb = D.BOARD["cam_body"]
    b.boss("z", D.Z_CAM_BASE, D.Z_CAM_BASE - 4.5, lambda s: s.rrect(lx, ly, cb, cb, 0.3), "Body")
    b.boss("z", D.Z_CAM_BASE - 4.5, D.Z_LENS_TOP, lambda s: s.circle((lx, ly), D.BOARD["cam_lens_d"] / 2), "Lens")
    b.p.color((0.05, 0.05, 0.05))
    return b.p


def cell():
    b = B("Cell_18650")
    x0 = D.BAT_X0 + (D.BAT_CAV_L - D.BAT_L) / 2
    zc = D.BAT_Z - (D.BAT_CAV_D - D.BAT_D) / 2          # rests on the saddles (lens side)
    yc = D.BAT_Y
    b.boss("x", x0, x0 + D.BAT_L, lambda s: s.circle((yc, zc), D.BAT_D / 2), "Cell")
    b.p.color((0.10, 0.35, 0.75))
    return b.p


def tp4056():
    b = B("TP4056_USBC")
    tp = D.TP
    x0, x1, y0, y1 = D.TP_X0, D.TP_X0 + tp["l"], D.TP_Y0, D.TP_Y1
    zf = D.TP_Z_FRONT
    b.boss("z", zf, zf - tp["t"], lambda s: _box(s, x0, x1, y0, y1), "PCB")
    yc = (y0 + y1) / 2
    ux0 = x0 - tp["usb_over"]
    b.boss("z", zf - tp["t"], zf - tp["t"] - tp["usb_h"],
           lambda s: _box(s, ux0, ux0 + tp["usb_l"], yc - tp["usb_w"] / 2, yc + tp["usb_w"] / 2), "USB_C")
    b.boss("z", zf - tp["t"], zf - tp["t"] - 1.6, lambda s: _box(s, x0 + 11, x0 + 16, yc - 2.5, yc + 2.5), "Chip")
    b.p.color((0.05, 0.20, 0.60))
    return b.p


def max30102():
    b = B("MAX30102")
    m = D.MAX
    relief = D.T_FRONT - 0.7
    zf = D.Z_FIN + relief - m["comp_h"] - 0.1
    b.boss("z", zf, zf - m["t"], lambda s: s.rrect(m["x"], m["y"], m["l"], m["w"], 0.5), "PCB")
    b.boss("z", zf, zf + m["ic_h"], lambda s: s.rrect(m["x"], m["y"], m["ic_l"], m["ic_w"], 0), "IC")
    b.boss("z", zf, zf + m["comp_h"],
           lambda s: [s.rrect(m["x"] + dx, m["y"] + dy, 1.6, 0.8, 0) for dx in (-6, 6) for dy in (-4, 4)], "Parts")
    b.p.color((0.45, 0.15, 0.60))
    return b.p


def inmp441():
    b = B("INMP441")
    mc = D.MIC
    b.boss("y", D.YI, D.YI - mc["t"], lambda s: s.circle((mc["x"], D.MIC_Z), mc["d"] / 2), "PCB")
    b.boss("y", D.YI - mc["t"], D.YI - mc["t"] - 1.1,
           lambda s: s.rrect(mc["x"], D.MIC_Z, 4.72, 3.76, 0), "Mic")
    b.p.color((0.40, 0.15, 0.55))
    return b.p


def buzzer():
    b = B("Buzzer_12mm")
    bz = D.BUZ
    b.boss("x", D.XI, D.XI - bz["h"], lambda s: s.circle((bz["y"], D.BUZ_Z), bz["d"] / 2), "Body")
    b.p.color((0.06, 0.06, 0.06))
    return b.p


def latch_switch():
    b = B("Latch_Switch_12mm")
    sw = D.SW
    zc = D.SW_Z
    b.boss("y", D.YI, D.YI - sw["body_h"], lambda s: s.rrect(sw["x"], zc, sw["body"], sw["body"], 0.3), "Body")
    b.boss("y", D.YI, D.YI - sw["body_h"] - 3.5,
           lambda s: [s.rrect(sw["x"] + dx, zc + dz, 0.6, 0.6, 0) for dx in (-4.5, 0, 4.5) for dz in (-2.5, 2.5)],
           "Pins")
    b.boss("y", D.YI + 0.0, D.H / 2 + 3.0, lambda s: s.circle((sw["x"], zc), sw["cap_d"] / 2), "Cap")
    b.p.color((0.10, 0.30, 0.95))
    return b.p


BUILDERS = {
    "Dupont_Harness": dupont_harness, "Camera_OV5640": camera, "Cell_18650": cell,
    "TP4056_USBC": tp4056, "MAX30102": max30102, "INMP441": inmp441, "Buzzer_12mm": buzzer,
    "Latch_Switch_12mm": latch_switch,
}
