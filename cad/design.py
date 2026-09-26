"""
Ripar Wallet v1 (wallet edition) - single source of truth for every dimension.

Device frame (mm), looking at the screen:
    X  -> right          Y  -> up          Z  -> out of the screen (toward the user)
    screen (front) outer face  Z = 0
    lens   (back)  outer face  Z = -D

Camera-style landscape body.  Front shell (screen side) and back shell (lens side)
meet at Z = Z_SPLIT and close with a lip + snap bead (no screws).

Change a number here, then run  make_all.py  to rebuild every part, the
assembly, the interference check, STL/STEP exports and renders.
"""
import math

import numpy as np

# =============================================================================
# enclosure
# =============================================================================
W, H, D = 100.0, 62.0, 32.0      # outer size X, Y, Z
RC = 5.0                          # plan-view corner radius
R_FRONT = 2.0                     # round on the screen-face edges
R_BACK = 2.5                      # round on the lens-face edges
T_WALL = 2.6                      # side walls: outer 1.2 back-shell rim + 0.14 gap + 1.26 front-shell lip (3 lines)
T_FRONT = 1.6                     # screen-face wall
T_BACK = 2.0                      # lens-face wall
Z_SPLIT = -13.0                   # parting plane

LIP_H = 2.5                       # lip length past the parting plane
RIM_T = 1.2                       # back-shell rim thickness in the rebate
LIP_CLR = 0.14                    # radial clearance lip <-> rim (PLA 0.15/side)
LIP_T = T_WALL - RIM_T - LIP_CLR  # 1.26
BEAD = 0.25                       # snap bead proud of the lip face
BEAD_Z = (Z_SPLIT - 0.9, Z_SPLIT - 1.7)
GROOVE_D = 0.35                   # groove depth in the rim
GROOVE_Z = (Z_SPLIT - 0.7, Z_SPLIT - 1.8)   # 0.2 mm latch window
LIP_CHAMFER = 0.5

XI = W / 2 - T_WALL               # inner half extents (47.4)
YI = H / 2 - T_WALL               # (28.4)
Z_FIN = -T_FRONT                  # inner face of the screen wall
Z_BIN = -D + T_BACK               # inner face of the lens wall

# =============================================================================
# Waveshare ESP32-S3-LCD-2  (numbers from the official STEP / PDF drawing)
# board frame: bx across (35.01), by along (48.21, +by = LCD top, -by = USB edge),
#              bz toward the LCD glass.
# =============================================================================
BOARD = dict(
    pcb_x=(-17.51, 17.51), pcb_y=(-25.81, 22.41), pcb_z=(-3.60, -2.00),
    lcd_x=(-17.30, 17.30), lcd_y=(-25.80, 22.20), lcd_z=(-1.60, 2.10),
    aa_x=(-15.30, 15.30), aa_y=(-20.40, 20.40),            # active area
    standoff_xy=[(14.5, 19.40), (-14.5, 19.40), (14.5, -22.805), (-14.5, -22.805)],
    standoff_d=3.53, standoff_z=(-6.10, -2.10),              # M2 SMT nuts, 2.5 mm proud of the back
    header_x=(15.24, -15.24), header_y=(-19.46, 16.06), header_z=(-11.90, -0.60),
    header_body_z=(-6.10, -3.60),
    usb_x=(-4.79, 4.79), usb_y=(-26.99, -19.28), usb_z=(-6.85, -2.69),
    rst_x=9.475, boot_x=-9.45, sw_plunger_y=-25.53, sw_z=(-5.41, -3.20),
    fpc_x=(-8.60, 8.60), fpc_y=(-15.32, -9.63), fpc_z=(-5.60, -3.60),
    bat_x=(-12.92, -5.27), bat_y=(-7.90, -2.70), bat_z=(-7.00, -3.60),
    tf_x=(-6.05, 5.35), tf_y=(1.50, 7.00), tf_z=(-6.30, -3.65),
    cam_lens_xy=(0.65, 3.75),          # measured from Waveshare's back-view photo (mirrored)
    cam_body=8.5, cam_h=6.0, cam_lens_d=6.0,
)

# placement: landscape, USB edge toward the LEFT wall, LCD glass against the screen wall
OZ = Z_FIN - BOARD["lcd_z"][1]                                   # -3.70
OX = (-XI + 0.30) - BOARD["usb_y"][0]                            # USB-C face 0.3 mm off the wall
OY = (YI - 0.30) - BOARD["pcb_x"][1]                             # PCB top edge 0.3 mm off the wall


def b2d(bx, by, bz=0.0):
    """board frame -> device frame"""
    return np.array([by + OX, -bx + OY, bz + OZ])


def board_rect(xr, yr):
    """board-frame box -> device-frame (x0, x1, y0, y1)"""
    xs = sorted([yr[0] + OX, yr[1] + OX])
    ys = sorted([-xr[0] + OY, -xr[1] + OY])
    return xs[0], xs[1], ys[0], ys[1]


# 4x4 board->device transform (column vectors, mm)
BOARD_M = np.array([[0, 1, 0, OX], [-1, 0, 0, OY], [0, 0, 1, OZ], [0, 0, 0, 1]], float)

# derived board features in device coordinates
PCB = board_rect(BOARD["pcb_x"], BOARD["pcb_y"])
LCD = board_rect(BOARD["lcd_x"], BOARD["lcd_y"])
AA = board_rect(BOARD["aa_x"], BOARD["aa_y"])
Z_PCB_BACK = BOARD["pcb_z"][0] + OZ                              # -7.30
Z_STANDOFF_END = BOARD["standoff_z"][0] + OZ                     # -9.80
Z_HEADER_BODY_END = BOARD["header_body_z"][0] + OZ               # -9.80
Z_PIN_TIP = BOARD["header_z"][0] + OZ                            # -15.60
STANDOFFS = [b2d(x, y)[:2] for x, y in BOARD["standoff_xy"]]
LENS_XY = b2d(*BOARD["cam_lens_xy"])[:2]
Z_CAM_BASE = BOARD["tf_z"][0] + OZ - 0.2                         # module taped on the TF slot
Z_LENS_TOP = Z_CAM_BASE - BOARD["cam_h"]
USB_C = b2d(0, BOARD["usb_y"][0], (BOARD["usb_z"][0] + BOARD["usb_z"][1]) / 2)
Y_BOOT = b2d(BOARD["boot_x"], 0)[1]
Y_RST = b2d(BOARD["rst_x"], 0)[1]
X_PLUNGER = b2d(0, BOARD["sw_plunger_y"])[0]
Z_SW = (BOARD["sw_z"][0] + BOARD["sw_z"][1]) / 2 + OZ

# dupont housings on the header pins (straight female jumpers)
DUPONT_L = 14.0
Z_DUPONT_END = Z_HEADER_BODY_END - DUPONT_L                     # -23.8

# =============================================================================
# screen window (active area + margin, 30 deg chamfer outward)
# =============================================================================
WIN_MARGIN = 0.4
WIN_DRAFT = 30.0
WIN_R = 1.0
WIN_IN = (AA[0] - WIN_MARGIN, AA[1] + WIN_MARGIN, AA[2] - WIN_MARGIN, AA[3] + WIN_MARGIN)
_g = T_FRONT * math.tan(math.radians(WIN_DRAFT))
WIN_OUT = (WIN_IN[0] - _g, WIN_IN[1] + _g, WIN_IN[2] - _g, WIN_IN[3] + _g)

# =============================================================================
# board retention
# =============================================================================
FENCE_T = 1.2
FENCE_CLR = 0.2
FENCE_Z_END = Z_PCB_BACK - 0.2
PEG_D = 4.2
PEG_GAP = 0.10                     # peg shoulder to standoff end
PEG_TIP_D = 1.4                    # unused while PEG_TIP_L = 0
PEG_TIP_L = 0.0                    # tips removed: they cannot find the M2 bore blind

# =============================================================================
# 18650 cell (3.7 V 2000 mAh 7.4 Wh), lying along X in the bottom strip
# =============================================================================
BAT_D = 19.0                       # 18.4 wrapped + black tape
BAT_L = 68.5                       # 65 cell + tabs/solder on both ends
BAT_RIB_GAP = 0.3                  # rib to cell: max cell incl. tape/wire = BAT_D + 0.3
BAT_CAV_D = 20.3
BAT_CAV_L = 71.0
BAT_X0 = -44.3
BAT_Y = -YI + BAT_CAV_D / 2 + 0.2
BAT_Z = Z_BIN + BAT_CAV_D / 2 + 0.05
BAT_X1 = BAT_X0 + BAT_CAV_L
SADDLE_X = (-30.0, 12.0)
SADDLE_T = 2.0
SADDLE_TOP = BAT_Z - 1.2
BAT_STOP_T = 1.2
BAT_WIRE_SLOT = 5.0
BAT_RIB_X = (-10.0, 8.0, 22.0)    # front-shell ribs that hold the cell down
BAT_RIB_T = 1.2

# =============================================================================
# TP4056 USB-C charger (charge-only port), bottom-left, components toward the cell
# =============================================================================
TP = dict(l=28.0, w=17.3, t=1.2, usb_w=8.94, usb_h=3.26, usb_l=7.35, usb_over=0.8)   # PCB 1.0-1.6 thick in the wild
TP_X0 = -XI + 0.20                                  # PCB edge 0.2 off the wall; receptacle reaches into the wall hole
TP_Y1 = -9.9                                          # PCB top edge
TP_Y0 = TP_Y1 - TP["w"]
TP_Z_FRONT = -3.17                                    # bare PCB face (toward the screen); keeps the port clear of the edge round
TP_USB_Z = TP_Z_FRONT - TP["t"] - TP["usb_h"] / 2     # receptacle centre
TP_RAIL_T = 1.2

# =============================================================================
# ports on the left wall
# =============================================================================
USB_HOLE = (9.8, 4.1)              # plug shell 8.4 x 2.6 + clearance (stadium)
TP_USB_HOLE = (9.8, 4.5)           # taller: TP4056 PCB thickness varies 1.0-1.6
USB_RECESS = (13.0, 7.2, 2.0)      # w, h, depth: 0.6 web, lets the overmold reach
PIN_HOLE_D = 3.6                   # SIGN pin (presses the BOOT key, GPIO0)
RST_HOLE_D = 1.3
PIN = dict(shaft_d=3.2, proud=1.2, flange_d=5.4, flange_t=0.84, nub_d=1.6, nub_gap=0.32)
Z_PIN = Z_SW - 0.3                 # a hair below the PCB edge

# =============================================================================
# big latching power switch (12 x 12 self-locking, blue cap) on the top face
# =============================================================================
SW = dict(body=12.0, body_h=12.0, cap_d=12.0, hole_d=12.6, x=36.0)   # MEASURE yours: 12x12 housing 9-12 mm tall
SW_Z = (Z_SPLIT - LIP_H - 0.3 + (-D + R_BACK + 0.3)) / 2           # centred in the flat
SW_CRADLE_T = 1.2
SW_CRADLE_CLR = 0.15

# =============================================================================
# INMP441 mic on the top face, buzzer on the right end
# =============================================================================
MIC = dict(d=14.2, t=1.0, x=16.0, hole_d=1.5, csk_d=3.0, csk=0.6)
MIC_Z = SW_Z
BUZ = dict(d=12.0, h=9.5, y=-18.0, hole_d=1.6, pitch=3.0, bore=12.4, thin_to=1.3)
BUZ_Z = SW_Z

# =============================================================================
# MAX30102 thumb pad (front face, right of the screen)
# =============================================================================
MAX = dict(l=20.3, w=15.3, t=1.6, ic_l=5.6, ic_w=3.3, ic_h=1.55, comp_h=1.2,
           x=29.0, y=11.0, win=(10.0, 8.0), win_r=2.0, win_chamfer=1.0)

# =============================================================================
# lens hood (back shell) - OV5640 looks through a 33 deg cone
# =============================================================================
HOOD_TOP_Z = -18.5
HOOD_BORE_R = 5.0
HOOD_T = 1.2
HOOD_DRAFT = 33.0
LENS_RING_R = (16.0, 17.0)         # decorative bezel groove on the lens face
LENS_RING_D = 0.6

# =============================================================================
# lettering
# =============================================================================
BRAND = "RIPAR WALLET"
FONT = "Arial Black"
TXT_DEPTH = 0.6
TXT_TOP_H = 4.2
TXT_BOT_H = 5.5
TXT_BACK = "RIPAR"
TXT_BACK_H = 6.0

FIT_TEST_X = -24.0                  # fit-test coupons keep X < this (left end)
SEAM_CHAMFER = 0.4                 # shadow line at the parting line hides print mismatch
PRY = dict(x=38.0, w=8.0, h=1.8, d=1.2)   # front shell only   # fingernail notch across the seam (bottom face)

# colours for renders (r, g, b 0..1)
C_SHELL_F = (0.13, 0.13, 0.15)
C_SHELL_B = (0.86, 0.86, 0.84)
C_PCB = (0.05, 0.25, 0.55)


def summary():
    rows = [
        ("outer size", "%.0f x %.0f x %.0f mm" % (W, H, D)),
        ("board offset", "OX %.2f  OY %.2f  OZ %.2f" % (OX, OY, OZ)),
        ("PCB (device)", "X %.2f..%.2f  Y %.2f..%.2f" % PCB),
        ("active area", "X %.2f..%.2f  Y %.2f..%.2f" % AA),
        ("window inner", "X %.2f..%.2f  Y %.2f..%.2f" % WIN_IN),
        ("standoffs", " ".join("(%.2f, %.2f)" % tuple(s) for s in STANDOFFS)),
        ("lens", "(%.2f, %.2f)  top Z %.2f" % (LENS_XY[0], LENS_XY[1], Z_LENS_TOP)),
        ("USB-C (board)", "Y %.2f  Z %.2f" % (USB_C[1], USB_C[2])),
        ("BOOT / RST", "Y %.2f / %.2f  Z %.2f  plunger X %.2f" % (Y_BOOT, Y_RST, Z_SW, X_PLUNGER)),
        ("battery", "X %.1f..%.1f  Y %.2f  Z %.2f" % (BAT_X0, BAT_X1, BAT_Y, BAT_Z)),
        ("TP4056", "X %.2f..%.2f  Y %.2f..%.2f  USB Z %.2f" % (TP_X0, TP_X0 + TP["l"], TP_Y0, TP_Y1, TP_USB_Z)),
        ("switch", "X %.1f  Z %.2f" % (SW["x"], SW_Z)),
    ]
    for k, v in rows:
        print("%-14s %s" % (k, v))


if __name__ == "__main__":
    summary()
