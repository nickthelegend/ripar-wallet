"""
Lightweight model of the Waveshare ESP32-S3-LCD-2, in the BOARD frame, built
from the boxes measured on the official STEP (vendor/board_boxes.json).
Two parts so they render in two colours:  Board_PCB (PCB + parts) and Board_LCD.
Placed in the assembly with design.BOARD_M.
"""
import design as D
from parts_shell import B

BD = D.BOARD


def _box(s, xr, yr):
    s.rrect((xr[0] + xr[1]) / 2, (yr[0] + yr[1]) / 2, abs(xr[1] - xr[0]), abs(yr[1] - yr[0]), 0)


def board_pcb():
    b = B("Board_PCB")
    z0, z1 = BD["pcb_z"]
    b.boss("z", z1, z0, lambda s: s.rrect(0, (BD["pcb_y"][0] + BD["pcb_y"][1]) / 2,
                                           BD["pcb_x"][1] - BD["pcb_x"][0], BD["pcb_y"][1] - BD["pcb_y"][0], 3.0),
           "PCB")
    zb = z0                                                   # back face of the PCB (-3.6)
    # header plastic + pins (both 14-pin rows)
    b.boss("z", zb, BD["header_body_z"][0],
           lambda s: [_box(s, (hx - 1.27, hx + 1.27), BD["header_y"]) for hx in BD["header_x"]], "Header_Body")
    b.boss("z", BD["header_body_z"][0], BD["header_z"][0],
           lambda s: [_box(s, (hx - 0.32, hx + 0.32), (BD["header_y"][0] + 0.9, BD["header_y"][1] - 0.9))
                      for hx in BD["header_x"]], "Header_Pins")
    # M2 SMT nuts with their thread bore
    b.boss("z", zb, BD["standoff_z"][0],
           lambda s: [s.circle(c, BD["standoff_d"] / 2) for c in BD["standoff_xy"]], "Standoffs")
    b.cut("z", BD["standoff_z"][0], zb + 0.5, lambda s: [s.circle(c, 0.8) for c in BD["standoff_xy"]], "M2_Bore")
    b.boss("z", zb, BD["usb_z"][0], lambda s: _box(s, BD["usb_x"], BD["usb_y"]), "USB_C")
    b.boss("z", zb, BD["sw_z"][0], lambda s: [_box(s, (x - 2.28, x + 2.28), (-25.53, -21.88))
                                             for x in (BD["rst_x"], BD["boot_x"])], "Keys")
    b.boss("z", zb, BD["fpc_z"][0], lambda s: _box(s, BD["fpc_x"], BD["fpc_y"]), "Cam_FPC")
    b.boss("z", zb, BD["bat_z"][0], lambda s: _box(s, BD["bat_x"], BD["bat_y"]), "Bat_Conn")
    b.boss("z", zb, BD["tf_z"][0], lambda s: _box(s, BD["tf_x"], BD["tf_y"]), "TF_Slot")
    b.boss("z", zb, -5.4, lambda s: _box(s, (7.0, 12.12), (8.0, 22.0)), "ESP32_S3")
    b.p.color((0.04, 0.22, 0.55))
    return b.p


def board_lcd():
    b = B("Board_LCD")
    b.boss("z", BD["lcd_z"][1], BD["pcb_z"][1],
           lambda s: _box(s, (-17.5, 17.5), (BD["lcd_y"][0], 22.4)), "LCD")
    b.p.color((0.02, 0.02, 0.03), spec=0.9, shine=0.9)
    return b.p


BUILDERS = {"Board_PCB": board_pcb, "Board_LCD": board_lcd}
