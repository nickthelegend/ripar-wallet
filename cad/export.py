"""
Export printable parts for Bambu Lab P1S:
  print/stl/*.stl    binary STL in mm, already ORIENTED for printing (flat face on the bed)
  print/step/*.step  STEP AP214 of every printable part and of the full assembly
  print/print_list.csv
"""
import csv
import json
import os

import numpy as np
import pythoncom
import trimesh
from win32com.client import VARIANT

from swlib import V, activate, app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PARTS = os.path.join(ROOT, "model", "parts")
OUT_STL = os.path.join(ROOT, "print", "stl")
OUT_STEP = os.path.join(ROOT, "print", "step")
ASM = os.path.join(ROOT, "model", "RiparWallet.SLDASM")


def Rx(deg):
    a = np.radians(deg)
    return np.array([[1, 0, 0, 0], [0, np.cos(a), -np.sin(a), 0], [0, np.sin(a), np.cos(a), 0], [0, 0, 0, 1]])


def Ry(deg):
    a = np.radians(deg)
    return np.array([[np.cos(a), 0, np.sin(a), 0], [0, 1, 0, 0], [-np.sin(a), 0, np.cos(a), 0], [0, 0, 0, 1]])


# part -> (qty, material, orientation transform, notes)
PRINTABLE = {
    "Front_Shell": (1, "PLA or PETG (black / dark)", Rx(180),
                    "screen face DOWN on the textured PEI plate; no supports; 0.16 mm layers, 3 walls, 15% gyroid"),
    "Back_Shell": (1, "PLA or PETG (black / dark: a light hood flares the camera)", np.eye(4),
                   "lens face DOWN; no supports (switch opening is a short bridge, lens cone is 33 deg); 0.16 mm layers, 3 walls"),
    "Sign_Pin": (1, "PLA", Ry(-90), "stand it on its flat outer end; 0.12 mm layers, 100% infill; print 2 spares"),
    "FitTest_Front": (1, "same as the shell", Rx(180), "OPTIONAL test (both coupons ~40 min): board fit, USB-C/SIGN/RST ports, lip"),
    "FitTest_Back": (1, "same as the shell", np.eye(4), "OPTIONAL test: snaps onto FitTest_Front; checks the bead click"),
}


def open_doc(sw, path):
    e = VARIANT(pythoncom.VT_BYREF | pythoncom.VT_I4, 0)
    w = VARIANT(pythoncom.VT_BYREF | pythoncom.VT_I4, 0)
    typ = 2 if path.upper().endswith(".SLDASM") else 1
    return sw.OpenDoc6(path, typ, 1, "", e, w)


def main():
    os.makedirs(OUT_STL, exist_ok=True)
    os.makedirs(OUT_STEP, exist_ok=True)
    sw = app()
    sw.SetUserPreferenceToggle(69, True)          # swSTLBinaryFormat
    sw.SetUserPreferenceToggle(71, True)          # swSTLDontTranslateToPositive: keep model coordinates
    sw.SetUserPreferenceIntegerValue(211, 0)      # swExportStlUnits = mm
    sw.SetUserPreferenceIntegerValue(78, 2)       # swSTLQuality = fine
    sw.SetUserPreferenceIntegerValue(75, 214)     # swStepAP = AP214
    man = json.load(open(os.path.join(PARTS, "manifest.json")))
    rows = []
    for name, (qty, mat, M, note) in PRINTABLE.items():
        src = os.path.join(PARTS, name + ".SLDPRT")
        doc = open_doc(sw, src)
        activate(doc)
        raw = os.path.join(OUT_STL, name + "_raw.stl")
        for f in (raw, os.path.join(OUT_STEP, name + ".step")):
            if os.path.exists(f):
                os.remove(f)
        e1 = doc.SaveAs3(raw, 0, 1)
        e2 = doc.SaveAs3(os.path.join(OUT_STEP, name + ".step"), 0, 1)
        sw.CloseDoc(V(doc.GetTitle))
        m = trimesh.load(raw)
        m.apply_transform(M)
        m.apply_translation(-m.bounds[0] * np.array([1, 1, 1]) + np.array([0, 0, 0]))
        m.apply_translation([-(m.bounds[0][0] + m.bounds[1][0]) / 2, -(m.bounds[0][1] + m.bounds[1][1]) / 2, 0])
        dst = os.path.join(OUT_STL, name + ".stl")
        m.export(dst)
        os.remove(raw)
        ext = m.bounds[1] - m.bounds[0]
        g = man.get(name, {}).get("mass_g_pla", 0)
        rows.append(dict(part=name, qty=qty, material=mat, size_mm="%.1f x %.1f x %.1f" % tuple(ext),
                         solid_mass_g=g, watertight=m.is_watertight, triangles=len(m.faces), notes=note,
                         stl="stl/%s.stl" % name, step="step/%s.step" % name))
        print("%-12s x%d  %s  watertight=%s  tris=%d  step_err=%s stl_err=%s" %
              (name, qty, rows[-1]["size_mm"], m.is_watertight, len(m.faces), e2, e1), flush=True)
    # full assembly STEP (for Fusion / FreeCAD / sharing)
    d = sw.GetOpenDocumentByName(ASM) or open_doc(sw, ASM)
    activate(d)
    dst = os.path.join(OUT_STEP, "RiparWallet_assembly.step")
    if os.path.exists(dst):
        os.remove(dst)
    print("assembly step err", d.SaveAs3(dst, 0, 1), flush=True)
    with open(os.path.join(ROOT, "print", "print_list.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    main()
