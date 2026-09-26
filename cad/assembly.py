"""Top-level assembly model/RiparWallet.SLDASM (everything fixed in its designed place)."""
import os
import sys

import numpy as np
import pythoncom
from win32com.client import VARIANT

import design as D
from swlib import CREATED, MM, NOTHING, TEMPLATE_ASM, V, activate, app, arr_d, cleanup_untitled

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PARTS = os.path.join(ROOT, "model", "parts")
ASM_PATH = os.path.join(ROOT, "model", "RiparWallet.SLDASM")

I4 = np.eye(4)
COMPONENTS = [
    ("Front_Shell", I4), ("Back_Shell", I4), ("Sign_Pin", I4),
    ("Board_PCB", D.BOARD_M), ("Board_LCD", D.BOARD_M),
    ("Dupont_Harness", I4), ("Camera_OV5640", I4), ("Cell_18650", I4), ("TP4056_USBC", I4),
    ("MAX30102", I4), ("INMP441", I4), ("Buzzer_12mm", I4), ("Latch_Switch_12mm", I4),
]


def sw_xf(M):
    """4x4 (column-vector, mm) -> SolidWorks MathTransform array (row-vector, m)."""
    R, t = M[:3, :3], M[:3, 3] * MM
    return [R[0, 0], R[1, 0], R[2, 0], R[0, 1], R[1, 1], R[2, 1], R[0, 2], R[1, 2], R[2, 2],
            t[0], t[1], t[2], 1.0, 0.0, 0.0, 0.0]


def from_sw(a):
    a = list(a)
    M = np.eye(4)
    M[:3, 0], M[:3, 1], M[:3, 2] = a[0:3], a[3:6], a[6:9]
    M[:3, 3] = np.array(a[9:12]) / MM
    return M


def open_doc(sw, path):
    e = VARIANT(pythoncom.VT_BYREF | pythoncom.VT_I4, 0)
    w = VARIANT(pythoncom.VT_BYREF | pythoncom.VT_I4, 0)
    typ = 2 if path.upper().endswith(".SLDASM") else 1
    d = sw.OpenDoc6(path, typ, 1, "", e, w)
    if d is None:
        raise RuntimeError("cannot open %s (err %s)" % (path, e.value))
    return d


def build():
    sw = app()
    cleanup_untitled()
    other = sw.GetOpenDocumentByName(ASM_PATH)
    if other is not None:
        sw.CloseDoc(V(other.GetTitle))
    doc = sw.NewDocument(TEMPLATE_ASM, 0, 0, 0)
    title = V(doc.GetTitle)
    CREATED.append(title)
    activate(doc)
    mu = V(sw.GetMathUtility)
    try:
        mu._FlagAsMethod("CreateTransform", "CreatePoint", "CreateVector")
    except Exception:
        pass
    for name, M in COMPONENTS:
        path = os.path.join(PARTS, name + ".SLDPRT")
        if sw.GetOpenDocumentByName(path) is None:
            open_doc(sw, path)
            activate(doc)
        c = doc.AddComponent5(path, 0, "", False, "", 0, 0, 0)
        if c is None:
            raise RuntimeError("AddComponent5 failed: " + name)
        if V(c.IsFixed):
            doc.ClearSelection2(True)
            c.Select4(False, NOTHING, False)
            V(doc.UnfixComponent)
        xf = mu.CreateTransform(arr_d(sw_xf(M)))
        c.SetTransformAndSolve2(xf)
        got = from_sw(V(c.Transform2).ArrayData)
        if np.abs(got - M).max() > 1e-3:
            raise RuntimeError("placement mismatch for %s" % name)
        doc.ClearSelection2(True)
        c.Select4(False, NOTHING, False)
        V(doc.FixComponent)
        doc.ClearSelection2(True)
        print("  placed", name, flush=True)
    doc.ForceRebuild3(False)
    if os.path.exists(ASM_PATH):
        os.remove(ASM_PATH)
    err = doc.SaveAs3(ASM_PATH, 0, 1)
    if err != 0:
        raise RuntimeError("assembly save failed err=%s" % err)
    CREATED.remove(title)
    print("saved", ASM_PATH, flush=True)
    return doc


def attach():
    """Open (or find) the saved assembly and return its document."""
    sw = app()
    d = sw.GetOpenDocumentByName(ASM_PATH)
    if d is None:
        d = open_doc(sw, ASM_PATH)
    activate(d)
    return d


if __name__ == "__main__":
    build()
