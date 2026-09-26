"""Import the official Waveshare ESP32-S3-LCD-2 STEP once and save it as a single
multibody part (board frame, mm).  Used to MEASURE the board: the per-component boxes
were dumped from it once (vendor/board_boxes.json) and transcribed into design.BOARD.
The assembly uses the lightweight Board_PCB / Board_LCD parts from parts_board.py."""
import os
import time

import pythoncom
from win32com.client import VARIANT

from swlib import V, app, cleanup_untitled

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STEP = os.path.join(ROOT, "cad", "vendor", "ESP32-S3-LCD-2-20250122.stp")
OUT = os.path.join(ROOT, "model", "parts", "Board_ESP32S3_LCD2.SLDPRT")


def main():
    if os.path.exists(OUT):
        print("exists:", OUT)
        return OUT
    sw = app()
    cleanup_untitled()
    t = time.time()
    imp = sw.GetImportFileData(STEP)
    err = VARIANT(pythoncom.VT_BYREF | pythoncom.VT_I4, 0)
    doc = sw.LoadFile4(STEP, "r", imp, err)
    if doc is None:
        raise RuntimeError("STEP import failed err=%s" % err.value)
    title = V(doc.GetTitle)
    print("imported %s (type %s) in %.0fs" % (title, V(doc.GetType), time.time() - t), flush=True)
    sw.SetUserPreferenceIntegerValue(201, 1)          # save assembly as part: all components
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    e = doc.SaveAs3(OUT, 0, 1)
    print("save-as-part err", e, "exists", os.path.exists(OUT), flush=True)
    sw.CloseDoc(title)
    for d in list(sw.GetDocuments or []):              # release the in-memory component docs
        if not V(d.GetPathName):
            sw.CloseDoc(V(d.GetTitle))
    e1 = VARIANT(pythoncom.VT_BYREF | pythoncom.VT_I4, 0)
    w1 = VARIANT(pythoncom.VT_BYREF | pythoncom.VT_I4, 0)
    part = sw.OpenDoc6(OUT, 1, 1, "", e1, w1)
    bodies = part.GetBodies2(0, True) or []
    lo = [1e9] * 3
    hi = [-1e9] * 3
    for b in bodies:
        bx = V(b.GetBodyBox)
        lo = [min(lo[i], bx[i] * 1000) for i in range(3)]
        hi = [max(hi[i], bx[i + 3] * 1000) for i in range(3)]
    print("board part: %d bodies, box %s .. %s" % (len(bodies), [round(v, 2) for v in lo],
                                                   [round(v, 2) for v in hi]), flush=True)
    sw.CloseDoc(V(part.GetTitle))
    return OUT


if __name__ == "__main__":
    main()
