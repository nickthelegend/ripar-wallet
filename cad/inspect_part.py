"""Large review renders of a part:  python inspect_part.py Front_Shell [view ...]
Views: iso, iso_back, front, back, left, right, top, bottom (2x2 grid per 4 views)."""
import os
import sys

import pythoncom
from PIL import Image, ImageDraw
from win32com.client import VARIANT

from swlib import V, _crop, activate, app, arr_d, hide_refs, snapshot

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PARTS = os.path.join(ROOT, "model", "parts")
REN = os.path.join(ROOT, "model", "renders")
NAMED = {"iso": ("*Isometric", 7), "front": ("*Front", 1), "back": ("*Back", 2), "left": ("*Left", 3),
         "right": ("*Right", 4), "top": ("*Top", 5), "bottom": ("*Bottom", 6), "trimetric": ("*Trimetric", 8)}


def view_iso_back(doc):
    """isometric from behind (lens side / inside of the front shell)"""
    doc.ShowNamedView2("*Isometric", 7)
    doc.ViewRotateplusy() if False else None
    v = doc.ActiveView
    for _ in range(2):          # 2 x 90 deg about screen Y
        doc.ShowNamedView2("", -1)
    mv = V(v.Orientation3)
    a = list(mv.ArrayData)
    # rotate 180 deg about the model Y axis: flip x and z columns
    for k in (0, 2, 3, 5, 6, 8):
        a[k] = -a[k]
    mu = V(app().GetMathUtility)
    v.Orientation3 = mu.CreateTransform(arr_d(a))
    doc.ViewZoomtofit2()


def render(doc, path, view, H=520):
    hide_refs(doc)
    if view == "iso_back":
        view_iso_back(doc)
        snapshot(doc, path, view=None, zoom=True)
    else:
        name, vid = NAMED[view]
        snapshot(doc, path, view=name, view_id=vid)
    im = _crop(Image.open(path).convert("RGB"))
    s = H / im.height
    if im.width * s > 900:
        s = 900 / im.width
    im = im.resize((int(im.width * s), int(im.height * s)))
    return im


def grid(ims, labels, out):
    cw = max(i.width for i in ims)
    ch = max(i.height for i in ims) + 22
    cols = 2
    rows = (len(ims) + 1) // 2
    g = Image.new("RGB", (cw * cols, ch * rows), (255, 255, 255))
    d = ImageDraw.Draw(g)
    for k, (im, lab) in enumerate(zip(ims, labels)):
        x, y = (k % cols) * cw, (k // cols) * ch
        g.paste(im, (x + (cw - im.width) // 2, y + 22))
        d.text((x + 6, y + 4), lab, fill=(0, 0, 0))
    g.save(out)
    return out


def main():
    name = sys.argv[1]
    views = sys.argv[2:] or ["iso", "iso_back", "back", "left"]
    sw = app()
    path = os.path.join(PARTS, name + ".SLDPRT")
    e = VARIANT(pythoncom.VT_BYREF | pythoncom.VT_I4, 0)
    w = VARIANT(pythoncom.VT_BYREF | pythoncom.VT_I4, 0)
    doc = sw.OpenDoc6(path, 1, 1, "", e, w)
    activate(doc)
    old = list(V(doc.MaterialPropertyValues))
    doc.MaterialPropertyValues = arr_d([0.78, 0.80, 0.84, 1, 1, 0.4, 0.3, 0, 0])
    tmp = os.path.join(REN, "_tmp.png")
    ims = [render(doc, tmp, v) for v in views]
    out = os.path.join(REN, "inspect_%s_%s.png" % (name, "_".join(views)))
    grid(ims, [name + " - " + v for v in views], out)
    doc.MaterialPropertyValues = arr_d(old)
    sw.CloseDoc(V(doc.GetTitle))
    os.remove(tmp)
    print(out)


if __name__ == "__main__":
    main()
