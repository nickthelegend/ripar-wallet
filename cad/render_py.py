"""
Offline renders of the Ripar Wallet assembly (numpy z-buffer rasteriser; no GPU,
no SolidWorks window needed).  Geometry = STL exports of the SolidWorks parts,
placed with the same transforms as model/RiparWallet.SLDASM.

    python render_py.py            -> model/renders/{hero_front,hero_back,inside,exploded,sheet}.png
"""
import os
import sys

import numpy as np
import pythoncom
import trimesh
from PIL import Image, ImageDraw, ImageFilter, ImageFont
from win32com.client import VARIANT

import design as D
from assembly import COMPONENTS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PARTS = os.path.join(ROOT, "model", "parts")
CACHE = os.path.join(ROOT, "model", "_stl_cache")
REN = os.path.join(ROOT, "model", "renders")

COLORS = {
    "Front_Shell": (0.16, 0.16, 0.18), "Back_Shell": (0.90, 0.89, 0.86), "Sign_Pin": (0.15, 0.40, 0.95),
    "Board_PCB": (0.08, 0.30, 0.62), "Board_LCD": (0.03, 0.03, 0.05), "Dupont_Harness": (0.10, 0.10, 0.10),
    "Camera_OV5640": (0.10, 0.10, 0.10), "Cell_18650": (0.15, 0.55, 0.35), "TP4056_USBC": (0.10, 0.35, 0.75),
    "MAX30102": (0.50, 0.20, 0.70), "INMP441": (0.45, 0.20, 0.60), "Buzzer_12mm": (0.08, 0.08, 0.08),
    "Latch_Switch_12mm": (0.10, 0.35, 0.95),
}


def export_stls(force=False):
    """SolidWorks -> raw STL (part frame) for every assembly component."""
    os.makedirs(CACHE, exist_ok=True)
    todo = []
    for name, _ in COMPONENTS:
        src = os.path.join(PARTS, name + ".SLDPRT")
        dst = os.path.join(CACHE, name + ".stl")
        if force or not os.path.exists(dst) or os.path.getmtime(dst) < os.path.getmtime(src):
            todo.append((name, src, dst))
    if not todo:
        return
    from swlib import V, activate, app
    sw = app()
    sw.SetUserPreferenceToggle(69, True)
    sw.SetUserPreferenceToggle(71, True)         # swSTLDontTranslateToPositive: keep model coordinates
    sw.SetUserPreferenceIntegerValue(211, 0)
    sw.SetUserPreferenceIntegerValue(78, 2)
    for name, src, dst in todo:
        e = VARIANT(pythoncom.VT_BYREF | pythoncom.VT_I4, 0)
        w = VARIANT(pythoncom.VT_BYREF | pythoncom.VT_I4, 0)
        doc = sw.GetOpenDocumentByName(src) or sw.OpenDoc6(src, 1, 1, "", e, w)
        activate(doc)
        if os.path.exists(dst):
            os.remove(dst)
        doc.SaveAs3(dst, 0, 1)
        sw.CloseDoc(V(doc.GetTitle))
        print("  stl", name, flush=True)


def load_scene():
    """STLs back into model coordinates.  Older SolidWorks exports were shifted into
    positive space, so each mesh is re-anchored on the part's own bounding box that
    build_parts.py recorded in manifest.json (exact for these prismatic parts)."""
    import json
    man = json.load(open(os.path.join(PARTS, "manifest.json")))
    scene = {}
    for name, M in COMPONENTS:
        m = trimesh.load(os.path.join(CACHE, name + ".stl"))
        if name in man:
            shift = np.array(man[name]["bbox_min"], float) - m.bounds[0]
            if np.abs(shift).max() > 0.3:
                m.apply_translation(shift)
        m.apply_transform(M)
        scene[name] = m
    return scene


# -----------------------------------------------------------------------------
# rasteriser
# -----------------------------------------------------------------------------
def camera(az, el):
    """orthographic camera: az about +Y (0 = looking at the screen face), el up/down (deg)"""
    a, e = np.radians(az), np.radians(el)
    fwd = -np.array([np.sin(a) * np.cos(e), np.sin(e), np.cos(a) * np.cos(e)])   # view direction
    up0 = np.array([0.0, 1.0, 0.0])
    right = np.cross(fwd, up0)
    right /= np.linalg.norm(right)
    up = np.cross(right, fwd)
    return right, up, fwd


def render(meshes, az, el, W=1500, H=1050, ss=2, pad=0.08):
    right, up, fwd = camera(az, el)
    light = -fwd * 0.55 + up * 0.55 + right * -0.35
    light /= np.linalg.norm(light)
    allv = np.vstack([m.vertices for m, _, _ in meshes])
    P = np.c_[allv @ right, allv @ up]
    lo, hi = P.min(0), P.max(0)
    Ws, Hs = W * ss, H * ss
    scale = min(Ws * (1 - 2 * pad) / (hi[0] - lo[0]), Hs * (1 - 2 * pad) / (hi[1] - lo[1]))
    cx, cy = (lo + hi) / 2
    zbuf = np.full((Hs, Ws), np.inf)
    img = np.zeros((Hs, Ws, 3))
    obj = np.full((Hs, Ws), -1, int)
    for oi, (m, col, alpha) in enumerate(meshes):
        v = m.vertices
        sx = (v @ right - cx) * scale + Ws / 2
        sy = Hs / 2 - (v @ up - cy) * scale
        sz = v @ fwd
        n = m.face_normals
        lam = np.clip(n @ light, 0, 1)
        spec = np.clip(n @ (light - fwd) / np.linalg.norm(light - fwd), 0, 1) ** 24
        base = np.array(col)
        shade = np.clip(base[None, :] * (0.38 + 0.62 * lam[:, None]) + 0.18 * spec[:, None], 0, 1)
        for fi, f in enumerate(m.faces):
            if n[fi] @ fwd > 0.02:          # back-face cull (closed meshes)
                continue
            x, y, z = sx[f], sy[f], sz[f]
            x0, x1 = int(max(np.floor(x.min()), 0)), int(min(np.ceil(x.max()), Ws - 1))
            y0, y1 = int(max(np.floor(y.min()), 0)), int(min(np.ceil(y.max()), Hs - 1))
            if x1 < x0 or y1 < y0:
                continue
            xs, ys = np.meshgrid(np.arange(x0, x1 + 1) + 0.5, np.arange(y0, y1 + 1) + 0.5)
            d = (y[1] - y[2]) * (x[0] - x[2]) + (x[2] - x[1]) * (y[0] - y[2])
            if abs(d) < 1e-12:
                continue
            w0 = ((y[1] - y[2]) * (xs - x[2]) + (x[2] - x[1]) * (ys - y[2])) / d
            w1 = ((y[2] - y[0]) * (xs - x[2]) + (x[0] - x[2]) * (ys - y[2])) / d
            w2 = 1 - w0 - w1
            inside = (w0 >= -1e-6) & (w1 >= -1e-6) & (w2 >= -1e-6)
            if not inside.any():
                continue
            zz = w0 * z[0] + w1 * z[1] + w2 * z[2]
            sub = zbuf[y0:y1 + 1, x0:x1 + 1]
            upd = inside & (zz < sub)
            sub[upd] = zz[upd]
            img[y0:y1 + 1, x0:x1 + 1][upd] = shade[fi]
            obj[y0:y1 + 1, x0:x1 + 1][upd] = oi
    # background
    bg = np.linspace(1.0, 0.86, Hs)[:, None, None] * np.array([1.0, 1.0, 1.0])[None, None, :]
    mask = np.isfinite(zbuf)
    out = np.where(mask[..., None], img, np.broadcast_to(bg, img.shape))
    # outlines: object / depth discontinuities
    zf = np.where(mask, zbuf, zbuf[mask].max() + 50 if mask.any() else 0)
    dz = np.zeros_like(zf)
    dz[:, 1:] = np.maximum(dz[:, 1:], np.abs(np.diff(zf, axis=1)))
    dz[1:, :] = np.maximum(dz[1:, :], np.abs(np.diff(zf, axis=0)))
    do = np.zeros_like(obj, bool)
    do[:, 1:] |= obj[:, 1:] != obj[:, :-1]
    do[1:, :] |= obj[1:, :] != obj[:-1, :]
    edge = (dz > 0.6) | do
    out[edge] = out[edge] * 0.25
    im = Image.fromarray((np.clip(out, 0, 1) * 255).astype(np.uint8))
    return im.resize((W, H), Image.LANCZOS)


def feature_edges_img(im):
    return im


def main():
    os.makedirs(REN, exist_ok=True)
    if "--no-sw" not in sys.argv:
        export_stls("--force" in sys.argv)
    scene = load_scene()

    def pick(names=None, offs=None, skip=()):
        out = []
        for name, m in scene.items():
            if name in skip or (names and name not in names):
                continue
            mm = m.copy()
            if offs and name in offs:
                mm.apply_translation(offs[name])
            out.append((mm, COLORS.get(name, (0.6, 0.6, 0.6)), 1.0))
        return out

    shots = []
    print("render hero_front", flush=True)
    shots.append(("SCREEN SIDE  -  thumb pulse pad right, SIGN pin + USB-C on the left end", "hero_front.png",
                  render(pick(), az=-32, el=24)))
    print("render hero_back", flush=True)
    shots.append(("LENS SIDE  -  OV5640 looks through the lens bezel (QR scanner)", "hero_back.png",
                  render(pick(), az=148, el=22)))
    print("render inside", flush=True)
    shots.append(("INSIDE  -  front shell removed", "inside.png",
                  render(pick(skip=("Front_Shell", "Sign_Pin")), az=-28, el=30)))
    print("render exploded", flush=True)
    offs = {"Front_Shell": (0, 0, 46), "Sign_Pin": (-10, 0, 46), "Board_LCD": (0, 0, 24), "Board_PCB": (0, 0, 24),
            "Dupont_Harness": (0, 0, 24), "Camera_OV5640": (0, 0, 24), "TP4056_USBC": (0, 0, 34),
            "MAX30102": (0, 0, 34), "Back_Shell": (0, 0, -24), "INMP441": (0, 0, -24),
            "Buzzer_12mm": (0, 0, -24), "Latch_Switch_12mm": (0, 0, -24), "Cell_18650": (0, 0, -6)}
    shots.append(("EXPLODED  -  snap-fit shells, everything drops into place (no screws)", "exploded.png",
                  render(pick(offs=offs), az=-38, el=20, H=1250)))
    for lab, fn, im in shots:
        im.save(os.path.join(REN, fn))
    W = max(im.width for _, _, im in shots)
    Hh = max(im.height for _, _, im in shots) + 40
    sheet = Image.new("RGB", (W * 2, Hh * 2), "white")
    d = ImageDraw.Draw(sheet)
    try:
        font = ImageFont.truetype("arialbd.ttf", 22)
    except Exception:
        font = None
    for k, (lab, fn, im) in enumerate(shots):
        x, y = (k % 2) * W, (k // 2) * Hh
        sheet.paste(im, (x + (W - im.width) // 2, y + 40))
        d.text((x + 16, y + 10), "RIPAR WALLET v1   " + lab, fill=(20, 20, 20), font=font)
    sheet.save(os.path.join(REN, "sheet.png"))
    print(os.path.join(REN, "sheet.png"))


if __name__ == "__main__":
    main()
