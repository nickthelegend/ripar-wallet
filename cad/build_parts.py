"""Build printable parts:  python build_parts.py [Front_Shell Back_Shell Sign_Pin ...]"""
import json
import os
import sys
import time

from swlib import cleanup_untitled, multiview, app, V
import parts_shell as PS
import parts_dummy as PD
import parts_board as PB

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PARTS = os.path.join(ROOT, "model", "parts")
REN = os.path.join(ROOT, "model", "renders")
PLA = 1.24e-3   # g/mm3


def build(name):
    t = time.time()
    p = {**PS.BUILDERS, **PD.BUILDERS, **PB.BUILDERS}[name]()
    lo, hi = p.bbox()
    vol = p.volume_mm3()
    nb = len(p.bodies())
    path = p.save(os.path.join(PARTS, name + ".SLDPRT"))
    if name in PS.BUILDERS and "--no-views" not in sys.argv:
        multiview(p.doc, os.path.join(REN, "part_%s.png" % name),
                  views=("*Isometric", "*Front", "*Back", "*Top", "*Bottom", "*Left", "*Right"), height=360)
    info = dict(bbox_min=[round(v, 2) for v in lo], bbox_max=[round(v, 2) for v in hi],
                volume_mm3=round(vol, 1), mass_g_pla=round(vol * PLA, 1), bodies=nb,
                seconds=round(time.time() - t, 1))
    print("%-12s %s" % (name, info), flush=True)
    p.close()
    return info


def main():
    os.makedirs(PARTS, exist_ok=True)
    os.makedirs(REN, exist_ok=True)
    app()
    cleanup_untitled()
    names = [a for a in sys.argv[1:] if not a.startswith("--")]
    if "--dummies" in sys.argv or "--all-dummies" in sys.argv:
        names += [n for n in PD.BUILDERS if n not in names]
    if not names:
        names = list(PS.BUILDERS) + list(PD.BUILDERS) + list(PB.BUILDERS)
    man_path = os.path.join(PARTS, "manifest.json")
    man = json.load(open(man_path)) if os.path.exists(man_path) else {}
    for n in names:
        man[n] = build(n)
        json.dump(man, open(man_path, "w"), indent=1)


if __name__ == "__main__":
    main()
