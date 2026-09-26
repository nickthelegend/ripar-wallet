"""SolidWorks interference detection on RiparWallet.SLDASM -> model/interference_report.json"""
import json
import os

from assembly import ROOT, attach
from swlib import MM, V

# designed contacts that are not collisions
EXPECTED = [
    ("Back_Shell", "Board_PCB"),             # peg tips enter the M2 SMT nuts
    ("Board_PCB", "Dupont_Harness"),         # header pins inside the jumper housings (plugged on)
]
TINY_MM3 = 0.05


def base(name):
    return name.rsplit("-", 1)[0]


def check(doc):
    idm = V(doc.InterferenceDetectionManager)
    for k, v in dict(TreatCoincidenceAsInterference=False, TreatSubAssembliesAsComponents=True,
                     IncludeMultibodyPartInterferences=False, MakeInterferingPartsTransparent=False,
                     CreateFastenersFolder=False, IgnoreHiddenBodies=True,
                     ShowIgnoredInterferences=False, UseTransform=True).items():
        try:
            setattr(idm, k, v)
        except Exception:
            pass
    ints = V(idm.GetInterferences) or []
    out = []
    for it in ints:
        comps = [V(c.Name2) for c in (V(it.Components) or [])]
        vol = V(it.Volume) / MM ** 3
        where = None
        try:
            b = V(it.GetInterferenceBody)
            bx = V(b.GetBodyBox)
            where = [round(v / MM, 2) for v in bx]
        except Exception:
            pass
        pair = tuple(sorted(base(c) for c in comps))
        expected = any(sorted(e) == list(pair) for e in EXPECTED) or vol < TINY_MM3
        out.append(dict(components=comps, pair=pair, volume_mm3=round(vol, 3), expected=expected, box=where))
    V(idm.Done)
    return out


def main():
    doc = attach()
    res = check(doc)
    bad = [r for r in res if not r["expected"]]
    print("%d interferences (%d unexpected)" % (len(res), len(bad)))
    for r in sorted(res, key=lambda r: -r["volume_mm3"]):
        print("  %s %9.3f mm3  %-45s %s" % ("  " if r["expected"] else "!!", r["volume_mm3"],
                                              " x ".join(r["pair"]), r["box"]))
    json.dump(res, open(os.path.join(ROOT, "model", "interference_report.json"), "w"), indent=1)
    return res


if __name__ == "__main__":
    main()
