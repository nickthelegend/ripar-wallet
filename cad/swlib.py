"""
swlib - thin helper layer over the SolidWorks COM API (pywin32).

All public helpers take millimetres and degrees; conversion to the API's
metres/radians happens here.  Sketches are written in a caller-defined 2D
frame (origin + u + v vectors in model space) and mapped to the real
sketch coordinates through the sketch's ModelToSketchTransform, so any
plane (standard, offset, angled) can be used without guessing axes.
"""
import math
import os
import types

import numpy as np
import pythoncom
import win32com.client as wc
from win32com.client import VARIANT

MM = 1e-3
DEG = math.pi / 180.0
NOTHING = VARIANT(pythoncom.VT_DISPATCH, None)
EMPTY = VARIANT(pythoncom.VT_EMPTY, None)

TEMPLATE_DIR = r"C:\ProgramData\SOLIDWORKS\SOLIDWORKS 2026\templates"
TEMPLATE_PART = os.path.join(TEMPLATE_DIR, "Part.PRTDOT")
TEMPLATE_ASM = os.path.join(TEMPLATE_DIR, "Assembly.ASMDOT")

# --- enums used (swconst) ---------------------------------------------------
END_BLIND, END_THROUGH_ALL, END_MIDPLANE, END_THROUGH_ALL_BOTH = 0, 1, 6, 9
END_UP_TO_NEXT = 2
START_SKETCH, START_OFFSET = 0, 3
REFPLANE_PARALLEL, REFPLANE_PERP, REFPLANE_COINCIDENT = 1, 2, 4
REFPLANE_DISTANCE, REFPLANE_ANGLE = 8, 16
REFPLANE_FLIP = 256
BODY_SOLID = 0
COMBINE_ADD, COMBINE_SUBTRACT, COMBINE_COMMON = 15903, 15902, 15901


def V(x):
    """Resolve a zero-argument COM member that pywin32 may expose either as a
    bound method (early-bound) or as an already-evaluated property."""
    return x() if isinstance(x, types.MethodType) else x


def arr_d(values):
    return VARIANT(pythoncom.VT_ARRAY | pythoncom.VT_R8, [float(v) for v in values])


def arr_disp(objs):
    return VARIANT(pythoncom.VT_ARRAY | pythoncom.VT_DISPATCH, list(objs))


_app = None
CREATED = []          # titles of documents this process created


def close_created():
    """Close only the documents created by this script (never the user's)."""
    sw = app()
    for t in list(CREATED):
        try:
            sw.CloseDoc(t)
        except Exception:
            pass
        CREATED.remove(t)


SW_EXE = r"C:\Program Files\SOLIDWORKS Corp\SOLIDWORKS\SLDWORKS.exe"
PID_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "model", ".sw_pid")


def _bind_pid(pid):
    """Attach to one specific SolidWorks process through its ROT moniker
    'SolidWorks_PID_<pid>' (never to whichever instance happens to be active)."""
    rot = pythoncom.GetRunningObjectTable()
    ctx = pythoncom.CreateBindCtx(0)
    for m in rot.EnumRunning():
        try:
            if m.GetDisplayName(ctx, None) == "SolidWorks_PID_%d" % pid:
                unk = rot.GetObject(m)
                return wc.Dispatch(unk.QueryInterface(pythoncom.IID_IDispatch))
        except Exception:
            pass
    return None


def app():
    """The dedicated SolidWorks session for this project.  It is started once
    by this script (its PID is kept in model/.sw_pid) so user sessions are
    never touched."""
    global _app
    if _app is not None:
        return _app
    import subprocess
    import time
    if os.path.exists(PID_FILE):
        pid = int(open(PID_FILE).read().strip())
        _app = _bind_pid(pid)
        if _app is not None:
            return _app
    proc = subprocess.Popen([SW_EXE])
    t0 = time.time()
    while time.time() - t0 < 300:
        time.sleep(3)
        _app = _bind_pid(proc.pid)
        if _app is not None:
            break
    if _app is None:
        raise RuntimeError("could not attach to the SolidWorks session started for this project")
    open(PID_FILE, "w").write(str(proc.pid))
    _app.Visible = True
    time.sleep(5)
    return _app


def _is_embedding_instance(pid):
    """True when pid is the session this project started (safe to clear)."""
    if os.path.exists(PID_FILE) and int(open(PID_FILE).read().strip()) == pid:
        return True
    return _is_embedding_legacy(pid)


def _is_embedding_legacy(pid):
    import subprocess
    out = subprocess.run(["powershell", "-NoProfile", "-Command",
                          "(Get-CimInstance Win32_Process -Filter \"ProcessId=%d\").CommandLine" % pid],
                         capture_output=True, text=True).stdout
    return "-Embedding" in out


def cleanup_untitled():
    """Close leftover *unsaved, untitled* documents from crashed script runs -
    only when talking to a script-launched (-Embedding) SolidWorks, so a
    user's own session is never touched."""
    sw = app()
    if not _is_embedding_instance(V(sw.GetProcessID)):
        return 0
    n = 0
    for d in (sw.GetDocuments or []):
        if not V(d.GetPathName):
            sw.CloseDoc(V(d.GetTitle))
            n += 1
    return n


def close_project_docs(folder=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "model")):
    """Close every open document that lives in this project's model folder
    (plus untitled leftovers in a script-launched SolidWorks)."""
    sw = app()
    if _is_embedding_instance(V(sw.GetProcessID)):
        # script-launched SolidWorks: everything open in it is ours
        n = len(list(sw.GetDocuments or []))
        sw.CloseAllDocuments(True)
        return n
    n = 0
    docs = list(sw.GetDocuments or [])
    # assemblies first so their parts can be released
    docs.sort(key=lambda d: 0 if V(d.GetType) == 2 else 1)
    for d in docs:
        p = V(d.GetPathName) or ""
        if p.lower().startswith(folder.lower()):
            sw.CloseDoc(V(d.GetTitle))
            n += 1
    n += cleanup_untitled()
    return n


def activate(doc):
    sw = app()
    err = VARIANT(pythoncom.VT_BYREF | pythoncom.VT_I4, 0)
    sw.ActivateDoc3(V(doc.GetTitle), False, 0, err)


def v3(p):
    return np.asarray(p, dtype=float)


def unit(p):
    p = v3(p)
    n = np.linalg.norm(p)
    return p / n if n > 0 else p


# =============================================================================
# geometry helpers for 2D outlines
# =============================================================================
def rounded_polygon(pts, radii):
    """Return a list of segments for a closed polygon whose corners are filleted.
    pts: [(x,y)], radii: float or list.  Segments are ('line', a, b) or
    ('arc', a, mid, b) with 2D tuples."""
    n = len(pts)
    if not isinstance(radii, (list, tuple)):
        radii = [radii] * n
    P = [np.array(p, float) for p in pts]
    corners = []
    for i in range(n):
        p0, p1, p2 = P[i - 1], P[i], P[(i + 1) % n]
        r = radii[i]
        if r <= 0:
            corners.append((p1, None, p1))
            continue
        d1 = unit(p0 - p1)
        d2 = unit(p2 - p1)
        cosang = float(np.clip(np.dot(d1, d2), -1, 1))
        half = math.acos(cosang) / 2.0
        t = r / math.tan(half)
        t1 = p1 + d1 * t
        t2 = p1 + d2 * t
        bis = unit(d1 + d2)
        c = p1 + bis * (r / math.sin(half))
        mid = c + unit(p1 - c) * r
        corners.append((t1, mid, t2))
    segs = []
    for i in range(n):
        t1, mid, t2 = corners[i]
        if mid is not None:
            segs.append(("arc", tuple(t1), tuple(mid), tuple(t2)))
        nt1 = corners[(i + 1) % n][0]
        if np.linalg.norm(nt1 - t2) > 1e-6:
            segs.append(("line", tuple(t2), tuple(nt1)))
    return segs


def rounded_rect(cx, cy, w, h, r):
    x0, x1, y0, y1 = cx - w / 2, cx + w / 2, cy - h / 2, cy + h / 2
    return rounded_polygon([(x0, y0), (x1, y0), (x1, y1), (x0, y1)], r)


def slot_profile(p1, p2, r):
    """Obround between centres p1,p2 with radius r."""
    p1, p2 = np.array(p1, float), np.array(p2, float)
    d = unit(p2 - p1)
    n = np.array([-d[1], d[0]])
    a1, b1 = p1 + n * r, p2 + n * r
    a2, b2 = p2 - n * r, p1 - n * r
    return [("line", tuple(a1), tuple(b1)),
            ("arc", tuple(b1), tuple(p2 + d * r), tuple(a2)),
            ("line", tuple(a2), tuple(b2)),
            ("arc", tuple(b2), tuple(p1 - d * r), tuple(a1))]


# =============================================================================
# Sketch
# =============================================================================
class Sketch:
    """2D sketch on a named plane.  Coordinates passed to drawing methods are
    in the caller frame: model = origin + a*u + b*v (mm)."""

    def __init__(self, part, plane, origin=(0, 0, 0), u=(1, 0, 0), v=(0, 1, 0)):
        self.part = part
        self.o, self.u, self.v = v3(origin), unit(u), unit(v)
        part.clear()
        if not part.select(plane, "PLANE"):
            if not part.select(plane, "FACE"):
                raise RuntimeError("cannot select plane " + plane)
        part.sm.InsertSketch(True)
        part.sm.AddToDB = True
        sk = V(part.doc.GetActiveSketch2)
        if sk is None:
            raise RuntimeError("sketch not active on " + plane)
        xf = V(sk.ModelToSketchTransform)
        a = list(xf.ArrayData)
        self.R = np.array(a[0:9]).reshape(3, 3)
        self.T = np.array(a[9:12])
        self.S = a[12]
        self.name = None
        # the caller's origin must lie on the sketch plane, otherwise geometry
        # would silently be projected onto a different plane
        off = ((self.o * MM) @ self.R) * self.S + self.T
        if abs(off[2]) > 1e-6:
            part.sm.InsertSketch(True)
            raise RuntimeError("sketch origin %s is %.3f mm off plane %s" %
                               (self.o, off[2] / MM, plane))

    def _sk(self, p2):
        m = (self.o + p2[0] * self.u + p2[1] * self.v) * MM
        s = (m @ self.R) * self.S + self.T  # SolidWorks row-vector convention
        return float(s[0]), float(s[1])

    def line(self, a, b):
        x1, y1 = self._sk(a)
        x2, y2 = self._sk(b)
        return self.part.sm.CreateLine(x1, y1, 0, x2, y2, 0)

    def centerline(self, a, b):
        x1, y1 = self._sk(a)
        x2, y2 = self._sk(b)
        return self.part.sm.CreateCenterLine(x1, y1, 0, x2, y2, 0)

    def arc3(self, a, mid, b):
        x1, y1 = self._sk(a)
        x2, y2 = self._sk(b)
        x3, y3 = self._sk(mid)
        return self.part.sm.Create3PointArc(x1, y1, 0, x2, y2, 0, x3, y3, 0)

    def circle(self, c, r):
        x, y = self._sk(c)
        return self.part.sm.CreateCircleByRadius(x, y, 0, r * MM * self._scale_len())

    def _scale_len(self):
        return 1.0

    def segs(self, segments):
        for s in segments:
            if s[0] == "line":
                self.line(s[1], s[2])
            else:
                self.arc3(s[1], s[2], s[3])

    def poly(self, pts, closed=True):
        n = len(pts)
        for i in range(n if closed else n - 1):
            self.line(pts[i], pts[(i + 1) % n])

    def rpoly(self, pts, r):
        self.segs(rounded_polygon(pts, r))

    def rrect(self, cx, cy, w, h, r):
        if r <= 0:
            x0, x1, y0, y1 = cx - w / 2, cx + w / 2, cy - h / 2, cy + h / 2
            self.poly([(x0, y0), (x1, y0), (x1, y1), (x0, y1)])
        else:
            self.segs(rounded_rect(cx, cy, w, h, r))

    def slot(self, p1, p2, r):
        self.segs(slot_profile(p1, p2, r))

    def spline(self, pts, closed=False):
        flat = []
        for p in pts:
            x, y = self._sk(p)
            flat += [x, y, 0.0]
        return self.part.sm.CreateSpline2(arr_d(flat), closed)

    def text(self, c, txt, height, font="Arial Black", width_factor=1.0, spacing=1.0,
             bold=False, outward=None, mirror=None):
        """Sketch text.  The baseline starts at caller point c (mm) and runs along
        the caller +u axis with letter tops toward +v.  `outward` (model vector) is
        the side the text must read correctly from; by default u x v.  The sketch
        axes are read from ModelToSketchTransform, so the text is rotated
        (Escapement) and mirrored as needed for any plane orientation."""
        xs, ys, n = self.R[:, 0], self.R[:, 1], self.R[:, 2]
        u = unit(self.u)
        out = unit(outward) if outward is not None else unit(np.cross(self.u, self.v))
        flip = float(np.dot(n, out)) < 0          # viewing the sketch from its back
        if mirror is None:
            mirror = flip
        ang = math.atan2(float(np.dot(u, ys)), float(np.dot(u, xs)))
        if flip:
            # verified on SW2026: a sketch seen from its back needs the text
            # rotated 180 deg AND horizontally mirrored (flag mirrors about the
            # insertion point) to read along +u with tops toward +v
            ang += math.pi
        x, y = self._sk(c)
        st = self.part.doc.InsertSketchText(x, y, 0, txt, 0, 0, 1 if mirror else 0,
                                            int(width_factor * 100), int(spacing * 100))
        if st is None:
            raise RuntimeError("InsertSketchText failed")
        fmt = V(st.GetTextFormat)
        fmt.TypeFaceName = font
        fmt.CharHeight = height * MM
        fmt.Bold = bold
        fmt.Escapement = ang
        st.SetTextFormat(False, fmt)
        return st

    def close(self, name=None):
        sm = self.part.sm
        sm.AddToDB = False
        sm.InsertSketch(True)
        feat = self.part.doc.FeatureByPositionReverse(0)
        if name:
            feat.Name = name
        self.name = feat.Name
        self.part.sk_normal[self.name] = unit(self.R[:, 2])
        return self.name


# =============================================================================
# Part
# =============================================================================
class Part:
    def __init__(self, name):
        self.sw = app()
        self.name = name
        self.doc = self.sw.NewDocument(TEMPLATE_PART, 0, 0, 0)
        if self.doc is None:
            raise RuntimeError("NewDocument failed")
        CREATED.append(V(self.doc.GetTitle))
        activate(self.doc)
        try:
            self.doc.ActiveView.EnableGraphicsUpdate = False   # speed; re-enabled for snapshots
        except Exception:
            pass
        self.ext = self.doc.Extension
        self.sm = self.doc.SketchManager
        self.fm = self.doc.FeatureManager
        self.selmgr = self.doc.SelectionManager
        self.doc.SetUserPreferenceToggle(10, False)  # swSketchInference off-ish
        self.sk_normal = {}

    # ---- selection ------------------------------------------------------------
    def clear(self):
        self.doc.ClearSelection2(True)

    def select(self, name, typ, append=False, mark=0):
        return self.ext.SelectByID2(name, typ, 0, 0, 0, append, mark, NOTHING, 0)

    def select_ent(self, ent, append=True, mark=0):
        sd = V(self.selmgr.CreateSelectData)
        sd.Mark = mark
        return ent.Select4(append, sd)

    def sketch(self, plane, origin=(0, 0, 0), u=(1, 0, 0), v=(0, 1, 0)):
        return Sketch(self, plane, origin, u, v)

    def has_feature(self, name):
        return self.doc.FeatureByName(name) is not None

    def last_feature(self, name=None):
        f = self.doc.FeatureByPositionReverse(0)
        if name and f is not None:
            f.Name = name
        return f

    # ---- reference geometry --------------------------------------------------
    def plane_offset(self, base, dist, name, flip=False):
        self.clear()
        self.select(base, "PLANE", False, 0)
        c = REFPLANE_DISTANCE | (REFPLANE_FLIP if flip else 0)
        f = self.fm.InsertRefPlane(c, abs(dist) * MM, 0, 0, 0, 0)
        if f is None:
            raise RuntimeError("ref plane failed " + name)
        f.Name = name
        self.clear()
        return name

    def plane_from_points(self, p0, p1, p2, name):
        """Reference plane through 3 model points (mm) - built from a 3D sketch."""
        self.clear()
        self.sm.Insert3DSketch(True)
        self.sm.AddToDB = True
        pts = [self.sm.CreatePoint(*(v3(p) * MM)) for p in (p0, p1, p2)]
        self.sm.AddToDB = False
        self.sm.Insert3DSketch(True)
        sk = self.doc.FeatureByPositionReverse(0)
        sk.Name = name + "_pts"
        self.clear()
        for i, sp in enumerate(pts):
            self.select_ent(sp, True, i)
        f = self.fm.InsertRefPlane(REFPLANE_COINCIDENT, 0, REFPLANE_COINCIDENT, 0,
                                   REFPLANE_COINCIDENT, 0)
        if f is None:
            raise RuntimeError("3pt plane failed " + name)
        f.Name = name
        sk.SetSuppression2(0, 1, EMPTY) if False else None
        self.clear()
        return name

    def axis_from_points(self, p0, p1, name):
        self.clear()
        self.sm.Insert3DSketch(True)
        self.sm.AddToDB = True
        ln = self.sm.CreateLine(*(v3(p0) * MM), *(v3(p1) * MM))
        self.sm.AddToDB = False
        self.sm.Insert3DSketch(True)
        sk = self.doc.FeatureByPositionReverse(0)
        sk.Name = name + "_line"
        self.clear()
        self.select_ent(ln, False, 0)
        ok = self.doc.InsertAxis2(True)
        f = self.doc.FeatureByPositionReverse(0)
        f.Name = name
        self.clear()
        return name

    # ---- features ------------------------------------------------------------
    def _sel_sketch(self, sk):
        self.clear()
        name = sk.name if isinstance(sk, Sketch) else sk
        if not self.select(name, "SKETCH", False, 0):
            raise RuntimeError("cannot select sketch " + str(name))

    def extrude(self, sk, d1=0.0, d2=0.0, mid=False, reverse=False, merge=True,
                offset=0.0, name=None, through=False, up_to_next=False, both=False,
                through_next=False, draft=0.0, draft_out=False):
        """Boss extrude.  d1 along the sketch plane normal (against it with
        reverse=True); d2 > 0 extrudes the second direction as well."""
        self._sel_sketch(sk)
        t2 = END_BLIND
        if up_to_next or through_next:
            t1 = 11 if up_to_next else 2
            if both:
                t2 = t1
        elif through:
            t1 = END_THROUGH_ALL
        else:
            t1 = END_MIDPLANE if mid else END_BLIND
        both = both or ((d2 > 0) and not mid)
        f = self.fm.FeatureExtrusion3(
            not both, False, reverse, t1, t2, d1 * MM, d2 * MM,
            bool(draft), False, bool(draft_out), False, abs(draft) * DEG, 0, False, False, False, False,
            merge, True, True,
            START_OFFSET if offset else START_SKETCH, abs(offset) * MM, offset < 0)
        if f is None:
            raise RuntimeError("extrude failed: %s" % name)
        if name:
            f.Name = name
        self.clear()
        return f

    def cut(self, sk, d1=0.0, d2=0.0, mid=False, reverse=False, through=False,
            through_both=False, offset=0.0, name=None, draft=0.0, draft_out=False):
        """Cut extrude.  SolidWorks cuts AGAINST the sketch plane normal by
        default (into the material of a face you sketched on); reverse=True
        cuts along the normal."""
        self._sel_sketch(sk)
        if through_both:
            t1, t2, sd = END_THROUGH_ALL, END_THROUGH_ALL, False
        elif through:
            t1, t2, sd = END_THROUGH_ALL, END_BLIND, True
        elif mid:
            t1, t2, sd = END_MIDPLANE, END_BLIND, True
        else:
            t1, t2, sd = END_BLIND, END_BLIND, not (d2 > 0)
        f = self.fm.FeatureCut4(
            sd, False, reverse, t1, t2, d1 * MM, d2 * MM,
            bool(draft), False, bool(draft_out), False, abs(draft) * DEG, 0, False, False, False, False,
            False, True, True, True, True, False,
            START_OFFSET if offset else START_SKETCH, abs(offset) * MM, offset < 0, False)
        if f is None:
            raise RuntimeError("cut failed: %s" % name)
        if name:
            f.Name = name
        self.clear()
        return f

    def _normal(self, sk):
        name = sk.name if isinstance(sk, Sketch) else sk
        return self.sk_normal[name]

    def extrude_toward(self, sk, d, direction, **kw):
        """Boss-extrude d mm from the sketch plane toward model vector `direction`."""
        rev = float(np.dot(self._normal(sk), unit(direction))) < 0
        return self.extrude(sk, d, reverse=rev, **kw)

    def cut_toward(self, sk, d, direction, **kw):
        """Cut d mm from the sketch plane toward model vector `direction`."""
        rev = float(np.dot(self._normal(sk), unit(direction))) > 0
        return self.cut(sk, d, reverse=rev, **kw)

    def revolve(self, sk, angle=360.0, cut=False, merge=True, name=None, mid=False):
        self._sel_sketch(sk)
        f = self.fm.FeatureRevolve2(
            True, True, False, cut, False, False,
            END_MIDPLANE if mid else END_BLIND, 0, angle * DEG, 0,
            False, False, 0, 0, 0, 0, 0, merge, True, True)
        if f is None:
            raise RuntimeError("revolve failed: %s" % name)
        if name:
            f.Name = name
        self.clear()
        return f

    def loft(self, sketches, merge=True, name=None, picks=None):
        """picks: one model point (mm) per profile; picking every profile at
        the corresponding spot keeps the loft connectors aligned (no twist)."""
        self.clear()
        for i, s in enumerate(sketches):
            nm = s.name if isinstance(s, Sketch) else s
            if picks is not None:
                x, y, z = (v3(picks[i]) * MM).tolist()
                self.ext.SelectByID2(nm, "SKETCH", x, y, z, True, 1, NOTHING, 0)
            else:
                self.select(nm, "SKETCH", True, 1)
        f = self.fm.InsertProtrusionBlend(False, False, False, 1.0, 0, 0, 0, 0, False, False,
                                          False, 0, 0, 0, merge, True, True)
        if f is None:
            raise RuntimeError("loft failed: %s" % name)
        if name:
            f.Name = name
        self.clear()
        return f

    def fillet(self, edges, r, name=None, quiet=False):
        edges = list(edges)
        if not edges:
            if quiet:
                return None
            raise RuntimeError("fillet: no edges (%s)" % name)
        self.clear()
        for e in edges:
            self.select_ent(e.ent if isinstance(e, EdgeInfo) else e, True, 0)
        f = self.fm.FeatureFillet3(195, r * MM, 0, 0, 0, 0, 0,
                                   EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY)
        self.clear()
        if f is None:
            if quiet:
                return None
            raise RuntimeError("fillet failed: %s (%d edges, r=%.2f)" % (name, len(edges), r))
        if name:
            f.Name = name
        return f

    def chamfer(self, edges, d, name=None, quiet=False):
        self.clear()
        for e in edges:
            self.select_ent(e.ent if isinstance(e, EdgeInfo) else e, True, 0)
        f = self.fm.InsertFeatureChamfer(4, 1, d * MM, 45 * DEG, 0, 0, 0, 0)
        self.clear()
        if f is None and not quiet:
            raise RuntimeError("chamfer failed: %s" % name)
        if f is not None and name:
            f.Name = name
        return f

    def shell(self, faces, t, name=None, outward=False):
        self.clear()
        for fc in faces:
            self.select_ent(fc.ent if isinstance(fc, FaceInfo) else fc, True, 0)
        before = self.doc.FeatureByPositionReverse(0).Name
        self.doc.InsertFeatureShell(t * MM, outward)
        f = self.doc.FeatureByPositionReverse(0)
        self.clear()
        if f.Name == before:
            raise RuntimeError("shell failed: %s" % name)
        if name:
            f.Name = name
        return f

    def move_body(self, body, translate=(0, 0, 0), rot_point=(0, 0, 0), rot=(0, 0, 0), copy=False):
        """Move/rotate a body.  rot = Euler angles (deg) about X, Y, Z."""
        self.clear()
        self.select_ent(body, False, 1)
        t = v3(translate) * MM
        rp = v3(rot_point) * MM
        f = self.fm.InsertMoveCopyBody2(t[0], t[1], t[2], 0, rp[0], rp[1], rp[2],
                                        rot[0] * DEG, rot[1] * DEG, rot[2] * DEG, copy, 1)
        self.clear()
        return f

    def combine_all(self, op=COMBINE_ADD, name=None):
        bodies = self.bodies()
        if len(bodies) < 2:
            return None
        self.clear()
        main = bodies[0]
        self.select_ent(main, False, 1) if False else None
        f = self.fm.InsertCombineFeature(op, main, arr_disp(bodies[1:]))
        self.clear()
        if f is None:
            raise RuntimeError("combine failed: %s" % name)
        if name:
            f.Name = name
        return f

    def cut_cylinder(self, a, b, d, name):
        """Straight round hole of diameter d from model point a to b (mm)."""
        a, b = v3(a), v3(b)
        ax = unit(b - a)
        ref = np.array([0, 0, 1.0]) if abs(ax[2]) < 0.9 else np.array([1.0, 0, 0])
        u = unit(np.cross(ax, ref))
        v = np.cross(ax, u)
        m = (a + b) / 2
        self.plane_from_points(m, m + 10 * u, m + 10 * v, name + "_Plane")
        s = self.sketch(name + "_Plane", origin=m, u=u, v=v)
        s.circle((0, 0), d / 2)
        s.close(name + "_Sk")
        return self.cut(s, float(np.linalg.norm(b - a)), mid=True, name=name)

    # ---- topology queries ------------------------------------------------------
    def bodies(self):
        b = self.doc.GetBodies2(BODY_SOLID, True)
        return list(b) if b else []

    def body(self):
        bs = self.bodies()
        if len(bs) != 1:
            raise RuntimeError("%s: expected 1 body, got %d" % (self.name, len(bs)))
        return bs[0]

    def edges(self):
        out = []
        for b in self.bodies():
            for e in V(b.GetEdges) or []:
                out.append(EdgeInfo(e))
        return out

    def faces(self):
        out = []
        for b in self.bodies():
            for f in V(b.GetFaces) or []:
                out.append(FaceInfo(f))
        return out

    def bbox(self):
        lo, hi = np.full(3, 1e9), np.full(3, -1e9)
        for b in self.bodies():
            bx = V(b.GetBodyBox)
            lo = np.minimum(lo, np.array(bx[:3]) / MM)
            hi = np.maximum(hi, np.array(bx[3:]) / MM)
        return lo, hi

    def volume_mm3(self):
        mp = V(self.ext.CreateMassProperty)
        return mp.Volume / MM ** 3

    # ---- appearance / output ---------------------------------------------------
    def color(self, rgb, spec=0.35, shine=0.4, transp=0.0):
        r, g, b = rgb
        vals = [r, g, b, 1.0, 1.0, spec, shine, transp, 0.0]
        self.doc.MaterialPropertyValues = arr_d(vals)

    def material(self, name="PLA"):
        try:
            self.doc.SetMaterialPropertyName2("Default", "solidworks materials.sldmat", name)
        except Exception:
            pass

    def rebuild(self):
        self.doc.ForceRebuild3(False)

    def save(self, path):
        self.rebuild()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        other = self.sw.GetOpenDocumentByName(path)
        if other is not None and V(other.GetTitle) != V(self.doc.GetTitle):
            self.sw.CloseDoc(V(other.GetTitle))
            activate(self.doc)
        if os.path.exists(path):
            os.remove(path)
        old = V(self.doc.GetTitle)
        err = self.doc.SaveAs3(path, 0, 1)
        if err != 0:
            raise RuntimeError("save failed %s err=%s" % (path, err))
        if old in CREATED:
            CREATED.remove(old)
        CREATED.append(V(self.doc.GetTitle))
        return path

    def close(self):
        t = V(self.doc.GetTitle)
        self.sw.CloseDoc(t)
        if t in CREATED:
            CREATED.remove(t)

    def snapshot(self, path, view="*Isometric", view_id=7):
        snapshot(self.doc, path, view, view_id)


def snapshot(doc, path, view="*Isometric", view_id=7, zoom=True):
    try:
        doc.ActiveView.EnableGraphicsUpdate = True
    except Exception:
        pass
    if view:
        doc.ShowNamedView2(view, view_id)
    if zoom:
        doc.ViewZoomtofit2()
    doc.GraphicsRedraw2()
    if os.path.exists(path):
        os.remove(path)
    return doc.SaveAs3(path, 0, 1)


# =============================================================================
# topology wrappers
# =============================================================================
class EdgeInfo:
    """Edge wrapper with lazily evaluated geometry (each value costs COM calls)."""

    def __init__(self, ent):
        self.ent = ent
        self._c = None

    def _curve(self):
        if self._c is None:
            cp = V(self.ent.GetCurveParams3)
            c = V(self.ent.GetCurve)
            self._c = (cp, c)
        return self._c

    def __getattr__(self, k):
        if k.startswith("_") or k == "ent":
            raise AttributeError(k)
        cp, c = self._curve()
        if k == "start":
            v = np.array(cp.StartPoint) / MM
        elif k == "end":
            v = np.array(cp.EndPoint) / MM
        elif k == "mid":
            u0, u1 = cp.UMinValue, cp.UMaxValue
            v = np.array(c.Evaluate2((u0 + u1) / 2, 0)[:3]) / MM
        elif k == "is_line":
            v = bool(V(c.IsLine))
        elif k == "is_circle":
            v = bool(V(c.IsCircle))
        elif k in ("center", "axis", "radius"):
            if self.is_circle:
                cpar = V(c.CircleParams)
                self.center = np.array(cpar[0:3]) / MM
                self.axis = np.array(cpar[3:6])
                self.radius = cpar[6] / MM
            else:
                self.center = self.axis = self.radius = None
            return getattr(self, k)
        elif k == "dir":
            v = unit(self.end - self.start) if self.is_line else None
        elif k == "length":
            v = float(np.linalg.norm(self.end - self.start)) if self.is_line else None
        elif k == "closed":
            v = float(np.linalg.norm(self.end - self.start)) < 1e-6
        else:
            raise AttributeError(k)
        setattr(self, k, v)
        return v

    def pts(self):
        return [self.start, self.mid, self.end]

    def __repr__(self):
        return "Edge(mid=%s)" % (np.round(self.mid, 2),)


class FaceInfo:
    def __init__(self, ent):
        self.ent = ent
        s = V(ent.GetSurface)
        self.is_plane = bool(V(s.IsPlane))
        self.is_cyl = bool(V(s.IsCylinder))
        bx = V(ent.GetBox)
        self.bmin = np.array(bx[:3]) / MM
        self.bmax = np.array(bx[3:]) / MM
        self.center = (self.bmin + self.bmax) / 2
        self.area = V(ent.GetArea) / MM ** 2
        self.normal = None
        if self.is_plane:
            n = np.array(V(ent.Normal))
            self.normal = n
            pp = V(s.PlaneParams)
            self.root = np.array(pp[3:6]) / MM
        self.cyl_axis = self.cyl_origin = None
        if self.is_cyl:
            cp = V(s.CylinderParams)
            self.cyl_origin = np.array(cp[0:3]) / MM
            self.cyl_axis = np.array(cp[3:6])
            self.radius = cp[6] / MM

    def __repr__(self):
        return "Face(%s c=%s)" % ("plane" if self.is_plane else "cyl" if self.is_cyl else "other",
                                  np.round(self.center, 2))


# =============================================================================
# edge filters
# =============================================================================
def edges_where(edges, pred):
    return [e for e in edges if pred(e)]


def all_pts(e, fn):
    return all(fn(p) for p in e.pts())


def any_pts(e, fn):
    return any(fn(p) for p in e.pts())


def parallel(e, axis, tol=1e-3):
    if not e.is_line:
        return False
    return abs(abs(float(np.dot(e.dir, unit(axis)))) - 1) < tol


def circ_axis(e, axis, tol=1e-3):
    if not e.is_circle:
        return False
    return abs(abs(float(np.dot(unit(e.axis), unit(axis)))) - 1) < tol


VIEW_IDS = {"*Front": 1, "*Back": 2, "*Left": 3, "*Right": 4, "*Top": 5, "*Bottom": 6,
            "*Isometric": 7, "*Trimetric": 8, "*Dimetric": 9}


def hide_refs(doc):
    for t in (4, 5, 6, 7, 13, 196, 31):
        try:
            doc.SetUserPreferenceToggle(t, False)
        except Exception:
            pass
    try:
        doc.Extension.SetUserPreferenceToggle(198, 0, True)
    except Exception:
        pass


def _crop(im, bg_tol=12):
    import PIL.ImageChops as IC
    from PIL import Image
    bg = Image.new(im.mode, im.size, im.getpixel((2, 2)))
    diff = IC.difference(im, bg).convert("L").point(lambda v: 255 if v > bg_tol else 0)
    bb = diff.getbbox()
    if bb:
        pad = 12
        bb = (max(bb[0] - pad, 0), max(bb[1] - pad, 0), min(bb[2] + pad, im.width), min(bb[3] + pad, im.height))
        im = im.crop(bb)
    return im


def multiview(doc, out_png, views=("*Isometric", "*Front", "*Right", "*Top"), height=420, tmp_dir=None):
    """Save several cropped views side by side into one PNG."""
    from PIL import Image, ImageDraw
    hide_refs(doc)
    tmp_dir = tmp_dir or os.path.dirname(out_png)
    ims = []
    for v in views:
        if isinstance(v, tuple):
            name, orient = v
            doc.ShowNamedView2("", -1)
            view = doc.ActiveView
            snapshot(doc, os.path.join(tmp_dir, "_mv_tmp.png"), view=None)
        else:
            snapshot(doc, os.path.join(tmp_dir, "_mv_tmp.png"), view=v, view_id=VIEW_IDS[v])
            name = v.strip("*")
        im = _crop(Image.open(os.path.join(tmp_dir, "_mv_tmp.png")).convert("RGB"))
        s = height / im.height
        im = im.resize((max(1, int(im.width * s)), height))
        d = ImageDraw.Draw(im)
        d.text((6, 4), name, fill=(40, 40, 40))
        ims.append(im)
    W = sum(i.width for i in ims) + 8 * (len(ims) - 1)
    out = Image.new("RGB", (W, height), (255, 255, 255))
    x = 0
    for i in ims:
        out.paste(i, (x, 0))
        x += i.width + 8
    out.save(out_png)
    try:
        os.remove(os.path.join(tmp_dir, "_mv_tmp.png"))
    except Exception:
        pass
    return out_png


def with_retry(fn, *args, tries=3, **kw):
    """Run a part builder; on a COM/geometry hiccup close what it created and
    try again from scratch."""
    import time
    import traceback
    last = None
    for k in range(tries):
        n0 = len(CREATED)
        try:
            return fn(*args, **kw)
        except Exception as e:  # noqa
            last = e
            print("  ! attempt %d failed: %s" % (k + 1, e))
            traceback.print_exc(limit=2)
            sw = app()
            for t in CREATED[n0:]:
                try:
                    sw.CloseDoc(t)
                except Exception:
                    pass
            del CREATED[n0:]
            time.sleep(2)
    raise last
