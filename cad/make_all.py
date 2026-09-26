"""
One command rebuilds everything from design.py:
    python cad/make_all.py        parts + assembly + interference + exports + P1S slicing + renders
                                  (works from any folder)
    python make_all.py --quick    skip renders
"""
import os
import subprocess
import sys

from swlib import close_project_docs

PY = sys.executable
steps = [
    ["build_parts.py", "Front_Shell", "Back_Shell", "Sign_Pin", "FitTest_Front", "FitTest_Back", "--all-dummies", "--no-views"],
    ["assembly.py"],
    ["interference.py"],
    ["export.py"],
    ["slice_bambu.py"],          # ready-to-print P1S .gcode.3mf in print/bambu/
]
if "--quick" not in sys.argv:
    steps.append(["render_py.py"])

print("closed", close_project_docs(), flush=True)
for st in steps:
    print("\n=== " + " ".join(st), flush=True)
    subprocess.run([PY, "-u"] + st, check=True, cwd=os.path.dirname(os.path.abspath(__file__)))
    if st[0] == "build_parts.py":
        close_project_docs()

if "--exit" in sys.argv:
    # give the RAM back: quit the SolidWorks session this project started (never a user session)
    import os
    from swlib import PID_FILE, _bind_pid
    if os.path.exists(PID_FILE):
        sw = _bind_pid(int(open(PID_FILE).read().strip()))
        if sw is not None:
            sw.ExitApp()
            print("SolidWorks session closed", flush=True)
