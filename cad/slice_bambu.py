"""
Slice the printable parts for a Bambu Lab P1S with Bambu Studio's command line.

Makes two ready-to-print projects in print/bambu/ (open in Bambu Studio -> Print,
or copy the .gcode.3mf to the P1S SD card):
  RiparWallet_ALL_P1S.gcode.3mf   ONE plate: Front_Shell + Back_Shell + 2 fit-test coupons + 3 x Sign_Pin

The Bambu system presets inherit from base profiles that the CLI does not
resolve, so each chain (P1S 0.4 machine, 0.16mm Optimal process, Bambu PLA
filament) is flattened here, and the project settings are applied on top.
"""
import ast
import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STL = os.path.join(ROOT, "print", "stl")
OUT = os.path.join(ROOT, "print", "bambu")
BS = r"D:\Program Files\Bambu Studio\bambu-studio.exe"
PROF = r"D:\Program Files\Bambu Studio\resources\profiles\BBL"

MACHINE = "Bambu Lab P1S 0.4 nozzle"
PROCESS = "0.16mm Optimal @BBL X1C"          # the X1C processes are the P1S-compatible ones
FILAMENT = sys.argv[sys.argv.index("--filament") + 1] if "--filament" in sys.argv else "Bambu PLA Basic @BBL P1S 0.4 nozzle"

PROCESS_OVERRIDES = {
    "layer_height": "0.16",
    "wall_loops": "3",
    "sparse_infill_density": "15%",
    "sparse_infill_pattern": "gyroid",
    "enable_support": "0",
    "brim_type": "auto_brim",
    "seam_position": "back",
    "curr_bed_type": "Textured PEI Plate",
}

# explicit plate layout (min-corner X, Y in mm on the 256 x 256 P1S bed; the front-left
# 18 x 28 mm corner is excluded by the printer).  Auto-arrange packed the tiny pins
# 1 mm from the shells, where their brims would fuse onto the shell.
JOBS = {
    # everything on ONE plate: both shells (back row), both fit-test coupons + 3 SIGN pins (front row)
    "RiparWallet_ALL_P1S": [("Front_Shell.stl", 18, 150), ("Back_Shell.stl", 138, 150),
                            ("FitTest_Front.stl", 40, 50), ("FitTest_Back.stl", 90, 50),
                            ("Sign_Pin.stl", 150, 75), ("Sign_Pin.stl", 170, 75), ("Sign_Pin.stl", 190, 75)],
}


def place(job, items):
    """translated copies of the STLs so each part sits at its plate position"""
    import trimesh
    d = os.path.join(OUT, "_plate_" + job)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    out = []
    for k, (f, x, y) in enumerate(items):
        m = trimesh.load(os.path.join(STL, f))
        m.apply_translation([x - m.bounds[0][0], y - m.bounds[0][1], -m.bounds[0][2]])
        dst = os.path.join(d, "%02d_%s" % (k, f))
        m.export(dst)
        out.append(dst)
    return out


def index(cat):
    names = {}
    for f in os.listdir(os.path.join(PROF, cat)):
        if f.endswith(".json"):
            try:
                j = json.load(open(os.path.join(PROF, cat, f), encoding="utf-8"))
                names[j.get("name")] = os.path.join(PROF, cat, f)
            except Exception:
                pass
    return names


def flatten(cat, name, overrides=None):
    names = index(cat)
    chain = []
    n = name
    while n:
        path = names[n]
        j = json.load(open(path, encoding="utf-8"))
        chain.append(j)
        n = j.get("inherits")
    merged = {}
    for j in reversed(chain):                       # base first, leaf last
        for inc in (ast.literal_eval(j["include"]) if isinstance(j.get("include"), str) else j.get("include", [])):
            merged.update({k: v for k, v in json.load(open(names[inc], encoding="utf-8")).items()
                           if k not in ("name", "instantiation")})
        merged.update(j)
    merged["inherits"] = ""
    merged.pop("include", None)
    merged["name"] = name
    merged["from"] = "system"
    merged["instantiation"] = "true"
    if overrides:
        merged.update(overrides)
    dst = os.path.join(OUT, "_presets", "%s.json" % name.replace("@", "at").replace(" ", "_"))
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    json.dump(merged, open(dst, "w", encoding="utf-8"), indent=1)
    return dst


def slice_job(job, files, machine, process, filament):
    work = os.path.join(OUT, "_work_" + job)
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    args = [BS, "--debug", "2", "--orient", "0", "--arrange", "0",
            "--load-settings", machine + ";" + process, "--load-filaments", filament,
            "--curr-bed-type", "Textured PEI Plate",
            "--slice", "0", "--outputdir", work, "--export-3mf", job + ".gcode.3mf"]
    args += place(job, files)
    r = subprocess.run(args, capture_output=True, text=True, timeout=900)
    res = json.load(open(os.path.join(work, "result.json"), encoding="utf-8"))
    ok = res.get("return_code") == 0
    plate = res["sliced_plates"][0] if res.get("sliced_plates") else {}
    gfile = os.path.join(work, "plate_1.gcode")
    stats = {}
    if os.path.exists(gfile):
        with open(gfile, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if line.startswith("; total estimated time") or "; model printing time" in line:
                    stats["time"] = line.strip("; \n")
                elif line.startswith("; total filament weight"):
                    stats["weight_g"] = line.split(":")[-1].strip()
                elif line.startswith("; total filament length"):
                    stats["length_mm"] = line.split(":")[-1].strip()
                elif any(line.startswith("; " + k + " =") for k in
                         ("layer_height", "wall_loops", "sparse_infill_density", "curr_bed_type",
                          "printer_model", "filament_settings_id", "enable_support")):
                    k, v = line[2:].split("=", 1)
                    stats[k.strip()] = v.strip()
                if len(stats) >= 11:
                    break
    dst = os.path.join(OUT, job + ".gcode.3mf")
    if ok:
        shutil.copyfile(os.path.join(work, job + ".gcode.3mf"), dst)
        import zipfile
        with zipfile.ZipFile(dst) as z:                       # plate previews rendered by Bambu Studio
            open(os.path.join(OUT, job + "_plate.png"), "wb").write(z.read("Metadata/top_1.png"))
            open(os.path.join(OUT, job + "_preview.png"), "wb").write(z.read("Metadata/plate_1.png"))
    print("%-18s %s  %s" % (job, "OK" if ok else "FAILED: " + res.get("error_string", "?"), stats), flush=True)
    for o in plate.get("objects", []):
        print("    %-16s at (%.0f, %.0f) size %.1f x %.1f x %.1f" % (o["name"], o["bbox"]["x"], o["bbox"]["y"],
              o["bbox"]["width"], o["bbox"]["depth"], o["bbox"]["height"]), flush=True)
    return dict(job=job, ok=ok, stats=stats, file=dst if ok else None,
                warning=plate.get("warning_message", ""))


def main():
    os.makedirs(OUT, exist_ok=True)
    m = flatten("machine", MACHINE)
    p = flatten("process", PROCESS, PROCESS_OVERRIDES)
    f = flatten("filament", FILAMENT)
    report = [slice_job(j, files, m, p, f) for j, files in JOBS.items()]
    json.dump(report, open(os.path.join(OUT, "slice_report.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
