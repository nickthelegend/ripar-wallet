#!/usr/bin/env python3
"""Build and run the host unit tests (portable firmware modules, compiled with MinGW g++ as C++14).

    python test/host/run_host_tests.py               # all test/host/test_*.cpp
    python test/host/run_host_tests.py hashes cbor   # only tests whose name contains one of the words
    python test/host/run_host_tests.py -v            # also print the output of passing tests
    python test/host/run_host_tests.py --keep        # keep the build dir (exe files) for debugging
    python test/host/run_host_tests.py --werror      # treat compiler warnings as errors

Each test file must start with a dependency line naming the firmware sources to link:

    // DEPS: hashes util crypto
      -> src/hashes.cpp src/util.cpp src/crypto.cpp
    A token containing '/' or ending in .c/.cpp is a path relative to the firmware dir
    (e.g. lib/quirc/quirc.c); .c files are compiled as C with gcc.

Compile flags: -std=c++14 -O1 -Wall -I include -I test/host -DRIPAR_HOST_TEST=1 (+ static libgcc/libstdc++).
Every run builds into its own test/host/build/run-<pid>/ (deleted afterwards unless --keep), so several
agents can run the tests at the same time. Exit code 0 only if every test compiled and passed.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
FW = os.path.normpath(os.path.join(HERE, "..", ".."))
# PlatformIO's MinGW (pio pkg install -g -t platformio/toolchain-gccmingw32); override with RIPAR_HOST_TOOLBIN
TOOLBIN = os.environ.get("RIPAR_HOST_TOOLBIN") or os.path.join(
    os.environ.get("PLATFORMIO_CORE_DIR") or os.path.join(os.path.expanduser("~"), ".platformio"),
    "packages", "toolchain-gccmingw32", "bin")
CXX = os.path.join(TOOLBIN, "g++.exe")
CC = os.path.join(TOOLBIN, "gcc.exe")
DEPS_RE = re.compile(r"^\s*//\s*DEPS\s*:(.*)$")


def read_deps(path):
    """DEPS from the first line (also tolerated within the first 5 lines). None if missing."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= 5:
                break
            m = DEPS_RE.match(line)
            if m:
                return m.group(1).split()
    return None


def dep_path(tok):
    if "/" in tok or "\\" in tok or tok.endswith((".c", ".cpp", ".cc")):
        return os.path.normpath(os.path.join(FW, tok))
    return os.path.join(FW, "src", tok + ".cpp")


def run(cmd, timeout, env=None):
    try:
        p = subprocess.run(cmd, cwd=FW, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, env=env)
        return p.returncode, p.stdout.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode("utf-8", errors="replace")
        return None, out + "\n*** TIMEOUT after %ds" % timeout
    except OSError as e:
        return -1, "*** could not start %s: %s" % (cmd[0], e)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("filters", nargs="*", help="substrings of test names to run (default: all)")
    ap.add_argument("-v", "--verbose", action="store_true", help="print output of passing tests too")
    ap.add_argument("--keep", action="store_true", help="keep the build directory")
    ap.add_argument("--werror", action="store_true", help="add -Werror")
    ap.add_argument("--timeout", type=int, default=300, help="per-test run timeout in seconds")
    ap.add_argument("--cxx", default=CXX, help="C++ compiler (default: PlatformIO MinGW g++ 5.1)")
    args = ap.parse_args()

    tests = sorted(f for f in os.listdir(HERE) if f.startswith("test_") and f.endswith(".cpp"))
    if args.filters:
        tests = [t for t in tests if any(w in t for w in args.filters)]
    if not tests:
        print("no tests found in %s (filters: %s)" % (HERE, args.filters or "-"))
        return 1

    cxx = args.cxx
    cc = os.path.join(os.path.dirname(cxx), "gcc.exe") if os.path.isabs(cxx) else "gcc"
    if cxx == CXX and not os.path.exists(CC):
        cc = "gcc"
    build = os.path.join(HERE, "build", "run-%d" % os.getpid())
    os.makedirs(build, exist_ok=True)
    env = dict(os.environ)
    # MinGW runtime DLLs (in case something is not linked statically) + compiler helpers
    env["PATH"] = os.path.dirname(cxx) + os.pathsep + env.get("PATH", "")

    common = ["-O1", "-Wall", "-DRIPAR_HOST_TEST=1", "-I", os.path.join(FW, "include"), "-I", HERE]
    if args.werror:
        common.append("-Werror")

    results = []
    t_all = time.time()
    for t in tests:
        name = t[:-4]
        src = os.path.join(HERE, t)
        deps = read_deps(src)
        if deps is None:
            print("FAIL  %-28s missing '// DEPS: ...' first line" % name)
            results.append((name, False))
            continue
        paths = [dep_path(d) for d in deps]
        missing = [p for p in paths if not os.path.exists(p)]
        if missing:
            print("FAIL  %-28s missing dependency: %s" % (name, ", ".join(os.path.relpath(p, FW) for p in missing)))
            results.append((name, False))
            continue
        t0 = time.time()
        objs, log, ok = [], "", True
        for p in paths:
            if p.endswith(".c"):
                obj = os.path.join(build, name + "__" + os.path.basename(p) + ".o")
                rc, out = run([cc, "-std=gnu99", "-c", p, "-o", obj] + common, 600, env)
                log += out
                if rc != 0:
                    ok = False
                    break
                objs.append(obj)
        exe = os.path.join(build, name + ".exe")
        if ok:
            cpp = [src] + [p for p in paths if not p.endswith(".c")]
            cmd = [cxx, "-std=c++14"] + common + cpp + objs + ["-o", exe, "-static-libgcc", "-static-libstdc++"]
            rc, out = run(cmd, 600, env)
            log += out
            ok = rc == 0
        if not ok:
            print("FAIL  %-28s (compile)" % name)
            print(indent(log))
            results.append((name, False))
            continue
        warn = log.count("warning:")
        rc, out = run([exe], args.timeout, env)
        dt = time.time() - t0
        passed = rc == 0
        last = out.strip().splitlines()[-1] if out.strip() else "(no output)"
        print("%s  %-28s %5.1fs  %s%s" % ("PASS" if passed else "FAIL", name, dt, last,
                                          ("  [%d compiler warnings]" % warn) if warn else ""))
        if not passed:
            if rc is None:
                pass
            elif rc != 1:
                out += "\n*** exit code %d / 0x%08X (crash / abort? 0xC0000005 = access violation)" % (
                    rc if rc < 2**31 else rc - 2**32, rc & 0xFFFFFFFF)
            print(indent(out))
        elif args.verbose:
            print(indent(out))
        if warn and (args.verbose or not passed):
            print(indent(log))
        results.append((name, passed))

    if not args.keep:
        shutil.rmtree(build, ignore_errors=True)
        try:
            os.rmdir(os.path.join(HERE, "build"))  # only if empty (another run may be using it)
        except OSError:
            pass
    else:
        print("build dir kept:", build)
    npass = sum(1 for _, p in results if p)
    print("== host tests: %d/%d passed in %.1fs -> %s" % (npass, len(results), time.time() - t_all,
                                                        "PASS" if npass == len(results) else "FAIL"))
    return 0 if npass == len(results) else 1


def indent(s):
    return "\n".join("      " + l for l in s.rstrip().splitlines())


if __name__ == "__main__":
    sys.exit(main())
