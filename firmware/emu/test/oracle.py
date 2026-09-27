#!/usr/bin/env python3
"""Reference oracle for the emulator tests (emu/test/run_tests.mjs). Python 3 stdlib only.

Everything here is the companion-side tool firmware/tools/make_request.py, independent of the C++ firmware:

  python emu/test/oracle.py build   < specs.json   -> requests, built by `make_request.py build ... --json`
  python emu/test/oracle.py verify  < jobs.json    -> for every emulator response:
        parseExit        exit code of `make_request.py parse <resp> [--req] [--pair] [--chain] [--contract]`, run as
                         a real subprocess (0 = every signature verified)
        identical        the response is byte-identical to what make_request.py's demo device (`simulate()`, same
                         request, same seed) builds with the salt / evidence / firmware id the emulator used
                         (simulate() takes them as arguments; the `simulate` CLI draws a random salt and a fixed demo
                         evidence + firmware id, so only salt-free responses can be compared with the CLI itself)
        cliIdentical     mandate / privy only: byte-identical to the stdout of `make_request.py simulate <req>`

build specs: [{"name", "kind", "fields": {...}, "reqid": hex32}] (a field value "$dh:<name>" = the delegation hash of
the mandate built under <name> earlier in the same batch). Output: {"<name>": {type, reqId, cbor, ur, parts}}.

verify jobs: [{"name", "kind", "resp", "req"?, "pair"?, "chain"?, "contract"?, "relay"?, "agentId"?,
"delegationHash"?, "epoch"?, "vault"?, "nonce"?}] with kind one of pair, pair-keys, cosign, deny, deny-from-cosign,
mandate, privy, revoke, panic, reopen.
"""
import contextlib
import io
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FW = os.path.normpath(os.path.join(HERE, "..", ".."))
MR_PATH = os.path.join(FW, "tools", "make_request.py")
sys.path.insert(0, os.path.join(FW, "tools"))
import make_request as mr  # noqa: E402

U = mr.U


def run_cli(args):
    p = subprocess.run([sys.executable, MR_PATH] + args, cwd=FW, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=120)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def build(specs):
    out = {}
    for sp in specs:
        fields = dict(sp.get("fields", {}))
        for k, v in list(fields.items()):
            if isinstance(v, str) and v.startswith("$dh:"):
                ref = out[v[4:]]
                q = mr.read_fields("mandate", mr.cbor_decode(bytes.fromhex(ref["cbor"])))
                fields[k] = "0x" + mr.delegation_struct_hash(q).hex()
        argv = ["make_request.py", "build", sp["kind"], json.dumps(fields), "--json"]
        if sp.get("reqid"):
            argv += ["--reqid", sp["reqid"]]
        if sp.get("frag"):
            argv += ["--frag", str(sp["frag"])]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = mr._main(argv)  # the CLI entry point of make_request.py
        if rc != 0:
            raise SystemExit("build %s failed (%d)" % (sp["name"], rc))
        out[sp["name"]] = json.loads(buf.getvalue())
    return out


def req_q(req_ur):
    kind, cb = mr.read_request(req_ur)
    return kind, mr.read_fields(kind, mr.cbor_decode(cb))


def expected(job, keys):
    kind = job["kind"]
    utype, cb = mr.ur_read(job["resp"])
    m = mr.cbor_decode(cb)
    if kind == "pair":
        _, q = req_q(job["req"])
        return "ripar-pair", mr.simulate("pair", q, keys, fwid=m[6])
    if kind == "pair-keys":  # the unsigned keys-only pairing QR of the HOME screen
        return "ripar-pair", U.cbor({2: keys["k1addr"], 3: keys["p1xy"], 6: m[6]})
    if kind in ("cosign", "deny"):
        _, q = req_q(job["req"])
        return ("ripar-cosign" if kind == "cosign" else "ripar-deny"), mr.simulate(kind, q, keys, ev12=m[3], salt16=m[4])
    if kind == "deny-from-cosign":
        _, q = req_q(job["req"])
        return "ripar-deny", mr.simulate_deny_from_cosign(q, keys, job["chain"], bytes.fromhex(job["relay"][2:]),
                                                         int(job["agentId"]), ev12=m[3], salt16=m[4])
    if kind in ("mandate", "privy"):
        _, q = req_q(job["req"])
        return mr.RESP_TYPES[kind], mr.simulate(kind, q, keys)
    contract = bytes.fromhex(job["contract"][2:])
    if kind == "revoke":
        dh = bytes.fromhex(job["delegationHash"][2:])
        return "ripar-revoke", U.cbor({1: dh, 2: mr.sign_p1(keys, mr.revoke_digest(job["chain"], contract, dh))})
    if kind == "panic":
        e = int(job["epoch"])
        return "ripar-panic", U.cbor({1: e, 2: mr.sign_p1(keys, mr.panic_digest(job["chain"], contract, e))})
    if kind == "reopen":
        vault, n = bytes.fromhex(job["vault"][2:]), int(job["nonce"])
        return "ripar-reopen", U.cbor({1: vault, 2: mr.u256_min(n),
                                       3: mr.sign_p1(keys, mr.reopen_digest(job["chain"], contract, vault, n))})
    raise SystemExit("unknown job kind " + kind)


def verify(jobs):
    keys = mr.demo_keys()
    results = []
    for job in jobs:
        r = {"name": job["name"]}
        args = ["parse", job["resp"]]
        if job.get("req"):
            args += ["--req", job["req"]]
        if job.get("pair"):
            args += ["--pair", job["pair"]]
        if job.get("chain") is not None and job["kind"] in ("revoke", "panic", "reopen", "deny-from-cosign"):
            args += ["--chain", str(job["chain"])]
        if job.get("contract"):
            args += ["--contract", job["contract"]]
        rc, so, se = run_cli(args)
        r["parseExit"] = rc
        try:
            rep = json.loads(so)
            r["parseResult"] = rep.get("result")
            r["parseFields"] = {k: rep[k] for k in ("delegationHash", "digest", "presenceHash", "signer", "minEpoch",
                                                   "nonce", "firmwareId", "k1Address", "salt16", "evidence12",
                                                   "evidence") if k in rep}
        except ValueError:
            r["parseResult"] = None
            r["parseError"] = (se or so)[-400:]
        try:
            utype, cb = expected(job, keys)
            want = mr.ur_single(utype, cb)
            r["expectedUr"] = want
            r["identical"] = want == job["resp"].strip().upper()
        except Exception as e:  # noqa: BLE001 - reported to the test
            r["identical"] = False
            r["expectError"] = "%s: %s" % (type(e).__name__, e)
        if job["kind"] in ("mandate", "privy"):
            rc2, so2, se2 = run_cli(["simulate", job["req"]])
            r["cliIdentical"] = rc2 == 0 and so2.strip() == job["resp"].strip().upper()
        results.append(r)
    return results


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("build", "verify"):
        print(__doc__)
        return 2
    data = json.load(sys.stdin)
    out = build(data) if sys.argv[1] == "build" else verify(data)
    sys.stdout.write(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
