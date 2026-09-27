#!/usr/bin/env python3
"""Test oracle for @ripar/protocol: runs firmware/tools/make_request.py (and ref_ur.py) IN-PROCESS and prints JSON.
Read-only with respect to firmware/: run it with `python -B` (no __pycache__ is written).

    python -B oracle.py <command> < input.json > output.json

Commands: demo | official | corpus | simulate | parse | privy | format_units | caveat_dump
Encoding of values in the JSON output: bytes -> "0x.." hex; integers with |v| >= 2^53 -> decimal strings.
"""
import json
import os
import random
import sys

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.environ.get("RIPAR_FW_TOOLS") or os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", "firmware", "tools"))
sys.path.insert(0, TOOLS)
import make_request as MR  # noqa: E402
import ref_ur as U  # noqa: E402

BIG = 1 << 53


def js(v):
    """Python value -> JSON-able value (bytes hex, big ints as strings, Tag as {"$tag", "value"})"""
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, int):
        return v if -BIG < v < BIG else str(v)
    if isinstance(v, (bytes, bytearray)):
        return "0x" + bytes(v).hex()
    if isinstance(v, str):
        return v
    if isinstance(v, (list, tuple)):
        return [js(x) for x in v]
    if isinstance(v, dict):
        return {str(k): js(x) for k, x in v.items()}
    if isinstance(v, U.Tag):
        return {"$tag": v.tag, "value": js(v.value)}
    raise TypeError(type(v))


def unjs_bytes(s):
    return MR.unhex(s)


def report_json(rep):
    return {"fields": js(rep.fields), "checks": [[n, ok] for n, ok in rep.checks], "unverified": rep.unverified,
            "ok": rep.ok()}


def rb(rng, n):
    return bytes(rng.getrandbits(8) for _ in range(n))


# ------------------------------------------------------------------------------------------------ commands
def cmd_demo(_inp):
    k = MR.demo_keys()
    return {"k1": MR.eip55("0x" + k["k1addr"].hex()), "p1": js(k["p1xy"]), "k1Priv": js(MR.rc.i2b(k["k1"])),
            "p1Priv": js(MR.rc.i2b(k["p1"]))}


def cmd_official(_inp):
    O = U.OFFICIAL
    out = {k: js(v) for k, v in O.items()}
    out["sampler"] = U.OFFICIAL_SAMPLER
    msg1024 = U.make_message(1024)
    out["msg1024"] = js(msg1024)
    out["wolf256cbor"] = js(U.make_message_ur_cbor(256))
    out["wolf50cbor"] = js(U.make_message_ur_cbor(50))
    # a protocol-like stream message and mixed parts until an optimal decoder completes (ref_ur gen_cpp)
    sm = U.gen_stream_message(700)
    enc = U.FountainEncoder(sm, 67)
    seqs = list(range(enc.seq_len + 1, enc.seq_len + 201))
    done = U.gf2_complete_at([enc.indexes(s) for s in seqs], enc.seq_len)
    out["stream"] = {"msg": js(sm), "seqLen": enc.seq_len, "fragLen": enc.frag_len, "crc": enc.checksum,
                     "mixed": [U.ur_part("ripar-cosign-req", enc, s).upper() for s in seqs[:done]],
                     "mixedIdx": [enc.indexes(s) for s in seqs[:done]],
                     "pure": [U.ur_part("ripar-cosign-req", enc, s).upper() for s in range(1, enc.seq_len + 1)]}
    return out


def _clean_fields(f):
    f = dict(f)
    f.pop("_ctx", None)
    return f


def _entry(kind, f, rng, keys, p1xy, k1addr, note):
    m = MR.BUILDERS[kind](f)
    cb = U.cbor(m)
    t = MR.REQ_TYPES[kind]
    e = {"kind": kind, "note": note, "fields": js(_clean_fields(f)), "cbor": js(cb), "ur": MR.ur_single(t, cb),
         "parts": MR.ur_parts(t, cb, 70), "parts40x3": MR.ur_parts(t, cb, 40, 3)}
    q = MR.read_fields(kind, MR.cbor_decode(cb))
    e["guessKind"] = MR.guess_kind(MR.cbor_decode(cb))  # make_request's kind of bare CBOR hex (a pair with key 11 reads as cosign)
    ev, salt = rb(rng, 12), rb(rng, 16)
    e["ev12"], e["salt16"] = js(ev), js(salt)
    if kind == "cosign":
        try:
            e["tokenCheck"] = js(list(MR.token_check(q)))
        except MR.ProtoError as ex:
            e["tokenCheck"] = {"error": str(ex)}
        kd, frm, to, amt = MR.decode_erc20(q["calldata"])
        e["erc20"] = {"kind": kd, "num": MR.KIND_NUM[kd], "from": js(frm), "to": js(to), "amount": js(amt)}
        e["aiMatches"] = MR.ai_matches(q)
        e["requestHash"] = js(MR.cosign_request_hash(q))
        e["callDataHash"] = js(MR.keccak256(q["calldata"]))
        e["presenceHash"] = js(MR.presence_hash(ev, salt))
        e["digest"] = js(MR.cosign_digest(q, MR.presence_hash(ev, salt)))
    if kind == "mandate":
        e["delegationHash"] = js(MR.delegation_struct_hash(q))
        e["digest"] = js(MR.mandate_digest(q))
    if kind == "deny":
        e["digest"] = js(MR.deny_digest(q, MR.presence_hash(ev, salt)))
    if kind == "pair":
        e["digest"] = js(MR.pair_digest(q["chainId"], q["registry"], keys["k1addr"], keys["p1xy"]))
    try:
        resp = MR.simulate(kind, q, keys, ev12=ev, salt16=salt, fwid=rb(rng, 8) if kind == "pair" else None)
    except MR.ProtoError as ex:
        e["simulateError"] = str(ex)
        return e
    rt = MR.RESP_TYPES[kind]
    rur = MR.ur_single(rt, resp)
    e["response"] = js(resp)
    e["responseUr"] = rur
    e["report"] = report_json(MR.parse_response(rur, (kind, cb), p1xy=p1xy, k1addr=k1addr))
    return e


def cmd_corpus(inp):
    seed = int(inp.get("seed", 20260927)) if isinstance(inp, dict) else 20260927
    rng = random.Random(seed)
    keys = MR.demo_keys()
    p1xy, k1addr = keys["p1xy"], keys["k1addr"]
    out = []
    for v in range(19):  # firmware v1.2: 19 variants (18 = MockUSD from the token table)
        out.append(_entry("cosign", MR._mk_cosign(rng, v), rng, keys, p1xy, k1addr, "cosign variant %d" % v))
    for v in range(6):
        f = MR._mk_mandate(rng, v, p1xy)
        e = _entry("mandate", f, rng, keys, p1xy, k1addr, "mandate variant %d" % v)
        if "_ctx" in f:
            cx = f["_ctx"]
            q = MR.read_fields("mandate", MR.cbor_decode(MR.unhex(e["cbor"])))
            e["ctx"] = js(cx)
            e["dumps"] = [MR.caveat_dump(q["chainId"], en, t, q["chainId"], cx["pulse"]) for en, t in q["caveats"]]
        out.append(e)
    for v in range(3):
        out.append(_entry("deny", MR._mk_deny(rng, v), rng, keys, p1xy, k1addr, "deny variant %d" % v))
    # pair: make_request gen-vectors' variants (firmware v1.2: the compiled-in contracts, the derived vault), then the
    # refusals of firmware_refusal (another registry / enforcer / relay / key-8 vault, a chain outside the table)
    for v in range(4):
        chain = [10143, 1, 143, 10143][v]
        reg = MR.RIPAR_REGISTRY[chain] if chain in MR.RIPAR_REGISTRY else MR.raddr(rng)
        f = {"reqId": rb(rng, 16), "chainId": chain, "registry": reg, "uuidTag": v == 1}
        if v == 0:
            f.update(manager=MR.DELEGATION_MANAGER, enforcer=MR.PULSE_ENFORCER, sentinel=MR.raddr(rng),
                     relay=MR.RIPAR_RELAY[10143], vault=keys["vault"], now=1790500000, minEpoch=12, reopenNonce=3)
        if v == 2:
            f.update(manager=MR.DELEGATION_MANAGER, enforcer=MR.PULSE_ENFORCER, now=(1 << 40) - 1,
                     minEpoch=(1 << 63) - 1, reopenNonce=(1 << 63) - 1)
        if v == 3:
            f.update(now=1790500000)
        out.append(_entry("pair", f, rng, keys, p1xy, k1addr, "pair variant %d" % v))
    for name, extra in (("another registry", {"registry": MR.raddr(rng)}), ("another enforcer", {"enforcer": MR.raddr(rng)}),
                        ("another relay", {"relay": MR.raddr(rng)}), ("another key-8 vault", {"vault": MR.raddr(rng)}),
                        ("another manager", {"manager": MR.raddr(rng)})):
        f = dict({"reqId": rb(rng, 16), "chainId": 10143, "registry": MR.RIPAR_REGISTRY[10143], "now": 1790500000}, **extra)
        out.append(_entry("pair", f, rng, keys, p1xy, k1addr, "pair refused: " + name))
    for name, kind, f in (
            ("cosign for another vault", "cosign", dict(MR._mk_cosign(rng, 1), delegator=MR.raddr(rng))),
            ("cosign for another enforcer", "cosign", dict(MR._mk_cosign(rng, 1), enforcer=MR.raddr(rng))),
            ("mandate for another vault", "mandate", dict(MR._mk_mandate(rng, 1), delegator=MR.raddr(rng))),
            ("mandate for another manager", "mandate", dict(MR._mk_mandate(rng, 1), manager=MR.raddr(rng))),
            ("deny to another relay", "deny", dict(MR._mk_deny(rng, 0), relay=MR.raddr(rng)))):
        out.append(_entry(kind, f, rng, keys, p1xy, k1addr, "refused: " + name))
    for name, jsb in MR.privy_valid():
        e = _entry("privy", {"reqId": rb(rng, 16), "json": jsb}, rng, keys, p1xy, k1addr, "privy " + name)
        out.append(e)
    # deny responses built by the device from co-sign reviews (MINOR 7)
    dfc = []
    for e in out:
        if e["kind"] == "cosign" and "response" in e:
            q = MR.read_fields("cosign", MR.cbor_decode(MR.unhex(e["cbor"])))
            relay, agent, salt = MR.raddr(rng), rng.choice([0, 7, (1 << 64) - 1]), rb(rng, 16)
            resp = MR.simulate_deny_from_cosign(q, keys, 10143, relay, agent, salt16=salt)
            dfc.append({"cosign": e["cbor"], "relay": js(relay), "agentId": js(agent), "salt16": js(salt),
                        "response": js(resp), "responseUr": MR.ur_single("ripar-deny", resp),
                        "report": report_json(MR.parse_response(MR.ur_single("ripar-deny", resp),
                                                                ("cosign", MR.unhex(e["cbor"])), p1xy=p1xy,
                                                                contract=relay))})
            if len(dfc) >= 6:
                break
    # device-initiated messages
    dev = []
    for i in range(12):
        chain, contract = [10143, 143, (1 << 64) - 1][i % 3], MR.raddr(rng)
        if i % 3 == 0:
            dh = rb(rng, 32)
            rs = MR.sign_p1(keys, MR.revoke_digest(chain, contract, dh))
            ut, payload = "ripar-revoke", {1: dh, 2: rs}
        elif i % 3 == 1:
            me = rng.choice([0, 1, 23, 24, 255, 256, 65535, 65536, (1 << 32) - 1, 1 << 32, (1 << 64) - 1])
            rs = MR.sign_p1(keys, MR.panic_digest(chain, contract, me))
            ut, payload = "ripar-panic", {1: me, 2: rs}
        else:
            vault, nonce = MR.raddr(rng), rng.choice([0, 1, 255, 256, rng.getrandbits(100), MR.MAX256, 1 << 248])
            rs = MR.sign_p1(keys, MR.reopen_digest(chain, contract, vault, nonce))
            ut, payload = "ripar-reopen", {1: vault, 2: MR.u256_min(nonce), 3: rs}
        cb = U.cbor(payload)
        ur = MR.ur_single(ut, cb)
        dev.append({"type": ut, "chainId": js(chain), "contract": js(contract), "cbor": js(cb), "ur": ur,
                    "report": report_json(MR.parse_response(ur, None, p1xy=p1xy, chain=chain, contract=contract))})
    return {"entries": out, "denyFromCosign": dfc, "deviceInitiated": dev, "p1": js(p1xy), "k1": js(k1addr)}


def cmd_simulate(inp):
    keys = MR.demo_keys()
    out = []
    for it in inp:
        cb = MR.unhex(it["cbor"])
        kind = it["kind"]
        q = MR.read_fields(kind, MR.cbor_decode(cb))
        try:
            resp = MR.simulate(kind, q, keys, ev12=MR.unhex(it["ev12"]) if it.get("ev12") else None,
                               salt16=MR.unhex(it["salt16"]) if it.get("salt16") else bytes(16),
                               fwid=MR.unhex(it["fwid"]) if it.get("fwid") else None)
        except MR.ProtoError as ex:
            out.append({"error": str(ex)})
            continue
        out.append({"response": js(resp), "ur": MR.ur_single(MR.RESP_TYPES[kind], resp)})
    return out


def cmd_parse(inp):
    out = []
    for it in inp:
        req = None
        if it.get("req"):
            req = (it["req"]["kind"], MR.unhex(it["req"]["cbor"]))
        try:
            rep = MR.parse_response(it["response"], req,
                                    p1xy=MR.unhex(it["p1"]) if it.get("p1") else None,
                                    k1addr=MR.unhex(it["k1"]) if it.get("k1") else None,
                                    chain=int(it["chain"]) if it.get("chain") is not None else None,
                                    contract=MR.unhex(it["contract"]) if it.get("contract") else None)
            out.append(report_json(rep))
        except (MR.ProtoError, ValueError, KeyError, TypeError) as ex:
            out.append({"error": "%s: %s" % (type(ex).__name__, ex)})
    return out


def cmd_privy(inp):
    valid = []
    for name, jsb in MR.privy_valid():
        v = MR.privy_parse(jsb)
        valid.append({"name": name, "json": js(jsb), "dump": MR.privy_dump(v), "path": v["path"], "kind": v["kind"]})
    invalid = [{"name": n, "json": js(j), "syntax": MR._json_syntax_invalid(j)} for n, j in MR.PRIVY_INVALID]
    return {"valid": valid, "invalid": invalid,
            "jsonValid": [js(j) for j in MR.JSON_VALID_EXTRA],
            "jsonInvalid": [js(j) for j in MR.JSON_INVALID_EXTRA],
            "canonical": [{"obj": o, "bytes": js(MR.canonical_json(o))} for o in (inp or [])]}


def cmd_format_units(inp):
    return [MR.E.format_units(int(v), int(d), int(m)) for v, d, m in inp]


def cmd_caveat_dump(inp):
    return [MR.caveat_dump(int(c["chain"]), MR.unhex(c["enforcer"]), MR.unhex(c["terms"]), int(c["pulseChain"]),
                           MR.unhex(c["pulseEnforcer"])) for c in inp]


COMMANDS = {"demo": cmd_demo, "official": cmd_official, "corpus": cmd_corpus, "simulate": cmd_simulate,
            "parse": cmd_parse, "privy": cmd_privy, "format_units": cmd_format_units, "caveat_dump": cmd_caveat_dump}

if __name__ == "__main__":
    raw = sys.stdin.buffer.read().decode("utf-8")
    data = json.loads(raw) if raw.strip() else None
    json.dump(COMMANDS[sys.argv[1]](data), sys.stdout)
