#!/usr/bin/env python3
"""EIP-712 / ERC-20 ABI reference for Ripar Wallet host tests (pure Python 3, stdlib only).

Independent of the C++ firmware: a *generic* EIP-712 encoder (encodeType with dependency discovery, encodeData
for atomic / dynamic / array / struct members) driven by field lists, plus a direct port of MetaMask
delegation-framework EncoderLib for the Delegation hash. keccak comes from tools/ref_hashes.py.

    python tools/ref_eip712.py              self-test (EIP-712 spec Mail example, PROTOCOL.md type strings,
                                            MetaMask typehashes, generic == EncoderLib, ABI/format checks)
    python tools/ref_eip712.py gen          (re)write test/host/vectors_eip712_abi.h (deterministic, seed 712)
    python tools/ref_eip712.py check        fail if test/host/vectors_eip712_abi.h is not what `gen` would write
    python tools/ref_eip712.py typed F.json digest/domain/struct hash of an eth_signTypedData_v4 JSON document
                                            (addresses/bytes as hex strings, integers as numbers or "0x.."/decimal)

Import:
    import sys; sys.path.insert(0, r"E:/Projects/ripar-wallet/firmware/tools")
    import ref_eip712 as E
    E.digest(E.domain_ripar("RiparPulseCosign", 10143, enforcer), "HumanApproval", msg)
"""
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ref_hashes import keccak256, eip55, h, unhex, EIP55_VECTORS  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FW = os.path.normpath(os.path.join(HERE, ".."))
VEC_PATH = os.path.join(FW, "test", "host", "vectors_eip712_abi.h")
PROTOCOL_MD = os.path.normpath(os.path.join(FW, "..", "docs", "PROTOCOL.md"))

MAX256 = (1 << 256) - 1
MAX64 = (1 << 64) - 1
ROOT_AUTHORITY = b"\xff" * 32

# ------------------------------------------------------------------ generic EIP-712 (spec)
DOMAIN_FIELDS = [("name", "string"), ("version", "string"), ("chainId", "uint256"), ("verifyingContract", "address")]

RIPAR_TYPES = {
    "EIP712Domain": DOMAIN_FIELDS,
    "Delegation": [("delegate", "address"), ("delegator", "address"), ("authority", "bytes32"),
                   ("caveats", "Caveat[]"), ("salt", "uint256")],
    "Caveat": [("enforcer", "address"), ("terms", "bytes")],
    "HumanApproval": [("delegationHash", "bytes32"), ("delegator", "address"), ("redeemer", "address"),
                      ("target", "address"), ("value", "uint256"), ("callDataHash", "bytes32"),
                      ("nonce", "uint256"), ("expiry", "uint64"), ("presenceHash", "bytes32")],
    "Revoke": [("delegationHash", "bytes32")],
    "Panic": [("minEpoch", "uint64")],
    "Reopen": [("vault", "address"), ("nonce", "uint256")],
    "Deny": [("agentId", "uint256"), ("requestHash", "bytes32"), ("presenceHash", "bytes32")],
    "BindDevice": [("owner", "address"), ("px", "bytes32"), ("py", "bytes32")],
}

# Byte-exact copy of docs/PROTOCOL.md section 3 (the self-test also compares against the file itself).
PROTOCOL_TYPE_STRINGS = [
    "Delegation(address delegate,address delegator,bytes32 authority,Caveat[] caveats,uint256 salt)"
    "Caveat(address enforcer,bytes terms)",
    "Caveat(address enforcer,bytes terms)",
    "HumanApproval(bytes32 delegationHash,address delegator,address redeemer,address target,uint256 value,"
    "bytes32 callDataHash,uint256 nonce,uint64 expiry,bytes32 presenceHash)",
    "Revoke(bytes32 delegationHash)",
    "Panic(uint64 minEpoch)",
    "Reopen(address vault,uint256 nonce)",
    "Deny(uint256 agentId,bytes32 requestHash,bytes32 presenceHash)",
    "BindDevice(address owner,bytes32 px,bytes32 py)",
]

# PROTOCOL.md section 3 domain table: struct -> domain name (version is always "1")
DOMAIN_OF = {
    "Delegation": "DelegationManager",
    "HumanApproval": "RiparPulseCosign",
    "Revoke": "RiparPulseCosign",
    "Panic": "RiparPulseCosign",
    "Reopen": "RiparSentinel",
    "Deny": "RiparReputationRelay",
    "BindDevice": "RiparDeviceRegistry",
}

# MetaMask delegation-framework src/utils/Constants.sol: keccak256 of the strings above (hex computed with
# ref_hashes.keccak256; the framework source defines them only as keccak256("...") expressions).
DELEGATION_TYPEHASH = "88c1d2ecf185adf710588203a5f263f0ff61be0d33da39792cde19ba9aa4331e"
CAVEAT_TYPEHASH = "80ad7e1b04ee6d994a125f4714ca0720908bd80ed16063ec8aee4b88e9253e2d"
EIP712_DOMAIN_TYPEHASH = "8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f"


def _base(t):
    return t[:t.index("[")] if "[" in t else t


def find_deps(primary, types, found=None):
    found = [] if found is None else found
    if primary in found or primary not in types:
        return found
    found.append(primary)
    for _, t in types[primary]:
        find_deps(_base(t), types, found)
    return found


def encode_type(primary, types):
    deps = find_deps(primary, types)
    deps = [primary] + sorted(d for d in deps if d != primary)
    return "".join("%s(%s)" % (d, ",".join("%s %s" % (t, n) for n, t in types[d])) for d in deps)


def type_hash(primary, types):
    return keccak256(encode_type(primary, types).encode())


def _to_int(v):
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        return int(v, 16) if v[:2] in ("0x", "0X") else int(v, 10)
    if isinstance(v, (bytes, bytearray)):
        return int.from_bytes(bytes(v), "big")
    raise TypeError("not an integer: %r" % (v,))


def _to_bytes(v):
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, str):
        return unhex(v)
    raise TypeError("not bytes: %r" % (v,))


def encode_value(t, v, types):
    if t in types:
        return hash_struct(t, v, types)
    if t.endswith("]"):
        inner = t[:t.rindex("[")]
        return keccak256(b"".join(encode_value(inner, x, types) for x in v))
    if t == "string":
        return keccak256(v.encode("utf-8") if isinstance(v, str) else bytes(v))
    if t == "bytes":
        return keccak256(_to_bytes(v))
    if t == "address":
        a = _to_bytes(v)
        assert len(a) == 20, "address must be 20 bytes"
        return b"\x00" * 12 + a
    if t == "bool":
        return (1 if v else 0).to_bytes(32, "big")
    if t.startswith("uint"):
        bits = int(t[4:] or 256)
        x = _to_int(v)
        assert 0 <= x < (1 << bits), "%s out of range" % t
        return x.to_bytes(32, "big")
    if t.startswith("int"):
        bits = int(t[3:] or 256)
        x = _to_int(v)
        assert -(1 << (bits - 1)) <= x < (1 << (bits - 1)), "%s out of range" % t
        return (x % (1 << 256)).to_bytes(32, "big")
    if t.startswith("bytes"):
        n = int(t[5:])
        b = _to_bytes(v)
        assert 1 <= n <= 32 and len(b) == n, "%s needs %d bytes" % (t, n)
        return b + b"\x00" * (32 - n)
    raise ValueError("unsupported type " + t)


def encode_data(primary, data, types):
    return type_hash(primary, types) + b"".join(encode_value(t, data[n], types) for n, t in types[primary])


def hash_struct(primary, data, types=RIPAR_TYPES):
    return keccak256(encode_data(primary, data, types))


def domain_separator(domain, types=None):
    fields = (types or {}).get("EIP712Domain") or [f for f in DOMAIN_FIELDS if f[0] in domain]
    return hash_struct("EIP712Domain", domain, {"EIP712Domain": fields})


def digest_from(domain_sep, struct_hash):
    return keccak256(b"\x19\x01" + domain_sep + struct_hash)


def digest(domain, primary, message, types=RIPAR_TYPES):
    return digest_from(domain_separator(domain, types), hash_struct(primary, message, types))


def domain_ripar(name, chain_id, contract, version="1"):
    return {"name": name, "version": version, "chainId": chain_id, "verifyingContract": contract}


# ------------------------------------------------------------------ MetaMask EncoderLib port
def _abi_word_addr(a):
    return b"\x00" * 12 + _to_bytes(a)


def mm_caveat_hash(enforcer, terms):
    """EncoderLib._getCaveatPacketHash: keccak256(abi.encode(CAVEAT_TYPEHASH, enforcer, keccak256(terms)))"""
    return keccak256(unhex(CAVEAT_TYPEHASH) + _abi_word_addr(enforcer) + keccak256(_to_bytes(terms)))


def mm_delegation_hash(delegate, delegator, authority, caveats, salt):
    """EncoderLib._getDelegationHash with _getCaveatArrayPacketHash = keccak256(abi.encodePacked(bytes32[]))"""
    arr = keccak256(b"".join(mm_caveat_hash(e, t) for e, t in caveats))
    return keccak256(unhex(DELEGATION_TYPEHASH) + _abi_word_addr(delegate) + _abi_word_addr(delegator) +
                     _to_bytes(authority) + arr + _to_int(salt).to_bytes(32, "big"))


# ------------------------------------------------------------------ ERC-20 ABI + formatting reference
SEL = {"transfer": bytes.fromhex("a9059cbb"), "approve": bytes.fromhex("095ea7b3"),
       "transferFrom": bytes.fromhex("23b872dd")}
SIG = {"transfer": "transfer(address,uint256)", "approve": "approve(address,uint256)",
       "transferFrom": "transferFrom(address,address,uint256)"}


def calldata(kind, *args):
    """ABI-encode transfer(to, amt) / approve(spender, amt) / transferFrom(from, to, amt)."""
    words = [(_abi_word_addr(a) if isinstance(a, (bytes, bytearray)) and len(a) == 20 else _to_int(a).to_bytes(32, "big"))
             for a in args]
    return SEL[kind] + b"".join(words)


def format_units(v, decimals, max_frac=6):
    """Reference for abi.cpp format_units (integer arithmetic, independent of the C++ string walk)."""
    decimals = max(0, decimals)
    max_frac = max(0, max_frac)
    ip, fp = divmod(v, 10 ** decimals)
    frac = str(fp).rjust(decimals, "0") if decimals else ""
    keep, dropped = frac[:max_frac], frac[max_frac:]
    s = "{:,}".format(ip)
    if dropped.strip("0"):
        return s + ("." + keep if keep else "") + "..."
    keep = keep.rstrip("0")
    return s + ("." + keep if keep else "")


def fingerprint(addr):
    """4 icon indexes 0..255 = keccak256(address)[0..3] (32 bits)."""
    d = keccak256(_to_bytes(addr))
    return [d[0], d[1], d[2], d[3]]


# ------------------------------------------------------------------ self-test
MAIL_TYPES = {
    "EIP712Domain": DOMAIN_FIELDS,
    "Person": [("name", "string"), ("wallet", "address")],
    "Mail": [("from", "Person"), ("to", "Person"), ("contents", "string")],
}
MAIL_DOMAIN = domain_ripar("Ether Mail", 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
MAIL_MSG = {"from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
            "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
            "contents": "Hello, Bob!"}
# EIP-712 spec, assets/eip-712/Example.js
MAIL_EXPECT = {
    "encodeType": "Mail(Person from,Person to,string contents)Person(string name,address wallet)",
    "typeHash": "a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2",
    "structHash": "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e",
    "domain": "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f",
    "digest": "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2",
}


def protocol_md_type_strings():
    """The fenced type-string block of docs/PROTOCOL.md section 3 (None if the file is missing)."""
    if not os.path.exists(PROTOCOL_MD):
        return None
    with open(PROTOCOL_MD, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.startswith("Delegation(address delegate"))
    except StopIteration:
        return []
    out = []
    for l in lines[start:]:
        if l.startswith("```"):
            break
        out.append(l)
    return out


def selftest(verbose=True):
    bad = [0]

    def ok(cond, what):
        if not cond:
            bad[0] += 1
            print("FAIL", what)
        elif verbose:
            print("ok  ", what)

    # EIP-712 spec example
    ok(encode_type("Mail", MAIL_TYPES) == MAIL_EXPECT["encodeType"], "Mail encodeType")
    ok(h(type_hash("Mail", MAIL_TYPES)) == MAIL_EXPECT["typeHash"], "Mail typeHash")
    ok(h(hash_struct("Mail", MAIL_MSG, MAIL_TYPES)) == MAIL_EXPECT["structHash"], "Mail hashStruct")
    ok(h(domain_separator(MAIL_DOMAIN)) == MAIL_EXPECT["domain"], "Mail domain separator")
    ok(h(digest(MAIL_DOMAIN, "Mail", MAIL_MSG, MAIL_TYPES)) == MAIL_EXPECT["digest"], "Mail digest")

    # Ripar type strings: generic encodeType == hard-coded copy == docs/PROTOCOL.md
    order = ["Delegation", "Caveat", "HumanApproval", "Revoke", "Panic", "Reopen", "Deny", "BindDevice"]
    derived = [encode_type(t, RIPAR_TYPES) for t in order]
    for t, d, p in zip(order, derived, PROTOCOL_TYPE_STRINGS):
        ok(d == p, "encodeType(%s) == PROTOCOL string" % t)
    md = protocol_md_type_strings()
    if md is None:
        print("skip  docs/PROTOCOL.md not found")
    else:
        ok(md == PROTOCOL_TYPE_STRINGS, "docs/PROTOCOL.md section 3 type block == PROTOCOL_TYPE_STRINGS")
    ok(h(type_hash("Delegation", RIPAR_TYPES)) == DELEGATION_TYPEHASH, "DELEGATION_TYPEHASH")
    ok(h(type_hash("Caveat", RIPAR_TYPES)) == CAVEAT_TYPEHASH, "CAVEAT_TYPEHASH")
    ok(h(type_hash("EIP712Domain", RIPAR_TYPES)) == EIP712_DOMAIN_TYPEHASH, "EIP712Domain typehash")

    # generic encoder == EncoderLib port on random delegations
    rng = random.Random(1)
    for n in (0, 1, 2, 3, 7):
        cav = [(rb(rng, 20), rb(rng, rng.choice([0, 1, 32, 33, 136, 137, 300])))
               for _ in range(n)]
        d = {"delegate": rb(rng, 20), "delegator": rb(rng, 20), "authority": ROOT_AUTHORITY,
             "caveats": [{"enforcer": e, "terms": t} for e, t in cav], "salt": rng.getrandbits(256)}
        ok(hash_struct("Delegation", d) ==
           mm_delegation_hash(d["delegate"], d["delegator"], d["authority"], cav, d["salt"]),
           "generic Delegation hash == EncoderLib port (%d caveats)" % n)
    ok(encode_value("Caveat[]", [], RIPAR_TYPES) == keccak256(b""), "empty Caveat[] encodes as keccak256('')")
    ok(encode_value("uint64", MAX64, RIPAR_TYPES) == MAX64.to_bytes(32, "big"), "uint64 -> uint256 word")

    # ERC-20 selectors and formatting
    for k, sig in SIG.items():
        ok(keccak256(sig.encode())[:4] == SEL[k], "selector " + sig)
    for v, d, m, want in [(0, 18, 6, "0"), (12500000, 6, 6, "12.5"), (1, 6, 6, "0.000001"),
                          (1234500000, 6, 6, "1,234.5"), (1, 18, 6, "0.000000..."), (10 ** 18, 18, 6, "1"),
                          (1234567, 6, 2, "1.23..."), (1500000, 6, 0, "1..."), (1000000, 6, 0, "1"),
                          (123456789, 0, 6, "123,456,789"), (1000, 0, 6, "1,000"), (999, 0, 6, "999")]:
        ok(format_units(v, d, m) == want, "format_units(%d,%d,%d) == %r (got %r)" % (v, d, m, want,
                                                                                 format_units(v, d, m)))
    print("ref_eip712 selftest:", "PASS" if bad[0] == 0 else "FAIL (%d)" % bad[0])
    return bad[0] == 0


# ------------------------------------------------------------------ vector generation
def rb(rng, n):
    return bytes(rng.getrandbits(8) for _ in range(n))


def r_u256(rng):
    c = rng.randrange(10)
    if c == 0:
        return 0
    if c == 1:
        return MAX256
    if c == 2:
        return rng.randrange(1, 1000)
    return rng.getrandbits(rng.choice([8, 32, 63, 64, 65, 96, 128, 200, 255, 256]))


def r_u64(rng):
    c = rng.randrange(6)
    if c == 0:
        return 0
    if c == 1:
        return MAX64
    return rng.getrandbits(rng.choice([8, 31, 32, 33, 63, 64]))


def r_addr(rng):
    c = rng.randrange(12)
    if c == 0:
        return b"\x00" * 20
    if c == 1:
        return b"\xff" * 20
    return rb(rng, 20)


def c_str(s):
    """C string literal; non-printables as 3-digit octal escapes (cannot swallow following digits)."""
    b = s.encode("utf-8") if isinstance(s, str) else bytes(s)
    out = []
    for c in b:
        if c in (0x22, 0x5C) or c < 0x20 or c >= 0x7F or c == 0x3F:  # also '?' (no trigraphs)
            out.append("\\%03o" % c)
        else:
            out.append(chr(c))
    return '"' + "".join(out) + '"'


def hx(b):
    return '"' + h(b) + '"'


def u256s(x):
    return '"' + x.to_bytes(32, "big").hex() + '"'


def u64s(x):
    return "0x%016xull" % x


def generate():
    rng = random.Random(712)
    L = []
    w = L.append
    w("// GENERATED by tools/ref_eip712.py gen (random.Random(712)) - DO NOT EDIT.")
    w("// Regenerate: python tools/ref_eip712.py gen      Check up to date: python tools/ref_eip712.py check")
    w("// Every expected value comes from the Python reference (generic EIP-712 encoder / EncoderLib port /")
    w("// integer-arithmetic format_units), not from the C++ code under test. Hex strings have no 0x prefix.")
    w("#pragma once")
    w("#include <cstdint>")
    w("")
    w('#include "abi.h"')
    w("")
    w("namespace vec {")
    w("")
    w("struct Domain { const char* name; const char* version; uint64_t chainId; const char* contract; const char* separator; };")
    w("struct Cav { const char* enforcer; const char* terms; const char* hash; };")
    w("struct Delegation { const char* delegate; const char* delegator; const char* authority; const char* salt;")
    w("                    unsigned ncaveats; Cav caveats[5]; const char* hash;")
    w("                    uint64_t chainId; const char* manager; const char* digest; };")
    w("struct HumanApproval { const char* delegationHash; const char* delegator; const char* redeemer; const char* target;")
    w("                       const char* value; const char* callDataHash; const char* nonce; uint64_t expiry;")
    w("                       const char* presenceHash; const char* hash; uint64_t chainId; const char* enforcer;")
    w("                       const char* digest; };")
    w("struct Revoke { const char* delegationHash; const char* hash; uint64_t chainId; const char* enforcer; const char* digest; };")
    w("struct Panic { uint64_t minEpoch; const char* hash; uint64_t chainId; const char* enforcer; const char* digest; };")
    w("struct Reopen { const char* vault; const char* nonce; const char* hash; uint64_t chainId; const char* sentinel; const char* digest; };")
    w("struct Deny { const char* agentId; const char* requestHash; const char* presenceHash; const char* hash;")
    w("              uint64_t chainId; const char* relay; const char* digest; };")
    w("struct BindDevice { const char* owner; const char* px; const char* py; const char* hash;")
    w("                    uint64_t chainId; const char* registry; const char* digest; };")
    w("struct Erc20 { const char* calldata; ripar::Erc20Call::Kind kind; uint32_t selector; const char* from; const char* to;")
    w("               const char* amount; const char* note; };")
    w("struct Checksum { const char* lower; const char* checksum; uint8_t fp[4]; };")
    w("struct Units { const char* value; int decimals; int maxFrac; const char* text; };")
    w("")

    def dom(name, chain, contract):
        return domain_separator(domain_ripar(name, chain, contract))

    def r_chain():
        return rng.choice([1, 143, 10143, 31337, 0, MAX64, rng.getrandbits(64)])

    # ---- domains
    w("static const Domain DOMAINS[] = {")
    names = ["DelegationManager", "RiparPulseCosign", "RiparSentinel", "RiparReputationRelay", "RiparDeviceRegistry",
             "", "Ether Mail", "Ripar \u00e9\u00e8 \u2713", "x" * 200, 'quote " back \\ q?']
    versions = ["1", "", "1.3.0", "2"]
    for i, nm in enumerate(names):
        ver = versions[i % len(versions)] if i >= 5 else "1"
        chain = r_chain()
        c = r_addr(rng)
        w("    {%s, %s, %s, %s, %s}," % (c_str(nm), c_str(ver), u64s(chain), hx(c),
                                        hx(domain_separator(domain_ripar(nm, chain, c, ver)))))
    w("};")
    w("")

    # ---- delegations
    w("static const Delegation DELEGATIONS[] = {")
    counts = [0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 3, 3, 4, 5, 5]
    for n in counts:
        cav = [(r_addr(rng), rb(rng, rng.choice([0, 1, 20, 31, 32, 33, 64, 96, 135, 136, 137, 200, 300])))
               for _ in range(n)]
        dg, dr = r_addr(rng), r_addr(rng)
        auth = ROOT_AUTHORITY if rng.randrange(3) else rb(rng, 32)
        salt = r_u256(rng)
        msg = {"delegate": dg, "delegator": dr, "authority": auth,
               "caveats": [{"enforcer": e, "terms": t} for e, t in cav], "salt": salt}
        sh = hash_struct("Delegation", msg)
        assert sh == mm_delegation_hash(dg, dr, auth, cav, salt)
        chain, mgr = r_chain(), r_addr(rng)
        dgst = digest_from(dom("DelegationManager", chain, mgr), sh)
        cavs = []
        for i in range(5):
            if i < n:
                e, t = cav[i]
                ch = hash_struct("Caveat", {"enforcer": e, "terms": t})
                assert ch == mm_caveat_hash(e, t)
                cavs.append("{%s, %s, %s}" % (hx(e), hx(t), hx(ch)))
            else:
                cavs.append('{"", "", ""}')
        w("    {%s, %s, %s, %s,\n     %d, {%s},\n     %s, %s, %s, %s}," % (
            hx(dg), hx(dr), hx(auth), u256s(salt), n, ",\n      ".join(cavs), hx(sh), u64s(chain), hx(mgr), hx(dgst)))
    w("};")
    w("")

    # ---- human approvals
    w("static const HumanApproval HUMAN_APPROVALS[] = {")
    for _ in range(12):
        m = {"delegationHash": rb(rng, 32), "delegator": r_addr(rng), "redeemer": r_addr(rng), "target": r_addr(rng),
             "value": r_u256(rng), "callDataHash": keccak256(rb(rng, rng.choice([0, 4, 68, 100]))),
             "nonce": r_u256(rng), "expiry": r_u64(rng), "presenceHash": rb(rng, 32)}
        sh = hash_struct("HumanApproval", m)
        chain, enf = r_chain(), r_addr(rng)
        w("    {%s, %s, %s, %s,\n     %s, %s, %s, %s,\n     %s, %s, %s, %s,\n     %s}," % (
            hx(m["delegationHash"]), hx(m["delegator"]), hx(m["redeemer"]), hx(m["target"]), u256s(m["value"]),
            hx(m["callDataHash"]), u256s(m["nonce"]), u64s(m["expiry"]), hx(m["presenceHash"]), hx(sh), u64s(chain),
            hx(enf), hx(digest_from(dom("RiparPulseCosign", chain, enf), sh))))
    w("};")
    w("")

    w("static const Revoke REVOKES[] = {")
    for _ in range(6):
        dh = rb(rng, 32) if rng.randrange(4) else bytes(32)
        sh = hash_struct("Revoke", {"delegationHash": dh})
        chain, enf = r_chain(), r_addr(rng)
        w("    {%s, %s, %s, %s, %s}," % (hx(dh), hx(sh), u64s(chain), hx(enf),
                                        hx(digest_from(dom("RiparPulseCosign", chain, enf), sh))))
    w("};")
    w("")

    w("static const Panic PANICS[] = {")
    for e in [0, 1, MAX64, 1 << 32, rng.getrandbits(64), rng.getrandbits(40)]:
        sh = hash_struct("Panic", {"minEpoch": e})
        chain, enf = r_chain(), r_addr(rng)
        w("    {%s, %s, %s, %s, %s}," % (u64s(e), hx(sh), u64s(chain), hx(enf),
                                        hx(digest_from(dom("RiparPulseCosign", chain, enf), sh))))
    w("};")
    w("")

    w("static const Reopen REOPENS[] = {")
    for _ in range(6):
        v, nonce = r_addr(rng), r_u256(rng)
        sh = hash_struct("Reopen", {"vault": v, "nonce": nonce})
        chain, s = r_chain(), r_addr(rng)
        w("    {%s, %s, %s, %s, %s, %s}," % (hx(v), u256s(nonce), hx(sh), u64s(chain), hx(s),
                                            hx(digest_from(dom("RiparSentinel", chain, s), sh))))
    w("};")
    w("")

    w("static const Deny DENIES[] = {")
    for _ in range(6):
        aid, rq = r_u256(rng), rb(rng, 32)
        ph = rb(rng, 32) if rng.randrange(3) else bytes(32)
        sh = hash_struct("Deny", {"agentId": aid, "requestHash": rq, "presenceHash": ph})
        chain, relay = r_chain(), r_addr(rng)
        w("    {%s, %s, %s, %s, %s, %s, %s}," % (u256s(aid), hx(rq), hx(ph), hx(sh), u64s(chain), hx(relay),
                                                hx(digest_from(dom("RiparReputationRelay", chain, relay), sh))))
    w("};")
    w("")

    w("static const BindDevice BIND_DEVICES[] = {")
    for _ in range(6):
        o, px, py = r_addr(rng), rb(rng, 32), rb(rng, 32)
        sh = hash_struct("BindDevice", {"owner": o, "px": px, "py": py})
        chain, reg = r_chain(), r_addr(rng)
        w("    {%s, %s, %s, %s, %s, %s, %s}," % (hx(o), hx(px), hx(py), hx(sh), u64s(chain), hx(reg),
                                                hx(digest_from(dom("RiparDeviceRegistry", chain, reg), sh))))
    w("};")
    w("")

    # ---- ERC-20 calldata
    K = {"transfer": "Transfer", "approve": "Approve", "transferFrom": "TransferFrom"}
    Z20 = bytes(20)
    rows = []  # (calldata, kind, selector int, from, to, amount int, note)

    def sel_int(cd):
        return int.from_bytes(cd[:4], "big") if len(cd) >= 4 else 0

    for i in range(24):
        kind = ["transfer", "approve", "transferFrom"][i % 3]
        a, b, amt = r_addr(rng), r_addr(rng), r_u256(rng)
        if kind == "transferFrom":
            cd = calldata(kind, a, b, amt)
            rows.append((cd, K[kind], sel_int(cd), a, b, amt, "ok " + kind))
        else:
            cd = calldata(kind, b, amt)
            rows.append((cd, K[kind], sel_int(cd), Z20, b, amt, "ok " + kind))
    # negatives
    for i in range(30):
        kind = ["transfer", "approve", "transferFrom"][i % 3]
        nargs = 3 if kind == "transferFrom" else 2
        args = [r_addr(rng) for _ in range(nargs - 1)] + [r_u256(rng)]
        cd = bytearray(calldata(kind, *args))
        how = i // 3
        if how in (0, 1):  # dirty high byte in an address word
            word = rng.randrange(nargs - 1)
            pos = 4 + 32 * word + rng.randrange(12)
            cd[pos] = rng.randrange(1, 256)
            note = "dirty address word %d byte %d" % (word, pos - 4 - 32 * word)
        elif how == 2:
            cd = cd[:-1]
            note = "one byte short"
        elif how == 3:
            cd = cd + b"\x00"
            note = "one extra byte"
        elif how == 4:
            cd = cd + bytes(32)
            note = "extra zero word"
        elif how == 5:
            cd = cd[:4 + 32 * (nargs - 1)]
            note = "missing last word"
        elif how == 6:
            cd = cd[:4]
            note = "selector only"
        elif how == 7:
            cd[rng.randrange(4)] ^= 1 << rng.randrange(8)
            note = "selector bit flip"
        elif how == 8:
            cd = cd[:4] + cd[4:36] + bytes(32) + cd[36:] if nargs == 2 else cd[:4] + cd[36:]
            note = "wrong arity"
        else:
            cd = cd[:rng.randrange(1, 4)]
            note = "shorter than a selector"
        cd = bytes(cd)
        rows.append((cd, "Unknown", sel_int(cd), Z20, Z20, 0, "bad " + kind + ": " + note))
    rows.append((b"", "None", 0, Z20, Z20, 0, "empty calldata"))
    # unknown well-formed calls
    for sig in ["increaseAllowance(address,uint256)", "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
                "transferFrom(address,uint256)", "transfer(address,address,uint256)"]:
        cd = keccak256(sig.encode())[:4] + rb(rng, 64)
        rows.append((cd, "Unknown", sel_int(cd), Z20, Z20, 0, "unknown selector " + sig))
    w("static const Erc20 ERC20S[] = {")
    for cd, kind, sel, fr, to, amt, note in rows:
        w("    {%s, ripar::Erc20Call::%s, 0x%08xu, %s, %s, %s, %s}," % (
            hx(cd), kind, sel, hx(fr), hx(to), u256s(amt), c_str(note)))
    w("};")
    w("")

    # ---- checksum + fingerprint
    w("static const Checksum CHECKSUMS[] = {")
    addrs = [unhex(a) for a in EIP55_VECTORS] + [bytes(20), b"\xff" * 20] + [rb(rng, 20) for _ in range(30)]
    for a in addrs:
        fp = fingerprint(a)
        w("    {%s, %s, {%d, %d, %d, %d}}," % (hx(a), c_str(eip55(a)), fp[0], fp[1], fp[2], fp[3]))
    w("};")
    w("")

    # ---- format_units
    w("static const Units UNITS[] = {")
    fixed = [(0, 18, 6), (1, 18, 6), (1, 6, 6), (12500000, 6, 6), (1234500000, 6, 6), (10 ** 18, 18, 6),
             (MAX256, 18, 6), (MAX256, 0, 6), (MAX256, 77, 80), (MAX256, 78, 80), (MAX256, 80, 90), (MAX256, 255, 6),
             (MAX256, 255, 300), (1, 255, 6), (10 ** 77, 77, 6), (999, 3, 6), (1000, 3, 6), (999999, 6, 6),
             (1000001, 6, 6), (1000001, 6, 5), (123456789, 0, 0), (5, 1, 0), (50, 1, 0), (7, -3, 6), (12345, 2, -1)]
    cases = list(fixed)
    for _ in range(80):
        cases.append((r_u256(rng), rng.choice([0, 1, 2, 6, 8, 9, 12, 18, 24, 30, 60, 77, 78, 79, 100]),
                      rng.choice([0, 1, 2, 4, 6, 6, 6, 8, 18, 40])))
    for v, d, m in cases:
        w("    {%s, %d, %d, %s}," % (u256s(v), d, m, c_str(format_units(v, d, m))))
    w("};")
    w("")
    w("}  // namespace vec")
    return "\n".join(L) + "\n"


def typed(path):
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    types = {k: [(x["name"], x["type"]) for x in v] for k, v in doc["types"].items()}
    ds = domain_separator(doc["domain"], types)
    sh = hash_struct(doc["primaryType"], doc["message"], types)
    print("encodeType ", encode_type(doc["primaryType"], types))
    print("domain     0x" + h(ds))
    print("structHash 0x" + h(sh))
    print("digest     0x" + h(digest_from(ds, sh)))
    return 0


def _main(argv):
    if len(argv) >= 2 and argv[1] == "gen":
        text = generate()
        with open(VEC_PATH, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        print("wrote %s (%d bytes)" % (VEC_PATH, len(text)))
        return 0
    if len(argv) >= 2 and argv[1] == "check":
        text = generate()
        try:
            with open(VEC_PATH, "r", encoding="utf-8", newline="") as f:
                cur = f.read()
        except OSError:
            cur = None
        good = cur == text
        print("vectors_eip712_abi.h:", "up to date" if good else "STALE (run: python tools/ref_eip712.py gen)")
        return 0 if good else 1
    if len(argv) >= 3 and argv[1] == "typed":
        return typed(argv[2])
    if len(argv) >= 2:
        print(__doc__)
        return 2
    return 0 if selftest() else 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
