#!/usr/bin/env python3
"""Ripar Wallet companion-side protocol tool (docs/PROTOCOL.md §4). Pure Python 3 stdlib.

BUILDS device requests (CBOR -> single-part UR + multipart pure-fragment QR parts) and PARSES / VERIFIES device
responses (UR -> CBOR -> fields; every signature checked with tools/ref_crypto.py against the digest rebuilt with
tools/ref_eip712.py). Independent of the C++ firmware; also generates test/host/vectors_protocol.h.

  python tools/make_request.py build <pair|cosign|mandate|deny|privy> [FIELDS...] [options]
      FIELDS: a JSON object ('{"chainId":10143,...}'), @file.json, and/or key=value pairs. A value is parsed as JSON
              when it is valid JSON (numbers, objects, arrays), otherwise used as a plain string (hex, text).
      --reqid HEX (16 bytes; default random)  --uuid-tag (wrap req-id in CBOR tag 37)
      --frag N (max fragment bytes, default 70)  --extra N (also print N mixed fountain parts)  --json (machine output)
  python tools/make_request.py parse <RESPONSE_UR | @file> [--req REQ] [--pair PAIR_UR] [--p1 HEX128] [--k1 ADDR]
                                     [--chain N] [--contract ADDR]
      REQ = the request as UR, multipart parts file, CBOR hex or @file. Exit 0 = every signature verified,
      1 = a check failed, 3 = parsed but a signature could not be checked (key / request missing).
  python tools/make_request.py simulate <REQ> [--seed HEX]     demo device: prints the response UR (no pulse check!)
  python tools/make_request.py demo-keys [--seed HEX]           K1 address / P1 public key of the demo device
  python tools/make_request.py gen-vectors | check-vectors      test/host/vectors_protocol.h (deterministic)
  python tools/make_request.py selftest                        build -> simulate -> parse/verify, tamper tests

Field names (JSON; addresses / bytes as 0x-hex, integers as numbers or "0x.." / decimal strings):
  pair:    chainId, registry, and the contracts to pin: manager (DelegationManager), enforcer (PulseCosignEnforcer),
           sentinel, relay, vault; now (companion clock, unix s; `build` adds the current time unless --no-now);
           minEpoch, reopenNonce (optional floors < 2^63 for the device counters, e.g. the on-chain minEpoch of the
           device key and the sentinel's last reopen nonce after the device lost its context; they only raise them)
  cosign:  chainId, enforcer, delegationHash, delegator, redeemer, target, value, nonce, expiry,
           calldata (hex) | transfer {to, amount} | approve {spender, amount} | transferFrom {from, to, amount},
           risk {src, category, label, ageDays}, ai {text, claims {to, token, amount}}, budgetLeft, decimals, symbol
           (a token in the firmware table - AUSD on 10143 - must not carry other decimals / symbol: refused)
  mandate: chainId, manager, delegate, delegator, authority (default ROOT), salt, label, agentId, caveats:
           [[enforcer, termsHex], ...] or [{enforcer, terms}] or typed [{kind, ...}] with kind (terms encoded here):
             pulse {enforcer, p1Key | px+py, token, perTxAutoCap, periodAutoCap, period, epoch, newPayeeNeedsHuman,
                    sentinel}   (enforcer = the PulseCosignEnforcer pinned at pairing; epoch = EXACTLY the device's
                    panic floor, i.e. the last panic epoch it signed (0 before any panic); sentinel = the pinned one,
                    or the zero address when none was pinned)
             erc20TransferAmount {token, amount}   nativeTokenTransferAmount {amount}   valueLte {amount}
             limitedCalls {amount}   erc20PeriodTransfer {token, amount, duration, start}
             timestamp {after, before}   allowedTargets {addresses}   redeemer {addresses}
           The device signs only a mandate with EXACTLY ONE pulse caveat (its own key) and decodable caveats.
  deny:    chainId, relay, agentId, requestHash
  privy:   json (a string = the exact bytes, or an object = canonicalised: sorted keys, no whitespace). The device
           signs only PATCH https://api.privy.io/v1/wallets/<id> {policy_ids, additional_signers} and
           PATCH https://api.privy.io/v1/key_quorums/<id> {public_keys, authorization_threshold, display_name,
           user_ids, key_quorum_ids} with headers privy-app-id (+ privy-idempotency-key) - see docs/PROTOCOL.md
Example:
  python tools/make_request.py build cosign chainId=10143 enforcer=0x11..11 delegationHash=0x22..22 \
      delegator=0x33..33 redeemer=0x44..44 target=0xa9012a055bd4e0eDfF8Ce09f960291C09D5322dC value=0 nonce=7 \
      expiry=1790000000 'transfer={"to":"0x55..55","amount":25000000}' decimals=6 symbol=AUSD

Wire rules implemented here (the device parser in src/protocol.cpp is stricter and is the reference):
  req-id = bstr(16) (optionally tag 37); u256 = minimal big-endian bstr, at least 1 byte (0 -> h'00');
  display texts without control characters; ai.text <= 100 UTF-8 bytes (use ai_text_trunc).
Responses echo the req-id as a plain bstr. u256 in responses (reopen nonce) is minimal big-endian, >= 1 byte.
"""
import argparse
import base64
import hashlib
import json
import os
import random
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ref_crypto as rc  # noqa: E402
import ref_eip712 as E  # noqa: E402
import ref_ur as U  # noqa: E402
from ref_hashes import keccak256, eip55  # noqa: E402

FW = os.path.normpath(os.path.join(HERE, ".."))
VEC_PATH = os.path.join(FW, "test", "host", "vectors_protocol.h")

ROOT = b"\xff" * 32
MAX256 = (1 << 256) - 1
MAX64 = (1 << 64) - 1
DEMO_SEED = hashlib.sha256(b"ripar demo seed").digest()  # same as test/host/crypto_vectors.h DEMO_SEED

REQ_TYPES = {"pair": "ripar-pair-req", "cosign": "ripar-cosign-req", "mandate": "ripar-mandate-req",
             "deny": "ripar-deny-req", "privy": "ripar-privy-req"}
RESP_TYPES = {"pair": "ripar-pair", "cosign": "ripar-cosign", "mandate": "eth-signature", "deny": "ripar-deny",
              "privy": "ripar-der-sig"}
DOMAIN_OF = {"pair": "RiparDeviceRegistry", "cosign": "RiparPulseCosign", "mandate": "DelegationManager",
             "deny": "RiparReputationRelay", "revoke": "RiparPulseCosign", "panic": "RiparPulseCosign",
             "reopen": "RiparSentinel"}
PRIVY_API = "https://api.privy.io"


class ProtoError(ValueError):
    pass


# ================================================================================================ value helpers
def h(b):
    return bytes(b).hex()


def unhex(s):
    s = s.strip()
    if s[:2] in ("0x", "0X"):
        s = s[2:]
    return bytes.fromhex(s)


def to_int(v):
    if isinstance(v, bool):
        raise ProtoError("expected an integer, got a boolean")
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        v = v.strip()
        return int(v, 16) if v[:2] in ("0x", "0X") else int(v, 10)
    if isinstance(v, (bytes, bytearray)):
        return int.from_bytes(bytes(v), "big")
    raise ProtoError("expected an integer: %r" % (v,))


def to_bytes(v, n=None, what="bytes"):
    if isinstance(v, (bytes, bytearray)):
        b = bytes(v)
    elif isinstance(v, str):
        b = unhex(v)
    else:
        raise ProtoError("%s: expected hex, got %r" % (what, v))
    if n is not None and len(b) != n:
        raise ProtoError("%s: expected %d bytes, got %d" % (what, n, len(b)))
    return b


def to_addr(v, what="address"):
    return to_bytes(v, 20, what)


def u256_min(x):
    """minimal big-endian, at least one byte (0 -> b'\\x00')"""
    x = to_int(x)
    if not 0 <= x <= MAX256:
        raise ProtoError("u256 out of range")
    return x.to_bytes(max(1, (x.bit_length() + 7) // 8), "big")


def ai_text_trunc(s, limit=100):
    """truncate to <= limit UTF-8 bytes on a character boundary, replacing control characters with spaces"""
    s = "".join(" " if (ord(c) < 0x20 or ord(c) == 0x7F) else c for c in s)
    b = s.encode("utf-8")
    if len(b) <= limit:
        return s
    return b[:limit].decode("utf-8", errors="ignore")


def canonical_json(obj):
    """RFC 8785-style canonical JSON for ASCII keys and integer numbers (what Privy's payloads use)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ================================================================================================ strict CBOR decoder
def cbor_decode(data):
    """Strict decode of exactly one item: definite lengths, no duplicate map keys, no trailing bytes.
    Returns int / bytes / str / list / dict / U.Tag / bool / None (floats rejected)."""
    data = bytes(data)
    pos = [0]

    def take(n):
        if pos[0] + n > len(data):
            raise ProtoError("CBOR truncated")
        b = data[pos[0]:pos[0] + n]
        pos[0] += n
        return b

    def item(depth):
        if depth > 16:
            raise ProtoError("CBOR nesting too deep")
        ib = take(1)[0]
        major, ai = ib >> 5, ib & 31
        if major == 7:
            if ai == 20:
                return False
            if ai == 21:
                return True
            if ai == 22:
                return None
            raise ProtoError("CBOR simple/float value not supported")
        if ai < 24:
            arg = ai
        elif ai in (24, 25, 26, 27):
            arg = int.from_bytes(take(1 << (ai - 24)), "big")
        else:
            raise ProtoError("CBOR indefinite / reserved length")
        if major == 0:
            return arg
        if major == 1:
            return -1 - arg
        if major == 2:
            return take(arg)
        if major == 3:
            try:
                return take(arg).decode("utf-8")
            except UnicodeDecodeError:
                raise ProtoError("CBOR text is not UTF-8")
        if major == 4:
            return [item(depth + 1) for _ in range(arg)]
        if major == 5:
            d = {}
            for _ in range(arg):
                k = item(depth + 1)
                if isinstance(k, (list, dict)):
                    raise ProtoError("CBOR map key must be a scalar")
                if isinstance(k, U.Tag):
                    raise ProtoError("CBOR tagged map key not supported")
                if k in d:
                    raise ProtoError("CBOR duplicate map key")
                d[k] = item(depth + 1)
            return d
        return U.Tag(arg, item(depth + 1))  # major 6

    v = item(0)
    if pos[0] != len(data):
        raise ProtoError("CBOR trailing bytes")
    return v


# ================================================================================================ UR in / out
def ur_single(ur_type, cbor_bytes):
    return U.ur_single(ur_type, cbor_bytes).upper()


def ur_parts(ur_type, cbor_bytes, frag=70, extra=0):
    enc = U.FountainEncoder(cbor_bytes, frag)
    return [U.ur_part(ur_type, enc, s).upper() for s in range(1, enc.seq_len + 1 + extra)]


def ur_read(text):
    """UR text -> (type, cbor bytes). Accepts one single-part UR, or several multipart parts (whitespace separated;
    pure parts are reassembled, mixed parts are ignored)."""
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    parts = " ".join(lines).split()
    if not parts:
        raise ProtoError("no UR given")
    singles = [p for p in parts if p.lower().startswith("ur:") and p.count("/") == 1]
    if singles:  # `build` output lists the single-part UR first, then the parts: the single-part UR is enough
        parts = singles[:1]
    frags, meta, utype = {}, None, None
    for p in parts:
        s = p.strip().lower()
        if not s.startswith("ur:"):
            raise ProtoError("not a UR: %r" % p[:40])
        path = s[3:].split("/")
        if utype is not None and path[0] != utype:
            raise ProtoError("mixed UR types")
        utype = path[0]
        if len(path) == 2:
            if len(parts) != 1:
                raise ProtoError("single-part UR mixed with other parts")
            return utype, U.bw_decode(path[1])
        if len(path) != 3:
            raise ProtoError("bad UR path")
        seq, slen, mlen, crc, frag = cbor_decode(U.bw_decode(path[2]))
        if meta is None:
            meta = (slen, mlen, crc)
        elif meta != (slen, mlen, crc):
            raise ProtoError("parts belong to different messages")
        if seq <= slen:
            frags[seq] = frag
    slen, mlen, crc = meta
    missing = [i for i in range(1, slen + 1) if i not in frags]
    if missing:
        raise ProtoError("missing pure parts %s (mixed-part solving not implemented here)" % missing)
    msg = b"".join(frags[i] for i in range(1, slen + 1))[:mlen]
    if U.crc32(msg) != crc:
        raise ProtoError("multipart message CRC mismatch")
    return utype, msg


def read_arg_blob(arg):
    """@file -> file text; otherwise the argument itself"""
    if arg.startswith("@"):
        with open(arg[1:], "r", encoding="utf-8") as f:
            return f.read()
    return arg


def read_request(arg):
    """UR / parts / CBOR hex / @file -> (kind, cbor bytes)"""
    raw = read_arg_blob(arg)
    text = "\n".join(ln for ln in raw.splitlines() if not ln.strip().startswith("#")).strip()
    if text.lower().startswith("ur:"):
        utype, cb = ur_read(text)
        for k, t in REQ_TYPES.items():
            if t == utype:
                return k, cb
        raise ProtoError("not a Ripar request UR type: " + utype)
    try:
        cb = unhex(text)
    except ValueError:
        raise ProtoError("request is neither a UR nor CBOR hex")
    m = cbor_decode(cb)
    return guess_kind(m), cb


def guess_kind(m):
    if not isinstance(m, dict):
        raise ProtoError("request is not a map")
    ks = set(m)
    if 11 in ks:
        return "cosign"
    if isinstance(m.get(7), list):
        return "mandate"
    if isinstance(m.get(5), bytes) and len(m[5]) == 32 and isinstance(m.get(4), int):
        return "deny"
    if ks == {1, 2} and isinstance(m.get(2), bytes):
        return "privy"
    return "pair"


# ================================================================================================ ERC-20 decode (independent)
SEL_TRANSFER, SEL_APPROVE, SEL_TRANSFER_FROM = bytes.fromhex("a9059cbb"), bytes.fromhex("095ea7b3"), bytes.fromhex("23b872dd")


def decode_erc20(cd):
    """-> (kind, from, to, amount); kind in none/transfer/approve/transferFrom/unknown (C++ Erc20Call::Kind 0..4)"""
    z20 = b"\x00" * 20
    if len(cd) == 0:
        return "none", z20, z20, 0
    sel = cd[:4]
    spec = {SEL_TRANSFER: ("transfer", 2), SEL_APPROVE: ("approve", 2), SEL_TRANSFER_FROM: ("transferFrom", 3)}
    if len(cd) < 4 or sel not in spec:
        return "unknown", z20, z20, 0
    kind, words = spec[sel]
    if len(cd) != 4 + 32 * words:
        return "unknown", z20, z20, 0
    w = [cd[4 + 32 * i: 36 + 32 * i] for i in range(words)]
    for a in w[:-1]:
        if a[:12] != b"\x00" * 12:
            return "unknown", z20, z20, 0
    if kind == "transferFrom":
        return kind, w[0][12:], w[1][12:], int.from_bytes(w[2], "big")
    return kind, z20, w[0][12:], int.from_bytes(w[1], "big")


KIND_NUM = {"none": 0, "transfer": 1, "approve": 2, "transferFrom": 3, "unknown": 4}


def ai_matches(q):
    """security review MINOR 1: only a plain native send or an ERC-20 transfer can match the AI claims, and only when
    recipient, token (zero = native) and amount all equal the decode; transferFrom / approve / unknown never match."""
    cl = q.get("claims")
    if not cl:
        return False
    kind, frm, to, amt = decode_erc20(q["calldata"])
    if kind == "none":
        return cl["to"] == q["target"] and cl["token"] == b"\x00" * 20 and cl["amount"] == q["value"]
    if kind == "transfer":
        return q["value"] == 0 and cl["to"] == to and cl["token"] == q["target"] and cl["amount"] == amt
    return False


# ================================================================================================ firmware tables (mirror)
# src/tokens.cpp (security review B3). "" placeholders of the C++ table (MockUSD, AUSD on 143) never match: omitted.
AUSD_10143 = unhex("0xa9012a055bd4e0eDfF8Ce09f960291C09D5322dC")
TOKENS = {(10143, AUSD_10143): (6, "AUSD", "Agora USD")}
NATIVE = {10143: (18, "MON", "Monad testnet"), 143: (18, "MON", "Monad")}
DELEGATION_MANAGER = unhex("0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3")  # MetaMask v1.3.0 on 10143 and 143
ZERO20 = b"\x00" * 20


def token_check(q):
    """(listed, decimals, symbol) of the asset of a co-sign amount. Raises ProtoError when a LISTED asset (table token
    or native coin of a supported chain) carries key 15 / 16 values that differ from the table: the device refuses.
    An unlisted asset: (False, -1, the companion's key-16 symbol or "")."""
    kind = decode_erc20(q["calldata"])[0]
    ent = NATIVE.get(q["chainId"]) if kind == "none" else TOKENS.get((q["chainId"], bytes(q["target"])))
    if ent is None:
        return False, -1, q.get("symbol", "") if q.get("hasSymbol") else ""
    dec, sym = ent[0], ent[1]
    if q.get("hasDecimals") and q["decimals"] != dec:
        raise ProtoError("key 15 (decimals) = %d disagrees with the firmware token table (%s has %d)" % (q["decimals"], sym, dec))
    if q.get("hasSymbol") and q["symbol"] != sym:
        raise ProtoError('key 16 (symbol) "%s" disagrees with the firmware token table (%s)' % (q["symbol"], sym))
    return True, dec, sym


# ---- caveat terms (getTermsInfo layouts of MetaMask delegation-framework v1.3.0 + Ripar PulseCosignEnforcer Terms)
MM_ENF = {  # MetaMask delegation-framework v1.3.0 (see src/enforcers.cpp)
    "AllowedTargetsEnforcer": "0x7F20f61b1f09b08D970938F6fa563634d65c4EeB",
    "AllowedMethodsEnforcer": "0x2c21fD0Cb9DC8445CB3fb0DC5E7Bb0Aca01842B5",
    "AllowedCalldataEnforcer": "0xc2b0d624c1c4319760C96503BA27C347F3260f55",
    "ERC20PeriodTransferEnforcer": "0x474e3Ae7E169e940607cC624Da8A15Eb120139aB",
    "ERC20TransferAmountEnforcer": "0xf100b0819427117EcF76Ed94B358B1A5b5C6D2Fc",
    "LimitedCallsEnforcer": "0x04658B29F6b82ed55274221a06Fc97D318E25416",
    "NativeTokenTransferAmountEnforcer": "0xF71af580b9c3078fbc2BBF16FbB8EEd82b330320",
    "NonceEnforcer": "0xDE4f2FAC4B3D87A1d9953Ca5FC09FCa7F366254f",
    "RedeemerEnforcer": "0xE144b0b2618071B4E56f746313528a669c7E65c5",
    "TimestampEnforcer": "0x1046bb45C8d673d4ea75321280DB34899413c069",
    "ValueLteEnforcer": "0x92Bf12322527cAA612fd31a0e810472BBB106A8F",
}
KIND_ENF = {"erc20TransferAmount": "ERC20TransferAmountEnforcer",
            "nativeTokenTransferAmount": "NativeTokenTransferAmountEnforcer", "valueLte": "ValueLteEnforcer",
            "limitedCalls": "LimitedCallsEnforcer", "erc20PeriodTransfer": "ERC20PeriodTransferEnforcer",
            "timestamp": "TimestampEnforcer", "allowedTargets": "AllowedTargetsEnforcer",
            "redeemer": "RedeemerEnforcer"}
ENF_KIND = {unhex(MM_ENF[v]): k for k, v in KIND_ENF.items()}


def _w_uint(x, bits=256):
    x = to_int(x)
    if not 0 <= x < (1 << bits):
        raise ProtoError("value does not fit uint%d" % bits)
    return x.to_bytes(32, "big")


def _w_addr(a):
    return b"\x00" * 12 + to_addr(a)


def terms_pulse(px, py, token, per_tx, period_cap, period, epoch, new_payee_needs_human, sentinel):
    """PulseCosignEnforcer Terms = abi.encode(bytes32 px, bytes32 py, address token, uint128 perTxAutoCap,
    uint128 periodAutoCap, uint32 period, uint64 epoch, bool newPayeeNeedsHuman, address sentinel): 288 bytes"""
    return (to_bytes(px, 32, "px") + to_bytes(py, 32, "py") + _w_addr(token) + _w_uint(per_tx, 128) +
            _w_uint(period_cap, 128) + _w_uint(period, 32) + _w_uint(epoch, 64) +
            _w_uint(1 if new_payee_needs_human else 0, 8) + _w_addr(sentinel))


def caveat_terms(kind, c):
    if kind == "pulse":
        if "p1Key" in c:
            xy = to_bytes(c["p1Key"], 64, "p1Key")
            px, py = xy[:32], xy[32:]
        else:
            px, py = c["px"], c["py"]
        return terms_pulse(px, py, c.get("token", ZERO20), c["perTxAutoCap"], c["periodAutoCap"], c["period"],
                           c.get("epoch", 0), c.get("newPayeeNeedsHuman", True), c.get("sentinel", ZERO20))
    if kind == "erc20TransferAmount":
        return to_addr(c["token"]) + _w_uint(c["amount"])
    if kind in ("nativeTokenTransferAmount", "valueLte", "limitedCalls"):
        return _w_uint(c["amount"])
    if kind == "erc20PeriodTransfer":
        return to_addr(c["token"]) + _w_uint(c["amount"]) + _w_uint(c["duration"]) + _w_uint(c["start"])
    if kind == "timestamp":
        return _w_uint(c.get("after", 0), 128)[16:] + _w_uint(c.get("before", 0), 128)[16:]
    if kind in ("allowedTargets", "redeemer"):
        return b"".join(to_addr(a) for a in c["addresses"])
    raise ProtoError("unknown caveat kind " + kind)


def caveat_from_spec(c):
    """[enforcer, terms] from [enforcer, termsHex] / {enforcer, terms} / {kind, ...}"""
    if isinstance(c, dict) and "kind" in c:
        k = c["kind"]
        if k == "pulse":
            if "enforcer" not in c:
                raise ProtoError("pulse caveat: give the PulseCosignEnforcer address (enforcer)")
            enf = c["enforcer"]
        else:
            enf = c.get("enforcer") or MM_ENF[KIND_ENF[k]]
        return [to_addr(enf, "caveat.enforcer"), caveat_terms(k, c)]
    if isinstance(c, dict):
        return [to_addr(c["enforcer"], "caveat.enforcer"), to_bytes(c.get("terms", ""), None, "caveat.terms")]
    return [to_addr(c[0], "caveat.enforcer"), to_bytes(c[1], None, "caveat.terms")]


def caveat_dump(chain, enforcer, terms, pulse_chain, pulse_enforcer):
    """Independent decode of one caveat (same text as test_policy.cpp dump()); None = the device must refuse it.
    (pulse_chain, pulse_enforcer) = the PulseCosignEnforcer pinned at pairing (it only counts on that chain)."""
    t = bytes(terms)
    enforcer = bytes(enforcer)
    d = lambda b: str(int.from_bytes(b, "big"))  # noqa: E731
    if not any(enforcer):
        return None
    if chain == pulse_chain and enforcer == bytes(pulse_enforcer):
        if len(t) != 288:
            return None
        w = [t[i:i + 32] for i in range(0, 288, 32)]
        zero_hi = [(2, 12), (3, 16), (4, 16), (5, 28), (6, 24), (7, 31), (8, 12)]
        if any(w[i][:n].strip(b"\x00") for i, n in zero_hi) or w[7][31] > 1:
            return None
        return "pulse px=%s py=%s token=%s perTx=%s periodCap=%s period=%s epoch=%s human=%d sentinel=%s" % (
            h(w[0]), h(w[1]), h(w[2][12:]), d(w[3]), d(w[4]), d(w[5]), d(w[6]), w[7][31], h(w[8][12:]))
    if chain not in (10143, 143):
        return None
    k = ENF_KIND.get(bytes(enforcer))
    if k == "erc20TransferAmount" and len(t) == 52 and any(t[:20]):
        return "erc20TransferAmount token=%s amount=%s" % (h(t[:20]), d(t[20:]))
    if k in ("nativeTokenTransferAmount", "valueLte", "limitedCalls") and len(t) == 32:
        return "%s amount=%s" % (k, d(t))
    if k == "erc20PeriodTransfer" and len(t) == 116 and any(t[:20]) and any(t[52:84]):
        return "erc20PeriodTransfer token=%s amount=%s duration=%s start=%s" % (h(t[:20]), d(t[20:52]), d(t[52:84]),
                                                                              d(t[84:]))
    if k == "timestamp" and len(t) == 32:
        return "timestamp after=%s before=%s" % (d(t[:16]), d(t[16:]))
    if k in ("allowedTargets", "redeemer") and t and len(t) % 20 == 0 and len(t) // 20 <= 16:
        return "%s %s" % (k, ",".join(h(t[i:i + 20]) for i in range(0, len(t), 20)))
    return None


# ================================================================================================ request builders
def _rid(f):
    rid = f.get("reqId")
    rid = os.urandom(16) if rid is None else to_bytes(rid, 16, "reqId")
    return U.Tag(37, rid) if f.get("uuidTag") else rid


def _need(f, *keys):
    for k in keys:
        if k not in f:
            raise ProtoError("missing field: " + k)


def _text(s, limit, what):
    if not isinstance(s, str):
        raise ProtoError(what + ": expected a string")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in s):
        raise ProtoError(what + ": control characters are refused by the device")
    if len(s.encode("utf-8")) > limit:
        raise ProtoError("%s: longer than %d UTF-8 bytes" % (what, limit))
    return s


PAIR_OPT = [(4, "manager"), (5, "enforcer"), (6, "sentinel"), (7, "relay"), (8, "vault")]
PAIR_FLOORS = [(10, "minEpoch"), (11, "reopenNonce")]  # optional, each < 2^63; they only raise the device counters


def build_pair_req(f):
    _need(f, "chainId", "registry")
    m = {1: _rid(f), 2: to_int(f["chainId"]), 3: to_addr(f["registry"], "registry")}
    for k, name in PAIR_OPT:
        if f.get(name) is not None:
            m[k] = to_addr(f[name], name)
    if f.get("now") is not None:
        m[9] = to_int(f["now"])
    for k, name in PAIR_FLOORS:
        if f.get(name) is not None:
            v = to_int(f[name])
            if not 0 <= v < (1 << 63):
                raise ProtoError(name + ": must be 0 .. 2^63-1")
            m[k] = v
    return m


def cosign_calldata(f):
    n = sum(k in f for k in ("calldata", "transfer", "approve", "transferFrom"))
    if n > 1:
        raise ProtoError("give only one of calldata / transfer / approve / transferFrom")
    if "transfer" in f:
        t = f["transfer"]
        return E.calldata("transfer", to_addr(t["to"]), to_int(t["amount"]))
    if "approve" in f:
        t = f["approve"]
        return E.calldata("approve", to_addr(t["spender"]), to_int(t["amount"]))
    if "transferFrom" in f:
        t = f["transferFrom"]
        return E.calldata("transferFrom", to_addr(t["from"]), to_addr(t["to"]), to_int(t["amount"]))
    return to_bytes(f.get("calldata", ""), None, "calldata")


def build_cosign_req(f):
    _need(f, "chainId", "enforcer", "delegationHash", "delegator", "redeemer", "target", "nonce", "expiry")
    m = {1: _rid(f), 2: to_int(f["chainId"]), 3: to_addr(f["enforcer"], "enforcer"),
         4: to_bytes(f["delegationHash"], 32, "delegationHash"), 5: to_addr(f["delegator"], "delegator"),
         6: to_addr(f["redeemer"], "redeemer"), 7: to_addr(f["target"], "target"), 8: u256_min(f.get("value", 0)),
         9: cosign_calldata(f), 10: u256_min(f["nonce"]), 11: to_int(f["expiry"])}
    if "risk" in f:
        r = f["risk"]
        m[12] = {1: _text(r.get("src", ""), 64, "risk.src"), 2: _text(r.get("category", ""), 64, "risk.category"),
                 3: _text(r.get("label", ""), 64, "risk.label"), 4: to_int(r.get("ageDays", 0))}
    if "ai" in f:
        a = f["ai"]
        am = {1: _text(ai_text_trunc(a.get("text", "")), 100, "ai.text")}
        if a.get("claims"):
            c = a["claims"]
            am[2] = {1: to_addr(c["to"], "ai.claims.to"), 2: to_addr(c.get("token", "0x" + "00" * 20), "ai.claims.token"),
                     3: u256_min(c["amount"])}
        m[13] = am
    if "budgetLeft" in f:
        m[14] = u256_min(f["budgetLeft"])
    if "decimals" in f:
        m[15] = to_int(f["decimals"])
    if "symbol" in f:
        m[16] = _text(f["symbol"], 16, "symbol")
    return m


def build_mandate_req(f):
    _need(f, "chainId", "manager", "delegate", "delegator", "caveats", "salt")
    cav = [caveat_from_spec(c) for c in f["caveats"]]
    m = {1: _rid(f), 2: to_int(f["chainId"]), 3: to_addr(f["manager"], "manager"),
         4: to_addr(f["delegate"], "delegate"), 5: to_addr(f["delegator"], "delegator"),
         6: to_bytes(f.get("authority", ROOT), 32, "authority"), 7: cav, 8: u256_min(f["salt"])}
    if "label" in f:
        m[9] = _text(f["label"], 64, "label")
    if "agentId" in f:
        m[10] = to_int(f["agentId"])
    return m


def build_deny_req(f):
    _need(f, "chainId", "relay", "agentId", "requestHash")
    return {1: _rid(f), 2: to_int(f["chainId"]), 3: to_addr(f["relay"], "relay"), 4: to_int(f["agentId"]),
            5: to_bytes(f["requestHash"], 32, "requestHash")}


def build_privy_req(f):
    _need(f, "json")
    j = f["json"]
    js = j.encode("utf-8") if isinstance(j, str) else (bytes(j) if isinstance(j, (bytes, bytearray)) else canonical_json(j))
    return {1: _rid(f), 2: js}


BUILDERS = {"pair": build_pair_req, "cosign": build_cosign_req, "mandate": build_mandate_req,
            "deny": build_deny_req, "privy": build_privy_req}


# ================================================================================================ request readers
def _rid_of(v):
    if isinstance(v, U.Tag) and v.tag == 37:
        v = v.value
    if not isinstance(v, bytes) or len(v) != 16:
        raise ProtoError("req-id must be bstr(16)")
    return v


def read_fields(kind, m):
    """request CBOR map -> normalised field dict (ints / bytes). Lenient: the device is the strict one."""
    if not isinstance(m, dict):
        raise ProtoError("request is not a map")
    q = {"kind": kind, "reqId": _rid_of(m[1])}
    if kind == "pair":
        q.update(chainId=m[2], registry=m[3], now=m.get(9))
        for k, name in PAIR_OPT + PAIR_FLOORS:
            q[name] = m.get(k)
    elif kind == "cosign":
        q.update(chainId=m[2], enforcer=m[3], delegationHash=m[4], delegator=m[5], redeemer=m[6], target=m[7],
                 value=to_int(m[8]), calldata=m[9], nonce=to_int(m[10]), expiry=m[11])
        if 13 in m and 2 in m[13]:
            c = m[13][2]
            q["claims"] = {"to": c[1], "token": c[2], "amount": to_int(c[3])}
        q["ai"] = m[13][1] if 13 in m else None
        q["risk"] = m.get(12)
        q["decimals"] = m.get(15, 18)
        q["symbol"] = m.get(16, "")
        q["hasDecimals"] = 15 in m
        q["hasSymbol"] = 16 in m
        q["budgetLeft"] = to_int(m[14]) if 14 in m else None
    elif kind == "mandate":
        q.update(chainId=m[2], manager=m[3], delegate=m[4], delegator=m[5], authority=m[6],
                 caveats=[(c[0], c[1]) for c in m[7]], salt=to_int(m[8]), label=m.get(9), agentId=m.get(10))
    elif kind == "deny":
        q.update(chainId=m[2], relay=m[3], agentId=m[4], requestHash=m[5])
    elif kind == "privy":
        q.update(json=m[2])
    return q


# ================================================================================================ digests (ref_eip712)
def dom(kind, chain, contract):
    return E.domain_ripar(DOMAIN_OF[kind], chain, contract)


def presence_hash(ev12, salt16):
    return hashlib.sha256(bytes(ev12) + bytes(salt16)).digest()


def cosign_digest(q, presence):
    msg = {"delegationHash": q["delegationHash"], "delegator": q["delegator"], "redeemer": q["redeemer"],
           "target": q["target"], "value": q["value"], "callDataHash": keccak256(q["calldata"]), "nonce": q["nonce"],
           "expiry": q["expiry"], "presenceHash": presence}
    return E.digest(dom("cosign", q["chainId"], q["enforcer"]), "HumanApproval", msg)


def cosign_request_hash(q):
    """security review MINOR 7: hashStruct(HumanApproval) of the reviewed request with presenceHash = 0 (the device
    computes it for a deny from the co-sign review; the companion never supplies it)"""
    msg = {"delegationHash": q["delegationHash"], "delegator": q["delegator"], "redeemer": q["redeemer"],
           "target": q["target"], "value": q["value"], "callDataHash": keccak256(q["calldata"]), "nonce": q["nonce"],
           "expiry": q["expiry"], "presenceHash": b"\x00" * 32}
    return E.hash_struct("HumanApproval", msg)


def delegation_struct_hash(q):
    msg = {"delegate": q["delegate"], "delegator": q["delegator"], "authority": q["authority"],
           "caveats": [{"enforcer": e, "terms": t} for e, t in q["caveats"]], "salt": q["salt"]}
    return E.hash_struct("Delegation", msg)


def mandate_digest(q):
    sh = delegation_struct_hash(q)
    mm = E.mm_delegation_hash(q["delegate"], q["delegator"], q["authority"], q["caveats"], q["salt"])
    assert sh == mm, "generic EIP-712 and MetaMask EncoderLib disagree"
    return E.digest_from(E.domain_separator(dom("mandate", q["chainId"], q["manager"])), sh)


def deny_digest(q, presence):
    return E.digest(dom("deny", q["chainId"], q["relay"]), "Deny",
                    {"agentId": q["agentId"], "requestHash": q["requestHash"], "presenceHash": presence})


def pair_digest(chain, registry, k1addr, p1xy):
    return E.digest(dom("pair", chain, registry), "BindDevice", {"owner": k1addr, "px": p1xy[:32], "py": p1xy[32:]})


def revoke_digest(chain, enforcer, dh):
    return E.digest(dom("revoke", chain, enforcer), "Revoke", {"delegationHash": dh})


def panic_digest(chain, enforcer, min_epoch):
    return E.digest(dom("panic", chain, enforcer), "Panic", {"minEpoch": min_epoch})


def reopen_digest(chain, sentinel, vault, nonce):
    return E.digest(dom("reopen", chain, sentinel), "Reopen", {"vault": vault, "nonce": nonce})


# ================================================================================================ Privy allow-list (independent)
PRIVY_WALLETS = "https://api.privy.io/v1/wallets/"
PRIVY_QUORUMS = "https://api.privy.io/v1/key_quorums/"
_PRIVY_ID = re.compile(r"[A-Za-z0-9_:.\-]{1,64}\Z")
SPKI_P256_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200") + b"\x04"


def p256_spki_b64(xy):
    """base64 DER SubjectPublicKeyInfo of an uncompressed P-256 key (Privy key quorum public_keys format)"""
    return base64.b64encode(SPKI_P256_PREFIX + to_bytes(xy, 64, "P-256 key")).decode("ascii")


def _jload(js):
    def reject(c):
        raise ProtoError("JSON constant " + c)
    return json.loads(js.decode("utf-8"), object_pairs_hook=lambda pairs: ("obj", pairs),
                      parse_int=lambda s: ("num", s), parse_float=lambda s: ("num", s), parse_constant=reject)


def _is_obj(v):
    return isinstance(v, tuple) and v[0] == "obj"


def _id_list(v, what):
    if not isinstance(v, list):
        raise ProtoError(what + " must be an array")
    if len(v) > 8:
        raise ProtoError(what + " has more than 8 entries")
    for e in v:
        if not isinstance(e, str) or not _PRIVY_ID.match(e):
            raise ProtoError(what + " entries must be ids")
    return list(v)


def _allowed(pairs, names, what):
    for k, _ in pairs:
        if k not in names:
            raise ProtoError("%s member %r is not allowed" % (what, k))


def privy_parse(js):
    """Independent reference of the device's Privy allow-list (security review M1). -> view dict; ProtoError for
    anything the device must refuse (JSON strictness via _json_syntax_invalid, then the request shape)."""
    js = bytes(js)
    if not js or _json_syntax_invalid(js):
        raise ProtoError("JSON is not strict RFC 8259 (or has duplicate keys / too deep)")
    doc = _jload(js)
    if not _is_obj(doc):
        raise ProtoError("top level is not an object")
    _allowed(doc[1], ("version", "method", "url", "body", "headers"), "top-level")
    top = dict(doc[1])
    if top.get("version") != ("num", "1"):
        raise ProtoError("version must be the number 1")
    for k in ("method", "url"):
        if not isinstance(top.get(k), str):
            raise ProtoError(k + " must be a string")
    if not _is_obj(top.get("headers")):
        raise ProtoError("headers must be an object")
    if "body" not in top:
        raise ProtoError("body is missing")
    if top["method"] != "PATCH":
        raise ProtoError("method must be PATCH")
    url = top["url"]
    if url.startswith(PRIVY_WALLETS) and len(url) > len(PRIVY_WALLETS):
        kind, rid = "wallet", url[len(PRIVY_WALLETS):]
    elif url.startswith(PRIVY_QUORUMS) and len(url) > len(PRIVY_QUORUMS):
        kind, rid = "key_quorum", url[len(PRIVY_QUORUMS):]
    else:
        raise ProtoError("url is not a Privy wallet / key quorum")
    if not _PRIVY_ID.match(rid):
        raise ProtoError("bad id in url")
    hdr = top["headers"][1]
    _allowed(hdr, ("privy-app-id", "privy-idempotency-key"), "header")
    hd = dict(hdr)
    if not isinstance(hd.get("privy-app-id"), str) or not _PRIVY_ID.match(hd["privy-app-id"]):
        raise ProtoError("privy-app-id must be an id")
    idem = hd.get("privy-idempotency-key")
    if idem is not None and (not isinstance(idem, str) or not _PRIVY_ID.match(idem)):
        raise ProtoError("privy-idempotency-key must be an id")
    body = top["body"]
    if not _is_obj(body) or not body[1]:
        raise ProtoError("body must be a non-empty object")
    v = {"kind": kind, "id": rid, "app": hd["privy-app-id"], "idem": idem, "method": "PATCH",
         "path": url[len("https://api.privy.io"):]}
    b = dict(body[1])
    if kind == "wallet":
        _allowed(body[1], ("policy_ids", "additional_signers"), "wallet body")
        if "policy_ids" in b:
            v["policy_ids"] = _id_list(b["policy_ids"], "policy_ids")
        if "additional_signers" in b:
            sg = b["additional_signers"]
            if not isinstance(sg, list) or len(sg) > 8:
                raise ProtoError("additional_signers must be an array of <= 8")
            out = []
            for e in sg:
                if not _is_obj(e):
                    raise ProtoError("signer must be an object")
                _allowed(e[1], ("signer_id", "override_policy_ids"), "signer")
                ed = dict(e[1])
                if not isinstance(ed.get("signer_id"), str) or not _PRIVY_ID.match(ed["signer_id"]):
                    raise ProtoError("signer_id must be an id")
                ov = _id_list(ed["override_policy_ids"], "override_policy_ids") if "override_policy_ids" in ed else None
                out.append((ed["signer_id"], ov))
            v["signers"] = out
    else:
        _allowed(body[1], ("public_keys", "authorization_threshold", "display_name", "user_ids", "key_quorum_ids"),
                 "key quorum body")
        if "public_keys" in b:
            pk = b["public_keys"]
            if not isinstance(pk, list) or not 1 <= len(pk) <= 8:
                raise ProtoError("public_keys must be an array of 1..8")
            xys = []
            for e in pk:
                if not isinstance(e, str):
                    raise ProtoError("public key must be a string")
                try:
                    der = base64.b64decode(e.encode("ascii"), validate=True)
                except (ValueError, UnicodeEncodeError):
                    raise ProtoError("public key is not base64")
                if base64.b64encode(der).decode("ascii") != e:
                    raise ProtoError("public key base64 is not canonical")
                if len(der) != 91 or der[:27] != SPKI_P256_PREFIX:
                    raise ProtoError("public key is not an uncompressed P-256 SPKI")
                xys.append(der[27:])
            v["public_keys"] = xys
        if "authorization_threshold" in b:
            t = b["authorization_threshold"]
            if not (isinstance(t, tuple) and t[0] == "num" and re.match(r"[1-9][0-9]?\Z", t[1])):
                raise ProtoError("authorization_threshold must be an integer 1..99")
            v["threshold"] = int(t[1])
        if "display_name" in b:
            n = b["display_name"]
            if not isinstance(n, str) or len(n.encode("utf-8")) > 64 or any(not 0x20 <= ord(c) <= 0x7E for c in n):
                raise ProtoError("display_name must be printable ASCII <= 64")
            v["display_name"] = n
        for k in ("user_ids", "key_quorum_ids"):
            if k in b:
                v[k] = _id_list(b[k], k)
    return v


def privy_dump(v):
    """Canonical text of a parsed Privy request (same format as test_protocol.cpp privy_dump())."""
    L = ["kind=%s id=%s app=%s idem=%s" % (v["kind"], v["id"], v["app"], v["idem"] if v["idem"] is not None else "-")]
    if "policy_ids" in v:
        L.append("policy_ids=" + ",".join(v["policy_ids"]))
    if "signers" in v:
        L.append("signers=" + ";".join(sid + ("" if ov is None else "[" + ",".join(ov) + "]") for sid, ov in v["signers"]))
    if "public_keys" in v:
        L.append("public_keys=" + ",".join(h(x) for x in v["public_keys"]))
    if "threshold" in v:
        L.append("threshold=%d" % v["threshold"])
    if "display_name" in v:
        L.append("display_name=" + v["display_name"])
    for k in ("user_ids", "key_quorum_ids"):
        if k in v:
            L.append(k + "=" + ",".join(v[k]))
    return "\n".join(L)


# ================================================================================================ demo device
def demo_keys(seed=DEMO_SEED):
    k1 = rc.derive_path(rc.K1, seed, rc.PATH_K1)
    p1 = rc.derive_path(rc.P1, seed, rc.PATH_P1)
    k1pub = rc.pubkey(rc.K1, k1)
    p1pub = rc.pubkey(rc.P1, p1)
    return {"k1": k1, "p1": p1, "k1addr": rc.eth_address(k1pub), "p1xy": rc.xy64(p1pub)}


def sign_p1(keys, digest):
    r, s, _ = rc.sign(rc.P1, keys["p1"], digest)
    return rc.i2b(r) + rc.i2b(s)


def sign_k1(keys, digest):
    r, s, recid = rc.sign(rc.K1, keys["k1"], digest)
    return rc.i2b(r) + rc.i2b(s) + bytes([27 + recid])


def demo_evidence(bpm=72):
    ir, red, dur = 120000, 90000, 800
    return bytes([1, bpm, 9]) + ir.to_bytes(3, "big") + red.to_bytes(3, "big") + bytes([42]) + dur.to_bytes(2, "big")


def simulate_deny_from_cosign(q, keys, chain, relay, agent_id, ev12=None, salt16=None):
    """ripar-deny the device builds when SIGN is held 2 s on a co-sign review (MINOR 7): requestHash computed from the
    reviewed request, chain + relay + agentId from the device's pinned context (given here)."""
    ev12 = bytes(12) if ev12 is None else ev12
    salt16 = os.urandom(16) if salt16 is None else salt16
    d = {"reqId": q["reqId"], "chainId": chain, "relay": relay, "agentId": agent_id, "requestHash": cosign_request_hash(q)}
    rs = sign_p1(keys, deny_digest(d, presence_hash(ev12, salt16)))
    return U.cbor({1: q["reqId"], 2: rs, 3: ev12, 4: salt16, 5: agent_id, 6: d["requestHash"]})


def simulate(kind, q, keys, ev12=None, salt16=None, fwid=None):
    """-> response CBOR bytes, as the device builds it (the pulse gate and the pinned-context policy are NOT
    simulated; token-table and Privy allow-list refusals are)."""
    ev12 = demo_evidence() if ev12 is None else ev12
    salt16 = os.urandom(16) if salt16 is None else salt16
    if kind == "pair":
        fwid = hashlib.sha256(b"ripar demo firmware").digest()[:8] if fwid is None else fwid
        d = pair_digest(q["chainId"], q["registry"], keys["k1addr"], keys["p1xy"])
        return U.cbor({1: q["reqId"], 2: keys["k1addr"], 3: keys["p1xy"], 4: sign_p1(keys, d), 5: sign_k1(keys, d),
                       6: fwid})
    if kind == "cosign":
        token_check(q)  # the device refuses a listed token whose keys 15 / 16 disagree with its table
        rs = sign_p1(keys, cosign_digest(q, presence_hash(ev12, salt16)))
        return U.cbor({1: q["reqId"], 2: rs, 3: ev12, 4: salt16})
    if kind == "mandate":
        if q["authority"] != ROOT:
            raise ProtoError("device refuses non-ROOT authority")
        return U.cbor({1: q["reqId"], 2: sign_k1(keys, mandate_digest(q))})
    if kind == "deny":
        rs = sign_p1(keys, deny_digest(q, presence_hash(ev12, salt16)))
        return U.cbor({1: q["reqId"], 2: rs, 3: ev12, 4: salt16, 5: q["agentId"], 6: q["requestHash"]})
    if kind == "privy":
        privy_parse(q["json"])  # the device only signs the allow-listed request shapes
        r, s, _ = rc.sign(rc.P1, keys["p1"], hashlib.sha256(q["json"]).digest())
        return U.cbor({1: q["reqId"], 2: rc.der(r, s)})
    raise ProtoError("unknown kind " + kind)


# ================================================================================================ response parsing + verify
def der_parse(der):
    """strict DER SEQUENCE{INTEGER r, INTEGER s} -> (r, s)"""
    def integer(b, i):
        if i + 2 > len(b) or b[i] != 0x02:
            raise ProtoError("DER: INTEGER expected")
        n = b[i + 1]
        v = b[i + 2:i + 2 + n]
        if n == 0 or len(v) != n or n > 33:
            raise ProtoError("DER: bad INTEGER length")
        if v[0] & 0x80:
            raise ProtoError("DER: negative INTEGER")
        if n > 1 and v[0] == 0 and not (v[1] & 0x80):
            raise ProtoError("DER: non-minimal INTEGER")
        return int.from_bytes(v, "big"), i + 2 + n
    if len(der) < 8 or der[0] != 0x30 or der[1] != len(der) - 2:
        raise ProtoError("DER: bad SEQUENCE")
    r, i = integer(der, 2)
    s, i = integer(der, i)
    if i != len(der):
        raise ProtoError("DER: trailing bytes")
    return r, s


def evidence_fields(ev):
    return {"version": ev[0], "bpm": ev[1], "beats": ev[2], "irDC": int.from_bytes(ev[3:6], "big"),
            "redDC": int.from_bytes(ev[6:9], "big"), "jitter_x1000": ev[9], "duration_ms": 10 * int.from_bytes(ev[10:12], "big")}


class Report(object):
    def __init__(self):
        self.fields, self.checks, self.unverified = {}, [], []

    def check(self, name, ok):
        self.checks.append((name, bool(ok)))
        return ok

    def ok(self):
        return all(c for _, c in self.checks)


def _p256_check(rep, name, xy, digest, rs):
    r, s = int.from_bytes(rs[:32], "big"), int.from_bytes(rs[32:64], "big")
    P = (int.from_bytes(xy[:32], "big"), int.from_bytes(xy[32:], "big"))
    rep.check(name + " low-s", s <= rc.P1.n // 2)
    rep.check(name + " P-256 signature", rc.verify(rc.P1, P, digest, r, s))


def _k1_recover(rep, name, digest, rsv):
    r, s, v = int.from_bytes(rsv[:32], "big"), int.from_bytes(rsv[32:64], "big"), rsv[64]
    rep.check(name + " v is 27/28", v in (27, 28))
    rep.check(name + " low-s", s <= rc.K1.n // 2)
    Q = rc.recover(rc.K1, digest, r, s, v - 27) if v in (27, 28) else None
    rep.check(name + " recoverable", Q is not None)
    return rc.eth_address(Q) if Q else None


def parse_response(ur_text, req=None, p1xy=None, k1addr=None, chain=None, contract=None):
    """-> Report. req = (kind, cbor) of the request (needed to rebuild the digest of request/response types)."""
    utype, cb = ur_read(ur_text.strip())
    m = cbor_decode(cb)
    rep = Report()
    rep.fields["type"] = utype
    if not isinstance(m, dict):
        raise ProtoError("response is not a map")
    q = read_fields(req[0], cbor_decode(req[1])) if req else None

    def need_bytes(k, n):
        v = m.get(k)
        if not isinstance(v, bytes) or (n is not None and len(v) != n):
            raise ProtoError("key %d must be bstr(%s)" % (k, n))
        return v

    def check_reqid():
        rid = need_bytes(1, 16)
        rep.fields["reqId"] = h(rid)
        if q:
            rep.check("req-id echoed", rid == q["reqId"])

    def keys_only(*ks):
        extra = set(m) - set(ks)
        if extra:
            raise ProtoError("unexpected keys %s" % sorted(extra))

    if utype == "ripar-pair":
        keys_only(1, 2, 3, 4, 5, 6)
        k1 = need_bytes(2, 20)
        xy = need_bytes(3, 64)
        rep.fields.update(k1Address=eip55("0x" + h(k1)), p1Key=h(xy), firmwareId=h(need_bytes(6, 8)))
        if 1 in m:
            check_reqid()
        if 4 in m or 5 in m:
            if not q or q["kind"] != "pair":
                rep.unverified.append("BindDevice signatures (give --req with the pair request)")
            else:
                d = pair_digest(q["chainId"], q["registry"], k1, xy)
                rep.fields["bindDigest"] = h(d)
                _p256_check(rep, "BindDevice P1", xy, d, need_bytes(4, 64))
                who = _k1_recover(rep, "BindDevice K1", d, need_bytes(5, 65))
                rep.check("BindDevice K1 recovers the K1 address", who == k1)
        rep.check("P1 key on curve", rc.on_curve(rc.P1, (int.from_bytes(xy[:32], "big"), int.from_bytes(xy[32:], "big"))))
    elif utype == "ripar-cosign":
        keys_only(1, 2, 3, 4)
        check_reqid()
        rs, ev, salt = need_bytes(2, 64), need_bytes(3, 12), need_bytes(4, 16)
        ph = presence_hash(ev, salt)
        rep.fields.update(rs=h(rs), evidence12=h(ev), evidence=evidence_fields(ev), salt16=h(salt), presenceHash=h(ph))
        if not q or q["kind"] != "cosign":
            rep.unverified.append("cosign signature (give --req with the cosign request)")
        elif p1xy is None:
            rep.unverified.append("cosign signature (give --p1 or --pair)")
        else:
            d = cosign_digest(q, ph)
            rep.fields["digest"] = h(d)
            _p256_check(rep, "cosign", p1xy, d, rs)
        if q and q["kind"] == "cosign":
            # what the companion relays as caveat args: abi.encode(nonce, expiry, presenceHash, r, s)
            args = (q["nonce"].to_bytes(32, "big") + q["expiry"].to_bytes(32, "big") + ph + rs[:32] + rs[32:])
            rep.fields["caveatArgs"] = "0x" + h(args)
    elif utype == "ripar-deny":
        keys_only(1, 2, 3, 4, 5, 6)
        check_reqid()
        rs, ev, salt, rh = need_bytes(2, 64), need_bytes(3, 12), need_bytes(4, 16), need_bytes(6, 32)
        if not isinstance(m.get(5), int) or m[5] < 0:
            raise ProtoError("key 5 (agentId) must be uint")
        agent = m[5]
        ph = presence_hash(ev, salt)
        rep.fields.update(rs=h(rs), evidence12=h(ev), evidence=evidence_fields(ev), salt16=h(salt), presenceHash=h(ph),
                          agentId=agent, requestHash=h(rh))
        dq = None
        if q and q["kind"] == "deny":  # deny of a companion deny-req: the device echoes what it signed
            rep.check("agentId echoed", agent == q["agentId"])
            rep.check("requestHash echoed", rh == q["requestHash"])
            dq = q
        elif q and q["kind"] == "cosign":  # deny from a co-sign review: requestHash computed by the device
            rep.check("requestHash = hashStruct(HumanApproval) of the co-sign request", rh == cosign_request_hash(q))
            if contract is None:
                rep.unverified.append("deny signature (give --contract RELAY; chain = --chain or the request's)")
            else:
                dq = {"chainId": chain if chain is not None else q["chainId"], "relay": contract, "agentId": agent,
                      "requestHash": rh}
        elif chain is not None and contract is not None:
            dq = {"chainId": chain, "relay": contract, "agentId": agent, "requestHash": rh}
        else:
            rep.unverified.append("deny signature (give --req, or --chain and --contract RELAY)")
        if dq is not None:
            if p1xy is None:
                rep.unverified.append("deny signature (give --p1 or --pair)")
            else:
                d = deny_digest(dq, ph)
                rep.fields["digest"] = h(d)
                _p256_check(rep, "deny", p1xy, d, rs)
    elif utype == "eth-signature":
        keys_only(1, 2)
        check_reqid()
        rsv = need_bytes(2, 65)
        rep.fields["rsv"] = h(rsv)
        if not q or q["kind"] != "mandate":
            rep.unverified.append("mandate signature (give --req with the mandate request)")
        else:
            d = mandate_digest(q)
            rep.fields.update(delegationHash=h(delegation_struct_hash(q)), digest=h(d))
            who = _k1_recover(rep, "mandate K1", d, rsv)
            if who:
                rep.fields["signer"] = eip55("0x" + h(who))
            if k1addr is None:
                rep.unverified.append("mandate signer identity (give --k1 or --pair)")
            else:
                rep.check("mandate signed by the paired K1", who == k1addr)
    elif utype == "ripar-der-sig":
        keys_only(1, 2)
        check_reqid()
        der = need_bytes(2, None)
        r, s = der_parse(der)
        rep.fields.update(der=h(der), r=h(rc.i2b(r)), s=h(rc.i2b(s)))
        if not q or q["kind"] != "privy":
            rep.unverified.append("Privy signature (give --req with the privy request)")
        elif p1xy is None:
            rep.unverified.append("Privy signature (give --p1 or --pair)")
        else:
            d = hashlib.sha256(q["json"]).digest()
            _p256_check(rep, "privy", p1xy, d, rc.i2b(r) + rc.i2b(s))
    elif utype in ("ripar-revoke", "ripar-panic", "ripar-reopen"):
        if utype == "ripar-revoke":
            keys_only(1, 2)
            dh, rs = need_bytes(1, 32), need_bytes(2, 64)
            rep.fields.update(delegationHash=h(dh), rs=h(rs))
            dig = (lambda: revoke_digest(chain, contract, dh))
        elif utype == "ripar-panic":
            keys_only(1, 2)
            if not isinstance(m.get(1), int) or m[1] < 0:
                raise ProtoError("key 1 must be uint")
            me, rs = m[1], need_bytes(2, 64)
            rep.fields.update(minEpoch=me, rs=h(rs))
            dig = (lambda: panic_digest(chain, contract, me))
        else:
            keys_only(1, 2, 3)
            vault, nb, rs = need_bytes(1, 20), need_bytes(2, None), need_bytes(3, 64)
            if len(nb) > 32:
                raise ProtoError("nonce longer than 32 bytes")
            nonce = int.from_bytes(nb, "big")
            rep.fields.update(vault=eip55("0x" + h(vault)), nonce=nonce, rs=h(rs))
            dig = (lambda: reopen_digest(chain, contract, vault, nonce))
        if chain is None or contract is None:
            rep.unverified.append("%s signature (give --chain and --contract)" % utype)
        elif p1xy is None:
            rep.unverified.append("%s signature (give --p1 or --pair)" % utype)
        else:
            d = dig()
            rep.fields["digest"] = h(d)
            _p256_check(rep, utype, p1xy, d, rs)
    else:
        raise ProtoError("unknown response type " + utype)
    return rep


# ================================================================================================ C++ test vectors
def c_str(s):
    return E.c_str(s)


def hx(b):
    return '"' + h(b) + '"'


def u256s(x):
    return '"' + x.to_bytes(32, "big").hex() + '"'


def u64s(x):
    return "0x%016xull" % x


def rb(rng, n):
    return bytes(rng.getrandbits(8) for _ in range(n))


def raddr(rng):
    a = rb(rng, 20)
    return a if any(a) else b"\x01" + a[1:]


MM = MM_ENF


def _pj(body="<default>", url="https://api.privy.io/v1/wallets/w1", method="PATCH", headers=None, drop=()):
    d = {"version": 1, "method": method, "url": url, "body": {"policy_ids": ["p1"]} if body == "<default>" else body,
         "headers": {"privy-app-id": "app1"} if headers is None else headers}
    for k in drop:
        d.pop(k)
    return canonical_json(d)


_PRIVY_VALID_CACHE = []


def privy_valid():
    """(name, json bytes) the device must accept (allow-listed shapes), each shown in full."""
    if _PRIVY_VALID_CACHE:
        return _PRIVY_VALID_CACHE
    me = demo_keys()["p1xy"]
    other = rc.xy64(rc.pubkey(rc.P1, 0x1234567))
    qurl = "https://api.privy.io/v1/key_quorums/kq1abc"
    _PRIVY_VALID_CACHE.extend([
        ("add signer (canonical)", canonical_json({
            "version": 1, "method": "PATCH", "url": "https://api.privy.io/v1/wallets/wl8yz4c2rq0q1cdz2q8a4",
            "body": {"additional_signers": [{"signer_id": "kq7ks9z3n1v2lq4d7w0p8m3y", "override_policy_ids": ["pol9x2"]}]},
            "headers": {"privy-app-id": "cm0appid1234"}})),
        ("remove signers", canonical_json({
            "version": 1, "method": "PATCH", "url": "https://api.privy.io/v1/wallets/wl8yz4c2rq0q1cdz2q8a4",
            "body": {"additional_signers": []}, "headers": {"privy-app-id": "cm0appid1234"}})),
        ("set policy + idempotency key", _pj(body={"policy_ids": ["pol9x2k4m8"]}, headers={
            "privy-app-id": "cm0appid1234", "privy-idempotency-key": "4b1d3c2a-7e1f-4c55-9a0b-2f6d8e1c3b7a"})),
        ("two signers: the second one is shown in full (review probe M1)", _pj(body={"additional_signers": [
            {"signer_id": "agent", "override_policy_ids": ["pol1"]}, {"signer_id": "ATTACKERkq0000000000000000"}]})),
        ("remove every policy + signer with empty override", _pj(body={
            "policy_ids": [], "additional_signers": [{"signer_id": "s1", "override_policy_ids": []}]})),
        ("key quorum: this device + another key", _pj(url=qurl, body={
            "public_keys": [p256_spki_b64(me), p256_spki_b64(other)], "authorization_threshold": 1,
            "display_name": "Ripar owner quorum"})),
        ("key quorum: users + nested quorums", _pj(url=qurl, body={
            "user_ids": ["did:privy:cm0user1"], "key_quorum_ids": ["kq2", "kq3"], "authorization_threshold": 12})),
        ("whitespace + escapes (exact bytes signed)",
         b' { "version" : 1 ,\r\n "method":"PATCH", "url":"https:\\/\\/api.privy.io\\/v1\\/wallets\\/w1",'
         b'\t"headers":{"privy-app-id":"app\\u0031"}, "body":{"policy_ids":["p\\u0031"]} } \n'),
        ("maximum sizes: 64-character ids, 8 entries", _pj(
            url="https://api.privy.io/v1/wallets/" + "w" * 64,
            body={"policy_ids": [("p%d" % i) * 32 for i in range(8)],
                  "additional_signers": [{"signer_id": ("s%d" % i) + "x" * 62, "override_policy_ids": ["o" * 64] * 8}
                                         for i in range(8)]},
            headers={"privy-app-id": "a" * 64, "privy-idempotency-key": "k" * 64})),
        ("key quorum: 8 keys, name of 64 bytes", _pj(url=qurl, body={
            "public_keys": [p256_spki_b64(rc.xy64(rc.pubkey(rc.P1, 1000 + i))) for i in range(8)],
            "display_name": "N" * 64, "authorization_threshold": 99})),
    ])
    return _PRIVY_VALID_CACHE


def _spki_b64_raw(der):
    return base64.b64encode(der).decode("ascii")


_K = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE"  # prefix of every base64 P-256 SPKI
_GOOD_KEY = _spki_b64_raw(SPKI_P256_PREFIX + bytes(range(64)))
_QURL = "https://api.privy.io/v1/key_quorums/kq1"
PRIVY_BASE = b'{"body":{"a":1},"headers":{"privy-app-id":"x"},"method":"PATCH","url":"https://api.privy.io/v1/w","version":1}'
PRIVY_INVALID = [
    # ---- request shapes outside the allow-list (security review M1)
    ("rpc eth_sendTransaction (review probe M1)", _pj(url="https://api.privy.io/v1/wallets/w1/rpc", method="POST", body={
        "method": "eth_sendTransaction", "caip2": "eip155:10143", "params": {"transaction": {
            "to": "0xa9012a055bd4e0eDfF8Ce09f960291C09D5322dC",
            "data": "0xa9059cbb000000000000000000000000" + "11" * 20 + "00" * 31 + "01"}}})),
    ("PATCH wallet rpc path", _pj(url="https://api.privy.io/v1/wallets/w1/rpc")),
    ("POST policies", _pj(method="POST", url="https://api.privy.io/v1/policies", body={
        "chain_type": "ethereum", "name": "x", "rules": [], "version": "1.0"})),
    ("DELETE key quorum", _pj(method="DELETE", url=_QURL, body={})),
    ("GET wallet", _pj(method="GET")),
    ("POST wallet", _pj(method="POST")),
    ("other host", _pj(url="https://evil.example/v1/wallets/w1")),
    ("lookalike host", _pj(url="https://api.privy.io.evil.example/v1/wallets/w1")),
    ("http", _pj(url="http://api.privy.io/v1/wallets/w1")),
    ("query string", _pj(url="https://api.privy.io/v1/wallets/w1?x=1")),
    ("trailing slash", _pj(url="https://api.privy.io/v1/wallets/w1/")),
    ("no id", _pj(url="https://api.privy.io/v1/wallets/")),
    ("id 65 characters", _pj(url="https://api.privy.io/v1/wallets/" + "w" * 65)),
    ("id with space", _pj(url="https://api.privy.io/v1/wallets/w 1")),
    ("id with percent escape", _pj(url="https://api.privy.io/v1/wallets/w%2F1")),
    ("owner change", _pj(body={"owner_id": "kq9"})),
    ("padding keys around the change (review probe M1)", _pj(body={
        "policy_ids": ["p1"], "a1": 1, "a2": 1, "a3": 1, "a4": 1, "a5": 1})),
    ("empty body", _pj(body={})),
    ("body array", _pj(body=[1])),
    ("body null", _pj(body=None)),
    ("body string", _pj(body="policy_ids")),
    ("body missing", _pj(drop=("body",))),
    ("unknown header", _pj(headers={"privy-app-id": "app1", "x-extra": "1"})),
    ("authorization header", _pj(headers={"privy-app-id": "app1", "authorization": "Basic x"})),
    ("missing privy-app-id", _pj(headers={})),
    ("privy-app-id number", _pj(headers={"privy-app-id": 5})),
    ("privy-app-id 65 characters", _pj(headers={"privy-app-id": "a" * 65})),
    ("idempotency key with space", _pj(headers={"privy-app-id": "app1", "privy-idempotency-key": "a b"})),
    ("signer unknown member", _pj(body={"additional_signers": [{"signer_id": "s1", "role": "admin"}]})),
    ("signer without signer_id", _pj(body={"additional_signers": [{"override_policy_ids": []}]})),
    ("signer_id number", _pj(body={"additional_signers": [{"signer_id": 7}]})),
    ("signer_id with slash", _pj(body={"additional_signers": [{"signer_id": "a/b"}]})),
    ("9 signers", _pj(body={"additional_signers": [{"signer_id": "s%d" % i} for i in range(9)]})),
    ("signers object", _pj(body={"additional_signers": {"signer_id": "s1"}})),
    ("signer not an object", _pj(body={"additional_signers": ["s1"]})),
    ("override not an array", _pj(body={"additional_signers": [{"signer_id": "s1", "override_policy_ids": "p1"}]})),
    ("9 override ids", _pj(body={"additional_signers": [{"signer_id": "s1", "override_policy_ids": ["p"] * 9}]})),
    ("9 policy ids", _pj(body={"policy_ids": ["p%d" % i for i in range(9)]})),
    ("policy id 65 characters", _pj(body={"policy_ids": ["p" * 65]})),
    ("policy id non-ASCII", _pj(body={"policy_ids": ["p\u00e9"]})),
    ("policy id empty", _pj(body={"policy_ids": [""]})),
    ("policy_ids string", _pj(body={"policy_ids": "p1"})),
    ("policy_ids null", _pj(body={"policy_ids": None})),
    ("wallet member in a key quorum update", _pj(url=_QURL, body={"policy_ids": ["p1"]})),
    ("key quorum member in a wallet update", _pj(body={"authorization_threshold": 1})),
    ("public key not base64", _pj(url=_QURL, body={"public_keys": ["not base64!"]})),
    ("public key non-canonical base64", _pj(url=_QURL, body={"public_keys": [_GOOD_KEY[:-3] + "B=="]})),
    ("public key without padding", _pj(url=_QURL, body={"public_keys": [_GOOD_KEY.rstrip("=")]})),
    ("public key url-safe alphabet", _pj(url=_QURL, body={"public_keys": [_spki_b64_raw(
        SPKI_P256_PREFIX + b"\xfb" * 64).replace("+", "-").replace("/", "_")]})),
    ("public key compressed point", _pj(url=_QURL, body={"public_keys": [_spki_b64_raw(bytes.fromhex(
        "3039301306072a8648ce3d020106082a8648ce3d030107032200") + b"\x02" + bytes(range(32)))]})),
    ("public key secp256k1", _pj(url=_QURL, body={"public_keys": [_spki_b64_raw(bytes.fromhex(
        "3056301006072a8648ce3d020106052b8104000a034200") + b"\x04" + bytes(range(64)))]})),
    ("public key with trailing byte", _pj(url=_QURL, body={"public_keys": [_spki_b64_raw(
        SPKI_P256_PREFIX + bytes(range(65)))]})),
    ("public key with whitespace", _pj(url=_QURL, body={"public_keys": [" " + _GOOD_KEY]})),
    ("public key PEM", _pj(url=_QURL, body={"public_keys": ["-----BEGIN PUBLIC KEY-----" + _GOOD_KEY]})),
    ("empty public_keys", _pj(url=_QURL, body={"public_keys": []})),
    ("9 public keys", _pj(url=_QURL, body={"public_keys": [_GOOD_KEY] * 9})),
    ("threshold 0", _pj(url=_QURL, body={"authorization_threshold": 0})),
    ("threshold 100", _pj(url=_QURL, body={"authorization_threshold": 100})),
    ("threshold string", _pj(url=_QURL, body={"authorization_threshold": "1"})),
    ("threshold 1.0", _pj(url=_QURL, body={"authorization_threshold": 1.0})),
    ("threshold 1e0", b'{"body":{"authorization_threshold":1e0},"headers":{"privy-app-id":"a"},"method":"PATCH",'
                      b'"url":"https://api.privy.io/v1/key_quorums/kq1","version":1}'),
    ("threshold negative", _pj(url=_QURL, body={"authorization_threshold": -1})),
    ("display_name non-ASCII", _pj(url=_QURL, body={"display_name": "Ripar \u00e9"})),
    ("display_name 65 bytes", _pj(url=_QURL, body={"display_name": "n" * 65})),
    ("display_name tab", _pj(url=_QURL, body={"display_name": "a\tb"})),
    ("user_ids with a number", _pj(url=_QURL, body={"user_ids": [1]})),
    ("version 2", _pj().replace(b'"version":1', b'"version":2')),
    ("version string", _pj().replace(b'"version":1', b'"version":"1"')),
    ("version 1.0", _pj().replace(b'"version":1', b'"version":1.0')),
    ("method lower-case", _pj(method="patch")),
    ("method number", _pj().replace(b'"method":"PATCH"', b'"method":1')),
    ("url number", _pj().replace(b'"url":"https://api.privy.io/v1/wallets/w1"', b'"url":7')),
    ("headers array", _pj().replace(b'"headers":{"privy-app-id":"app1"}', b'"headers":[]')),
    ("unknown top-level key", _pj()[:-1] + b',"zz":1}'),
    ("missing method", _pj(drop=("method",))),
    ("missing url", _pj(drop=("url",))),
    ("missing headers", _pj(drop=("headers",))),
    ("missing version", _pj(drop=("version",))),
    # ---- strict JSON (the parser itself refuses these)
    ("duplicate key", b'{"body":{"a":1,"a":2},"headers":{},"method":"PATCH","url":"https://api.privy.io/v1/w","version":1}'),
    ("duplicate key via escape", b'{"body":{"a":1,"\\u0061":2},"headers":{},"method":"PATCH","url":"https://api.privy.io/v","version":1}'),
    ("duplicate top-level key", b'{"method":"PATCH","body":{},"headers":{},"method":"GET","url":"https://api.privy.io/v","version":1}'),
    ("duplicate in nested array object", b'{"body":{"s":[{"id":1,"id":1}]},"headers":{},"method":"PATCH","url":"https://api.privy.io/v","version":1}'),
    ("duplicate policy_ids member", b'{"body":{"policy_ids":["p1"],"policy_ids":["evil"]},"headers":{"privy-app-id":"a"},"method":"PATCH","url":"https://api.privy.io/v1/wallets/w1","version":1}'),
    ("trailing garbage", PRIVY_BASE + b"x"),
    ("second value", PRIVY_BASE + b" {}"),
    ("trailing NUL", PRIVY_BASE + b"\x00"),
    ("trailing comma object", PRIVY_BASE[:-1] + b",}"),
    ("trailing comma array", b'{"body":[1,],"headers":{},"method":"PATCH","url":"https://api.privy.io/v","version":1}'),
    ("depth 17", b'{"body":{"k":' + b"[" * 15 + b"1" + b"]" * 15 + b'},"headers":{},"method":"GET","url":"https://api.privy.io/v","version":1}'),
    ("invalid UTF-8 byte", b'{"body":{"a":"\xff"},"headers":{},"method":"PATCH","url":"https://api.privy.io/v","version":1}'),
    ("overlong UTF-8", b'{"body":{"a":"\xc0\xaf"},"headers":{},"method":"PATCH","url":"https://api.privy.io/v","version":1}'),
    ("UTF-8 surrogate", b'{"body":{"a":"\xed\xa0\x80"},"headers":{},"method":"PATCH","url":"https://api.privy.io/v","version":1}'),
    ("truncated UTF-8", b'{"body":{"a":"\xe2\x82"},"headers":{},"method":"PATCH","url":"https://api.privy.io/v","version":1}'),
    ("lone high surrogate", b'{"body":{"a":"\\ud83d"},"headers":{},"method":"PATCH","url":"https://api.privy.io/v","version":1}'),
    ("lone low surrogate", b'{"body":{"a":"\\ude00"},"headers":{},"method":"PATCH","url":"https://api.privy.io/v","version":1}'),
    ("high + non-low surrogate", b'{"body":{"a":"\\ud83d\\u0041"},"headers":{},"method":"PATCH","url":"https://api.privy.io/v","version":1}'),
    ("escaped NUL", b'{"body":{"a":"\\u0000"},"headers":{},"method":"PATCH","url":"https://api.privy.io/v","version":1}'),
    ("raw control char", b'{"body":{"a":"x\ny"},"headers":{},"method":"PATCH","url":"https://api.privy.io/v","version":1}'),
    ("bad escape", b'{"body":{"a":"\\x41"},"headers":{},"method":"PATCH","url":"https://api.privy.io/v","version":1}'),
    ("leading zero", b'{"body":{"a":01},"headers":{},"method":"PATCH","url":"https://api.privy.io/v","version":1}'),
    ("plus sign", b'{"body":{"a":+1},"headers":{},"method":"PATCH","url":"https://api.privy.io/v","version":1}'),
    ("bare fraction", b'{"body":{"a":.5},"headers":{},"method":"PATCH","url":"https://api.privy.io/v","version":1}'),
    ("dangling dot", b'{"body":{"a":1.},"headers":{},"method":"PATCH","url":"https://api.privy.io/v","version":1}'),
    ("NaN", b'{"body":{"a":NaN},"headers":{},"method":"PATCH","url":"https://api.privy.io/v","version":1}'),
    ("single quotes", b"{'body':{},'headers':{},'method':'PATCH','url':'https://api.privy.io/v','version':1}"),
    ("comment", b'{"body":{}/*x*/,"headers":{},"method":"PATCH","url":"https://api.privy.io/v","version":1}'),
    ("BOM", b"\xef\xbb\xbf" + PRIVY_BASE),
    ("bad literal", b'{"body":{"a":tru},"headers":{},"method":"PATCH","url":"https://api.privy.io/v","version":1}'),
    ("unterminated string", b'{"body":{"a":"abc},"headers":{},"method":"PATCH","url":"https://api.privy.io/v","version":1}'),
    ("unterminated object", PRIVY_BASE[:-1]),
    ("empty document", b""),
    ("only whitespace", b"  \n"),
    ("top-level array", b'[{"version":1}]'),
]

JSON_VALID_EXTRA = [  # json_parse_strict only (not Privy-shaped)
    b"0", b"-0", b"1.5e-3", b"-12.25E+10", b"true", b"null", b'"a\\"\\\\\\/\\b\\f\\n\\r\\t"', b"[]", b"{}",
    b" [ 1 , { \"a\" : [ ] } ] ", b'"\\uD834\\uDD1E"', b'"\x7f"', b"[" * 16 + b"]" * 16,
]
JSON_INVALID_EXTRA = [b"[" * 17 + b"]" * 17, b"-", b"1e", b"1e+", b"01", b"[1 2]", b'{"a" 1}', b'{"a":}', b"{,}",
                      b'"abc', b"\"\\u12\"", b"\"\\uZZZZ\"", b"nul", b"1 2", b"\t", b"{\"a\":1}}", b"[1]]",
                      b"[[,,1]", b"[,1]", b"[,]", b'{"a":[,,"b"]}', b"{\"a\":1,}", b"-01", b"0x10", b"1.5.2"]


def _mk_cosign(rng, variant):
    target = raddr(rng)
    to = raddr(rng)
    f = {"reqId": rb(rng, 16), "chainId": 10143, "enforcer": raddr(rng), "delegationHash": rb(rng, 32),
         "delegator": raddr(rng), "redeemer": raddr(rng), "target": target, "value": 0, "nonce": rng.getrandbits(64),
         "expiry": 1790000000 + rng.randrange(100000)}
    z20 = b"\x00" * 20
    if variant == 0:  # minimal native transfer
        f["value"] = rng.randrange(1, 10 ** 18)
    elif variant == 1:  # ERC-20 transfer, matching claims, all optionals
        amt = rng.randrange(1, 10 ** 8)
        f["transfer"] = {"to": to, "amount": amt}
        f["risk"] = {"src": "Nansen", "category": "Exchange", "label": "Binance 14", "ageDays": 1234}
        f["ai"] = {"text": "Paying the invoice #1042 to the usual supplier", "claims": {"to": to, "token": target, "amount": amt}}
        f["budgetLeft"] = 50 * 10 ** 6
        f["decimals"] = 6
        f["symbol"] = "AUSD"
    elif variant == 2:  # claims amount differs by one
        amt = rng.randrange(1, 10 ** 8)
        f["transfer"] = {"to": to, "amount": amt}
        f["ai"] = {"text": "pay", "claims": {"to": to, "token": target, "amount": amt + 1}}
    elif variant == 3:  # approve, matching claims (spender = to)
        amt = MAX256
        f["approve"] = {"spender": to, "amount": amt}
        f["ai"] = {"text": "approve router", "claims": {"to": to, "token": target, "amount": amt}}
    elif variant == 4:  # transferFrom matching fields but native value attached -> no match
        amt = rng.randrange(1, 10 ** 8)
        f["transferFrom"] = {"from": raddr(rng), "to": to, "amount": amt}
        f["value"] = 1
        f["ai"] = {"text": "pull", "claims": {"to": to, "token": target, "amount": amt}}
    elif variant == 5:  # unknown selector, claims present -> no match
        f["calldata"] = bytes.fromhex("12345678") + rb(rng, 64)
        f["ai"] = {"text": "mystery", "claims": {"to": to, "token": target, "amount": 5}}
    elif variant == 6:  # native with matching claims (token = zero)
        f["value"] = rng.randrange(1, 10 ** 18)
        f["ai"] = {"text": "send MON", "claims": {"to": target, "token": z20, "amount": f["value"]}}
    elif variant == 7:  # native claim with non-zero token -> no match; ai without claims is separate (variant 8)
        f["value"] = 5
        f["ai"] = {"text": "send", "claims": {"to": target, "token": raddr(rng), "amount": 5}}
    elif variant == 8:  # ai text only, 100 bytes of 2-byte UTF-8, risk texts at 64 bytes, symbol 16, decimals 255
        f["transfer"] = {"to": to, "amount": 1}
        f["ai"] = {"text": "\u00e9" * 50}
        f["risk"] = {"src": "s" * 64, "category": "\u20ac" * 21 + "c", "label": "L" * 64, "ageDays": MAX64}
        f["symbol"] = "S" * 16
        f["decimals"] = 255
        f["uuidTag"] = True
    elif variant == 9:  # dirty address word -> Unknown; extremes
        f["calldata"] = SEL_TRANSFER + b"\x01" + b"\x00" * 11 + to + (7).to_bytes(32, "big")
        f["value"] = MAX256
        f["nonce"] = MAX256
        f["expiry"] = MAX64
        f["chainId"] = MAX64
        f["budgetLeft"] = 0
    elif variant == 10:  # claims with zero "to" and 0 amount, transfer of 0
        f["transfer"] = {"to": to, "amount": 0}
        f["ai"] = {"text": "", "claims": {"to": z20, "token": target, "amount": 0}}
    elif variant == 11:  # ERC-20 transfer, claims name another token contract -> no match
        amt = rng.randrange(1, 10 ** 8)
        f["transfer"] = {"to": to, "amount": amt}
        f["ai"] = {"text": "pay in AUSD", "claims": {"to": to, "token": raddr(rng), "amount": amt}}
    elif variant == 12:  # approve with claims token = zero (as if native) -> no match
        f["approve"] = {"spender": to, "amount": 3}
        f["ai"] = {"text": "x", "claims": {"to": to, "token": z20, "amount": 3}}
    elif variant == 13:  # transferFrom pulling FROM the delegator, claims equal the decode -> still no match (MINOR 1)
        amt = rng.randrange(1, 10 ** 8)
        f["transferFrom"] = {"from": f["delegator"], "to": to, "amount": amt}
        f["ai"] = {"text": "pull from vault", "claims": {"to": to, "token": target, "amount": amt}}
    elif variant == 14:  # AUSD from the firmware table, keys 15/16 agree with it
        f["target"] = AUSD_10143
        f["transfer"] = {"to": to, "amount": 25 * 10 ** 6}
        f["decimals"] = 6
        f["symbol"] = "AUSD"
        f["ai"] = {"text": "rent", "claims": {"to": to, "token": AUSD_10143, "amount": 25 * 10 ** 6}}
    elif variant == 15:  # AUSD without keys 15/16: the table decimals are used (review probe B3: 1e12 base units)
        f["target"] = AUSD_10143
        f["transfer"] = {"to": to, "amount": 10 ** 12}
    elif variant == 16:  # native MON with keys 15/16 equal to the chain table
        f["value"] = 5 * 10 ** 17
        f["decimals"] = 18
        f["symbol"] = "MON"
    elif variant == 17:  # unlimited AUSD approve with claims -> never a match (MINOR 1)
        f["target"] = AUSD_10143
        f["approve"] = {"spender": to, "amount": MAX256}
        f["ai"] = {"text": "approve router", "claims": {"to": to, "token": AUSD_10143, "amount": MAX256}}
    return f


def _mk_mandate(rng, variant, p1xy=None):
    f = {"reqId": rb(rng, 16), "chainId": 10143, "manager": E.unhex("0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3"),
         "delegate": raddr(rng), "delegator": raddr(rng), "salt": rng.getrandbits(64)}
    if variant == 0:
        f["caveats"] = [[raddr(rng), rb(rng, 32 * 7)]]
    elif variant == 1:
        f["caveats"] = [[E.unhex(MM["AllowedTargetsEnforcer"]), rb(rng, 40)],
                        [E.unhex(MM["TimestampEnforcer"]), rb(rng, 32)],
                        [raddr(rng), rb(rng, 256)]]
        f["label"] = "Rent agent (monthly)"
        f["agentId"] = 42
    elif variant == 2:
        f["caveats"] = [[raddr(rng), rb(rng, rng.randrange(0, 40))] for _ in range(16)]
        f["salt"] = 0
        f["uuidTag"] = True
    elif variant == 3:
        f["caveats"] = [[E.unhex(MM["LimitedCallsEnforcer"]), b""]]
        f["label"] = "x" * 64
        f["agentId"] = MAX64
        f["chainId"] = 143
    elif variant == 4:
        f["caveats"] = [[raddr(rng), rb(rng, 700)], [raddr(rng), rb(rng, 1)]]
        f["salt"] = MAX256
    elif variant == 5:  # signable with a pinned context: one pulse caveat (demo P1 key) + every other decoder
        pulse, vault, sentinel = raddr(rng), raddr(rng), raddr(rng)
        f["delegator"] = vault
        f["caveats"] = [
            {"kind": "pulse", "enforcer": pulse, "p1Key": p1xy, "token": AUSD_10143, "perTxAutoCap": 25 * 10 ** 6,
             "periodAutoCap": 50 * 10 ** 6, "period": 86400, "epoch": 3, "newPayeeNeedsHuman": True,
             "sentinel": sentinel},
            {"kind": "erc20TransferAmount", "token": AUSD_10143, "amount": 500 * 10 ** 6},
            {"kind": "erc20PeriodTransfer", "token": AUSD_10143, "amount": 50 * 10 ** 6, "duration": 86400,
             "start": 1790380800},
            {"kind": "nativeTokenTransferAmount", "amount": 10 ** 18},
            {"kind": "valueLte", "amount": 0},
            {"kind": "limitedCalls", "amount": 100},
            {"kind": "timestamp", "after": 1790380800, "before": 1790380800 + 30 * 86400},
            {"kind": "allowedTargets", "addresses": [AUSD_10143]},
            {"kind": "redeemer", "addresses": [f["delegate"], raddr(rng)]},
        ]
        f["label"] = "Ripar demo agent"
        f["agentId"] = 7
        f["_ctx"] = {"pulse": pulse, "vault": vault, "sentinel": sentinel, "minEpoch": 3}
    return f


def _mk_deny(rng, variant):
    return {"reqId": rb(rng, 16), "chainId": [10143, 143, MAX64][variant % 3], "relay": raddr(rng),
            "agentId": [7, 0, MAX64][variant % 3], "requestHash": rb(rng, 32), "uuidTag": variant == 1}


def _mutations(kind, base):
    """(name, map) invalid requests derived from a valid base map (all are well-formed CBOR)."""
    out = []

    def mut(name, fn):
        m = json_clone(base)
        fn(m)
        out.append((name, m))

    required = {"pair": [1, 2, 3], "cosign": list(range(1, 12)), "mandate": list(range(1, 9)),
                "deny": [1, 2, 3, 4, 5], "privy": [1, 2]}[kind]
    for k in required:
        mut("missing key %d" % k, lambda m, k=k: m.pop(k))
    mut("unknown key 99", lambda m: m.__setitem__(99, 1))
    mut("unknown key 0", lambda m: m.__setitem__(0, 1))
    mut("text key", lambda m: m.__setitem__("x", 1))
    mut("negative key", lambda m: m.__setitem__(-1, 1))
    mut("req-id 15 bytes", lambda m: m.__setitem__(1, b"\x11" * 15))
    mut("req-id 17 bytes", lambda m: m.__setitem__(1, b"\x11" * 17))
    mut("req-id text", lambda m: m.__setitem__(1, "0123456789abcdef"))
    mut("req-id tag 38", lambda m: m.__setitem__(1, U.Tag(38, b"\x11" * 16)))
    mut("req-id tag 37 of text", lambda m: m.__setitem__(1, U.Tag(37, "0123456789abcdef")))
    mut("req-id tag 37 of 15 bytes", lambda m: m.__setitem__(1, U.Tag(37, b"\x11" * 15)))
    if kind != "privy":
        mut("chainId 0", lambda m: m.__setitem__(2, 0))
        mut("chainId negative", lambda m: m.__setitem__(2, -1))
        mut("chainId bstr", lambda m: m.__setitem__(2, b"\x27\x9f"))
        mut("chainId text", lambda m: m.__setitem__(2, "10143"))
    addr_keys = {"pair": [3, 4, 5, 6, 7, 8], "cosign": [3, 5, 6, 7], "mandate": [3, 4, 5], "deny": [3], "privy": []}[kind]
    for k in addr_keys:
        mut("key %d 19 bytes" % k, lambda m, k=k: m.__setitem__(k, m[k][:19]))
        mut("key %d 21 bytes" % k, lambda m, k=k: m.__setitem__(k, m[k] + b"\x00"))
        mut("key %d zero address" % k, lambda m, k=k: m.__setitem__(k, b"\x00" * 20))
        mut("key %d text" % k, lambda m, k=k: m.__setitem__(k, "0x" + h(m[k])))
        mut("key %d uint" % k, lambda m, k=k: m.__setitem__(k, 5))
    b32_keys = {"cosign": [4], "mandate": [6], "deny": [5]}.get(kind, [])
    for k in b32_keys:
        mut("key %d 31 bytes" % k, lambda m, k=k: m.__setitem__(k, m[k][:31]))
        mut("key %d 33 bytes" % k, lambda m, k=k: m.__setitem__(k, m[k] + b"\x00"))
        mut("key %d text" % k, lambda m, k=k: m.__setitem__(k, "x"))
    u256_keys = {"cosign": [8, 10], "mandate": [8]}.get(kind, [])
    for k in u256_keys:
        mut("key %d 33 bytes" % k, lambda m, k=k: m.__setitem__(k, b"\x00" * 33))
        mut("key %d uint" % k, lambda m, k=k: m.__setitem__(k, 5))
        mut("key %d bignum tag" % k, lambda m, k=k: m.__setitem__(k, U.Tag(2, b"\x05")))
    if kind == "cosign":
        mut("calldata text", lambda m: m.__setitem__(9, "0xa9059cbb"))
        mut("calldata null", lambda m: m.__setitem__(9, None))
        mut("expiry bstr", lambda m: m.__setitem__(11, b"\x01"))
        mut("expiry negative", lambda m: m.__setitem__(11, -5))
        mut("risk array", lambda m: m.__setitem__(12, ["a", "b", "c", 1]))
        mut("risk missing label", lambda m: m.__setitem__(12, {1: "a", 2: "b", 4: 1}))
        mut("risk missing ageDays", lambda m: m.__setitem__(12, {1: "a", 2: "b", 3: "c"}))
        mut("risk unknown key", lambda m: m.__setitem__(12, {1: "a", 2: "b", 3: "c", 4: 1, 5: "x"}))
        mut("risk newline", lambda m: m.__setitem__(12, {1: "a", 2: "b", 3: "Binance\nSAFE", 4: 1}))
        mut("risk DEL", lambda m: m.__setitem__(12, {1: "a\x7f", 2: "b", 3: "c", 4: 1}))
        mut("risk label 65 bytes", lambda m: m.__setitem__(12, {1: "a", 2: "b", 3: "L" * 65, 4: 1}))
        mut("risk src bstr", lambda m: m.__setitem__(12, {1: b"a", 2: "b", 3: "c", 4: 1}))
        mut("risk ageDays text", lambda m: m.__setitem__(12, {1: "a", 2: "b", 3: "c", 4: "1"}))
        mut("ai text 101 bytes", lambda m: m.__setitem__(13, {1: "a" * 101}))
        mut("ai text 101 bytes utf8", lambda m: m.__setitem__(13, {1: "a" + "\u00e9" * 50}))
        mut("ai text tab", lambda m: m.__setitem__(13, {1: "a\tb"}))
        mut("ai missing text", lambda m: m.__setitem__(13, {2: {1: b"\x01" * 20, 2: b"\x02" * 20, 3: b"\x05"}}))
        mut("ai unknown key", lambda m: m.__setitem__(13, {1: "a", 3: 1}))
        mut("ai claims missing amount", lambda m: m.__setitem__(13, {1: "a", 2: {1: b"\x01" * 20, 2: b"\x02" * 20}}))
        mut("ai claims to 21 bytes", lambda m: m.__setitem__(13, {1: "a", 2: {1: b"\x01" * 21, 2: b"\x02" * 20, 3: b"\x05"}}))
        mut("ai claims amount 33 bytes", lambda m: m.__setitem__(13, {1: "a", 2: {1: b"\x01" * 20, 2: b"\x02" * 20, 3: b"\x05" * 33}}))
        mut("ai claims unknown key", lambda m: m.__setitem__(13, {1: "a", 2: {1: b"\x01" * 20, 2: b"\x02" * 20, 3: b"\x05", 4: 0}}))
        mut("ai claims array", lambda m: m.__setitem__(13, {1: "a", 2: [b"\x01" * 20, b"\x02" * 20, b"\x05"]}))
        mut("budget 33 bytes", lambda m: m.__setitem__(14, b"\x01" * 33))
        mut("budget uint", lambda m: m.__setitem__(14, 1))
        mut("decimals 256", lambda m: m.__setitem__(15, 256))
        mut("decimals text", lambda m: m.__setitem__(15, "6"))
        mut("decimals negative", lambda m: m.__setitem__(15, -1))
        mut("symbol 17 bytes", lambda m: m.__setitem__(16, "S" * 17))
        mut("symbol newline", lambda m: m.__setitem__(16, "AUSD\n"))
        mut("symbol bstr", lambda m: m.__setitem__(16, b"AUSD"))
        mut("key 17", lambda m: m.__setitem__(17, 0))
    if kind == "mandate":
        mut("authority zero", lambda m: m.__setitem__(6, b"\x00" * 32))
        mut("authority one bit off", lambda m: m.__setitem__(6, b"\xff" * 31 + b"\xfe"))
        mut("authority real hash", lambda m: m.__setitem__(6, keccak256(b"parent delegation")))
        mut("caveats empty", lambda m: m.__setitem__(7, []))
        mut("caveats 17", lambda m: m.__setitem__(7, [[b"\x01" * 20, b""]] * 17))
        mut("caveats map", lambda m: m.__setitem__(7, {1: [b"\x01" * 20, b""]}))
        mut("caveat 3 items", lambda m: m.__setitem__(7, [[b"\x01" * 20, b"", b""]]))
        mut("caveat 1 item", lambda m: m.__setitem__(7, [[b"\x01" * 20]]))
        mut("caveat not array", lambda m: m.__setitem__(7, [b"\x01" * 20]))
        mut("caveat enforcer 19 bytes", lambda m: m.__setitem__(7, [[b"\x01" * 19, b""]]))
        mut("caveat enforcer text", lambda m: m.__setitem__(7, [["0x" + "01" * 20, b""]]))
        mut("caveat terms text", lambda m: m.__setitem__(7, [[b"\x01" * 20, "00"]]))
        mut("second caveat bad", lambda m: m.__setitem__(7, [[b"\x01" * 20, b""], [b"\x01" * 20, 5]]))
        mut("label newline", lambda m: m.__setitem__(9, "Rent\nagent"))
        mut("label 65 bytes", lambda m: m.__setitem__(9, "x" * 65))
        mut("label bstr", lambda m: m.__setitem__(9, b"x"))
        mut("agentId bstr", lambda m: m.__setitem__(10, b"\x2a"))
        mut("agentId negative", lambda m: m.__setitem__(10, -42))
        mut("key 11", lambda m: m.__setitem__(11, 0))
    if kind == "deny":
        mut("agentId bstr", lambda m: m.__setitem__(4, b"\x07"))
        mut("agentId text", lambda m: m.__setitem__(4, "7"))
        mut("key 6", lambda m: m.__setitem__(6, 0))
    if kind == "pair":
        mut("key 9 = 2^40", lambda m: m.__setitem__(9, 1 << 40))
        mut("key 9 = 2^64-1", lambda m: m.__setitem__(9, MAX64))
        mut("key 9 bstr", lambda m: m.__setitem__(9, b"\x01"))
        mut("key 9 negative", lambda m: m.__setitem__(9, -1))
        mut("key 10 = 2^63", lambda m: m.__setitem__(10, 1 << 63))
        mut("key 10 = 2^64-1", lambda m: m.__setitem__(10, MAX64))
        mut("key 10 bstr", lambda m: m.__setitem__(10, b"\x01"))
        mut("key 10 negative", lambda m: m.__setitem__(10, -1))
        mut("key 11 = 2^63", lambda m: m.__setitem__(11, 1 << 63))
        mut("key 11 text", lambda m: m.__setitem__(11, "1"))
        mut("key 12", lambda m: m.__setitem__(12, 0))
    if kind == "privy":
        mut("json as text", lambda m: m.__setitem__(2, m[2].decode("utf-8")))
        mut("json empty", lambda m: m.__setitem__(2, b""))
        mut("key 3", lambda m: m.__setitem__(3, 0))
    out.append(("not a map (array)", [base[k] for k in sorted(base) if isinstance(k, int)]))
    return out


def _token_mutations(ausd, native):
    """co-sign requests whose optional keys 15 / 16 contradict the firmware token table (security review B3)"""
    out = []

    def mut(name, base, fn):
        m = json_clone(base)
        fn(m)
        out.append((name, m))
    mut("AUSD decimals 18 (table: 6)", ausd, lambda m: m.__setitem__(15, 18))
    mut("AUSD decimals 0", ausd, lambda m: m.__setitem__(15, 0))
    mut("AUSD symbol USDC", ausd, lambda m: m.__setitem__(16, "USDC"))
    mut("AUSD symbol lower-case", ausd, lambda m: m.__setitem__(16, "ausd"))
    mut("AUSD no decimals, symbol USDT", ausd, lambda m: (m.pop(15), m.__setitem__(16, "USDT")))
    mut("native MON decimals 6", native, lambda m: m.__setitem__(15, 6))
    mut("native MON symbol ETH", native, lambda m: m.__setitem__(16, "ETH"))
    return out


def json_clone(m):
    if isinstance(m, dict):
        return {k: json_clone(v) for k, v in m.items()}
    if isinstance(m, list):
        return [json_clone(v) for v in m]
    return m


def generate_vectors():
    rng = random.Random(4711)
    keys = demo_keys()
    L = []
    w = L.append
    w("// GENERATED by tools/make_request.py gen-vectors - do not edit (python tools/make_request.py check-vectors).")
    w("// Requests are built with tools/ref_ur.py cbor(); digests with tools/ref_eip712.py (generic EIP-712 + MetaMask")
    w("// EncoderLib); signatures with tools/ref_crypto.py (RFC 6979, low-s) using the demo seed sha256(\"ripar demo seed\").")
    w("// Token table, caveat decoders and the Privy allow-list are independent Python references (make_request.py).")
    w("#pragma once")
    w("#include <cstddef>")
    w("#include <cstdint>")
    w("namespace pv {")
    w("static const char DEMO_K1_PRIV[] = %s;" % hx(rc.i2b(keys["k1"])))
    w("static const char DEMO_K1_ADDR[] = %s;" % hx(keys["k1addr"]))
    w("static const char DEMO_P1_PRIV[] = %s;" % hx(rc.i2b(keys["p1"])))
    w("static const char DEMO_P1_XY[] = %s;" % hx(keys["p1xy"]))
    w("")

    # ---------------------------------------------------------------- cosign
    w("// tokListed/tokDecimals/tokSymbol: the device's TokenView (firmware token table, security review B3);")
    w("// requestHash = hashStruct(HumanApproval) with presenceHash 0 (deny from the review, MINOR 7).")
    w("struct Cosign {")
    w("  const char* name; const char* cbor; const char* reqId; uint64_t chainId; const char* enforcer;")
    w("  const char* delegationHash; const char* delegator; const char* redeemer; const char* target; const char* value;")
    w("  const char* calldata; const char* nonce; uint64_t expiry;")
    w("  int riskPresent; const char* riskSrc; const char* riskCategory; const char* riskLabel; uint64_t riskAge;")
    w("  int aiPresent; const char* aiText; int aiHasClaims; const char* aiTo; const char* aiToken; const char* aiAmount;")
    w("  int hasBudget; const char* budget; int decimals; const char* symbol;")
    w("  int callKind; const char* callFrom; const char* callTo; const char* callAmount; uint32_t callSelector; int aiMatches;")
    w("  const char* callDataHash; const char* ev12; const char* salt16; const char* presenceHash; const char* digest;")
    w("  const char* rs; const char* resp; const char* respUr;")
    w("  int hasDecimals; int hasSymbol; int tokListed; int tokDecimals; const char* tokSymbol; const char* requestHash;")
    w("};")
    w("static const Cosign COSIGN[] = {")
    cosign_cbors = []
    for variant in range(18):
        f = _mk_cosign(rng, variant)
        m = build_cosign_req(f)
        if variant == 8:  # insertion order shuffled (the device accepts any key order)
            ks = list(m)
            rng.shuffle(ks)
            m = {k: m[k] for k in ks}
        if variant == 9:  # budgetLeft as an empty bstr (= 0)
            m[14] = b""
        if variant == 0:
            m[8] = b"\x00" * (32 - len(m[8])) + m[8]  # value as a full 32-byte word
        cb = U.cbor(m)
        cosign_cbors.append(cb)
        q = read_fields("cosign", m)
        listed, tdec, tsym = token_check(q)
        kind, frm, to, amt = decode_erc20(q["calldata"])
        ev, salt = rb(rng, 12), rb(rng, 16)
        ph = presence_hash(ev, salt)
        d = cosign_digest(q, ph)
        rs = sign_p1(keys, d)
        resp = U.cbor({1: q["reqId"], 2: rs, 3: ev, 4: salt})
        risk = q["risk"]
        ai = m.get(13)
        cl = q.get("claims")
        sel = int.from_bytes(q["calldata"][:4], "big") if len(q["calldata"]) >= 4 else 0
        w("  {%s, %s, %s, %s, %s," % (c_str("cosign %d" % variant), hx(cb), hx(q["reqId"]), u64s(q["chainId"]), hx(q["enforcer"])))
        w("   %s, %s, %s, %s, %s," % (hx(q["delegationHash"]), hx(q["delegator"]), hx(q["redeemer"]), hx(q["target"]), u256s(q["value"])))
        w("   %s, %s, %s," % (hx(q["calldata"]), u256s(q["nonce"]), u64s(q["expiry"])))
        if risk:
            w("   1, %s, %s, %s, %s," % (c_str(risk[1]), c_str(risk[2]), c_str(risk[3]), u64s(risk[4])))
        else:
            w('   0, "", "", "", 0,')
        if ai is not None:
            if cl:
                w("   1, %s, 1, %s, %s, %s," % (c_str(ai[1]), hx(cl["to"]), hx(cl["token"]), u256s(cl["amount"])))
            else:
                w("   1, %s, 0, %s, %s, %s," % (c_str(ai[1]), hx(bytes(20)), hx(bytes(20)), u256s(0)))
        else:
            w('   0, "", 0, %s, %s, %s,' % (hx(bytes(20)), hx(bytes(20)), u256s(0)))
        w("   %d, %s, %d, %s," % (1 if 14 in m else 0, u256s(to_int(m.get(14, b""))), q["decimals"], c_str(q["symbol"])))
        w("   %d, %s, %s, %s, 0x%08xu, %d," % (KIND_NUM[kind], hx(frm), hx(to), u256s(amt), sel, 1 if ai_matches(q) else 0))
        w("   %s, %s, %s, %s, %s," % (hx(keccak256(q["calldata"])), hx(ev), hx(salt), hx(ph), hx(d)))
        w("   %s, %s, %s," % (hx(rs), hx(resp), c_str(ur_single("ripar-cosign", resp))))
        w("   %d, %d, %d, %d, %s, %s}," % (1 if q["hasDecimals"] else 0, 1 if q["hasSymbol"] else 0, 1 if listed else 0,
                                          tdec, c_str(tsym), hx(cosign_request_hash(q))))
    w("};")
    w("")

    # ---------------------------------------------------------------- mandate
    w("struct CaveatV { const char* enforcer; const char* terms; };")
    mand = []
    for variant in range(6):
        f = _mk_mandate(rng, variant, keys["p1xy"])
        m = build_mandate_req(f)
        cb = U.cbor(m)
        q = read_fields("mandate", m)
        w("static const CaveatV MANDATE_CAV_%d[] = {" % variant)
        for e, t in q["caveats"]:
            w("  {%s, %s}," % (hx(e), hx(t)))
        w("};")
        mand.append((variant, cb, q, m, f))
    w("struct Mandate {")
    w("  const char* name; const char* cbor; const char* reqId; uint64_t chainId; const char* manager; const char* delegate;")
    w("  const char* delegator; const CaveatV* caveats; size_t ncaveats; const char* salt; const char* label;")
    w("  int hasAgentId; uint64_t agentId; const char* delegationHash; const char* digest; const char* rsv;")
    w("  const char* resp; const char* respUr;")
    w("};")
    w("static const Mandate MANDATE[] = {")
    mandate_cbors = []
    for variant, cb, q, m, f in mand:
        mandate_cbors.append(cb)
        d = mandate_digest(q)
        rsv = sign_k1(keys, d)
        resp = U.cbor({1: q["reqId"], 2: rsv})
        w("  {%s, %s, %s, %s, %s, %s," % (c_str("mandate %d" % variant), hx(cb), hx(q["reqId"]), u64s(q["chainId"]),
                                          hx(q["manager"]), hx(q["delegate"])))
        w("   %s, MANDATE_CAV_%d, %d, %s, %s," % (hx(q["delegator"]), variant, len(q["caveats"]), u256s(q["salt"]),
                                               c_str(q["label"] or "")))
        w("   %d, %s, %s, %s, %s," % (0 if q["agentId"] is None else 1, u64s(q["agentId"] or 0),
                                     hx(delegation_struct_hash(q)), hx(d), hx(rsv)))
        w("   %s, %s}," % (hx(resp), c_str(ur_single("eth-signature", resp))))
    w("};")
    w("")
    # the signable mandate (variant 5) + the context it needs + the independent decode of every caveat
    w("// Mandate that passes policy.h check_mandate() with this pinned context; dumps = independent decode of each")
    w("// caveat (same text as test_policy.cpp dump()).")
    variant, cb, q, m, f = mand[5]
    cx = f["_ctx"]
    dumps = [caveat_dump(q["chainId"], e, t, q["chainId"], cx["pulse"]) for e, t in q["caveats"]]
    assert all(dumps), "policy mandate has an undecodable caveat"
    w("static const char* const POLICY_DUMPS_0[] = {")
    for dmp in dumps:
        w("  %s," % c_str(dmp))
    w("};")
    w("struct PolicyMandate { const char* name; size_t mandate; uint64_t chainId; const char* manager;")
    w("  const char* pulseEnforcer; const char* vault; const char* sentinel; uint64_t minEpoch;")
    w("  const char* const* dumps; size_t ndumps; };")
    w("static const PolicyMandate POLICY_MANDATE[] = {")
    w("  {%s, 5, %s, %s, %s, %s, %s, %s, POLICY_DUMPS_0, %d}," % (
        c_str("signable mandate"), u64s(q["chainId"]), hx(q["manager"]), hx(cx["pulse"]), hx(cx["vault"]),
        hx(cx["sentinel"]), u64s(cx["minEpoch"]), len(dumps)))
    w("};")
    w("")

    # ---------------------------------------------------------------- deny
    w("struct Deny {")
    w("  const char* name; const char* cbor; const char* reqId; uint64_t chainId; const char* relay; uint64_t agentId;")
    w("  const char* requestHash; const char* ev12; const char* salt16; const char* presenceHash; const char* digest;")
    w("  const char* rs; const char* resp; const char* respUr;")
    w("};")
    w("static const Deny DENY[] = {")
    deny_cbors = []
    for variant in range(3):
        f = _mk_deny(rng, variant)
        m = build_deny_req(f)
        cb = U.cbor(m)
        deny_cbors.append(cb)
        q = read_fields("deny", m)
        ev = bytes(12) if variant == 2 else rb(rng, 12)  # Deny may carry all-zero evidence
        salt = rb(rng, 16)
        ph = presence_hash(ev, salt)
        d = deny_digest(q, ph)
        rs = sign_p1(keys, d)
        resp = U.cbor({1: q["reqId"], 2: rs, 3: ev, 4: salt, 5: q["agentId"], 6: q["requestHash"]})
        w("  {%s, %s, %s, %s, %s, %s," % (c_str("deny %d" % variant), hx(cb), hx(q["reqId"]), u64s(q["chainId"]),
                                          hx(q["relay"]), u64s(q["agentId"])))
        w("   %s, %s, %s, %s, %s," % (hx(q["requestHash"]), hx(ev), hx(salt), hx(ph), hx(d)))
        w("   %s, %s, %s}," % (hx(rs), hx(resp), c_str(ur_single("ripar-deny", resp))))
    w("};")
    w("")
    w("// Deny built by the device from a co-sign review (MINOR 7): chain / relay / agentId from the pinned context,")
    w("// requestHash = hashStruct(HumanApproval) of COSIGN[cosign] with presenceHash 0.")
    w("struct DenyFromCosign { size_t cosign; uint64_t chainId; const char* relay; uint64_t agentId; const char* requestHash;")
    w("  const char* ev12; const char* salt16; const char* digest; const char* rs; const char* resp; const char* respUr; };")
    w("static const DenyFromCosign DENY_FROM_COSIGN[] = {")
    for ci, zero_ev in ((1, True), (14, False)):
        q = read_fields("cosign", cbor_decode(cosign_cbors[ci]))
        relay, agent = raddr(rng), [7, MAX64][ci % 2]
        ev = bytes(12) if zero_ev else rb(rng, 12)
        salt = rb(rng, 16)
        rh = cosign_request_hash(q)
        dq = {"chainId": 10143, "relay": relay, "agentId": agent, "requestHash": rh}
        d = deny_digest(dq, presence_hash(ev, salt))
        rs = sign_p1(keys, d)
        resp = U.cbor({1: q["reqId"], 2: rs, 3: ev, 4: salt, 5: agent, 6: rh})
        assert resp == simulate_deny_from_cosign(q, keys, 10143, relay, agent, ev, salt)
        w("  {%d, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s}," % (ci, u64s(10143), hx(relay), u64s(agent), hx(rh), hx(ev),
                                                           hx(salt), hx(d), hx(rs), hx(resp),
                                                           c_str(ur_single("ripar-deny", resp))))
    w("};")
    w("")

    # ---------------------------------------------------------------- pair
    w("struct Pair {")
    w("  const char* name; const char* cbor; const char* reqId; uint64_t chainId; const char* registry;")
    w("  const char* digest; const char* p1sig; const char* k1sig; const char* fwid; const char* resp; const char* respUr;")
    w("  const char* respNoReq;")
    w("  const char* manager; const char* enforcer; const char* sentinel; const char* relay; const char* vault;")
    w("  int hasNow; uint64_t now; int hasMinEpoch; uint64_t minEpoch; int hasReopenNonce; uint64_t reopenNonce;")
    w("};")
    w("static const Pair PAIR[] = {")
    pair_cbors = []
    for variant in range(3):
        f = {"reqId": rb(rng, 16), "chainId": [10143, 1, 143][variant], "registry": raddr(rng), "uuidTag": variant == 1}
        if variant == 0:
            f.update(manager=DELEGATION_MANAGER, enforcer=raddr(rng), sentinel=raddr(rng), relay=raddr(rng),
                     vault=raddr(rng), now=1790500000, minEpoch=12, reopenNonce=3)
        if variant == 2:
            f.update(manager=DELEGATION_MANAGER, enforcer=raddr(rng), now=(1 << 40) - 1, minEpoch=(1 << 63) - 1,
                     reopenNonce=(1 << 63) - 1)
        m = build_pair_req(f)
        cb = U.cbor(m)
        pair_cbors.append(cb)
        q = read_fields("pair", m)
        fwid = rb(rng, 8)
        d = pair_digest(q["chainId"], q["registry"], keys["k1addr"], keys["p1xy"])
        p1sig, k1sig = sign_p1(keys, d), sign_k1(keys, d)
        resp = U.cbor({1: q["reqId"], 2: keys["k1addr"], 3: keys["p1xy"], 4: p1sig, 5: k1sig, 6: fwid})
        noreq = U.cbor({2: keys["k1addr"], 3: keys["p1xy"], 6: fwid})
        opt = [hx(q[n] or bytes(20)) for _, n in PAIR_OPT]
        w("  {%s, %s, %s, %s, %s," % (c_str("pair %d" % variant), hx(cb), hx(q["reqId"]), u64s(q["chainId"]), hx(q["registry"])))
        w("   %s, %s, %s, %s, %s, %s," % (hx(d), hx(p1sig), hx(k1sig), hx(fwid), hx(resp), c_str(ur_single("ripar-pair", resp))))
        w("   %s," % hx(noreq))
        w("   %s, %s, %s, %s, %s, %d, %s," % (opt[0], opt[1], opt[2], opt[3], opt[4], 0 if q["now"] is None else 1,
                                              u64s(q["now"] or 0)))
        w("   %d, %s, %d, %s}," % (0 if q["minEpoch"] is None else 1, u64s(q["minEpoch"] or 0),
                                 0 if q["reopenNonce"] is None else 1, u64s(q["reopenNonce"] or 0)))
    w("};")
    w("")

    # ---------------------------------------------------------------- privy
    w("// dump = canonical text of the parsed request (privy_dump() in make_request.py / test_protocol.cpp).")
    w("struct Privy {")
    w("  const char* name; const char* cbor; const char* reqId; const char* json; const char* method; const char* path;")
    w("  int kind; const char* dump; const char* sha; const char* der; const char* resp; const char* respUr;")
    w("};")
    w("static const Privy PRIVY[] = {")
    privy_cbors = []
    for name, js in privy_valid():
        f = {"reqId": rb(rng, 16), "json": js}
        m = build_privy_req(f)
        cb = U.cbor(m)
        privy_cbors.append(cb)
        v = privy_parse(js)
        sha = hashlib.sha256(js).digest()
        r, s, _ = rc.sign(rc.P1, keys["p1"], sha)
        der = rc.der(r, s)
        resp = U.cbor({1: m[1], 2: der})
        w("  {%s, %s, %s, %s, %s, %s," % (c_str("privy " + name), hx(cb), hx(m[1]), hx(js), c_str(v["method"]),
                                          c_str(v["path"])))
        w("   %d, %s," % (1 if v["kind"] == "wallet" else 2, c_str(privy_dump(v))))
        w("   %s, %s, %s, %s}," % (hx(sha), hx(der), hx(resp), c_str(ur_single("ripar-der-sig", resp))))
    w("};")
    w("")

    # ---------------------------------------------------------------- invalid requests
    w("// type: 0 pair, 1 cosign, 2 mandate, 3 deny, 4 privy. Every entry is well-formed CBOR that the parser must refuse.")
    w("struct Invalid { const char* name; int type; const char* cbor; };")
    w("static const Invalid INVALID[] = {")
    ninv = 0
    bases = [("pair", 0, cbor_decode(pair_cbors[0])), ("cosign", 1, cbor_decode(cosign_cbors[1])),
             ("mandate", 2, cbor_decode(mandate_cbors[1])), ("deny", 3, cbor_decode(deny_cbors[0])),
             ("privy", 4, cbor_decode(privy_cbors[0]))]
    for kind, t, base in bases:
        for name, m in _mutations(kind, base):
            w("  {%s, %d, %s}," % (c_str("%s: %s" % (kind, name)), t, hx(U.cbor(m))))
            ninv += 1
    for name, m in _token_mutations(cbor_decode(cosign_cbors[14]), cbor_decode(cosign_cbors[0])):
        try:  # the Python reference must refuse it too
            token_check(read_fields("cosign", m))
            raise AssertionError("token mutation accepted by token_check: " + name)
        except ProtoError:
            pass
        w("  {%s, 1, %s}," % (c_str("cosign token table: " + name), hx(U.cbor(m))))
        ninv += 1
    for name, js in PRIVY_INVALID:
        try:
            privy_parse(js)
            raise AssertionError("PRIVY_INVALID accepted by privy_parse: " + name)
        except ProtoError:
            pass
        m = {1: rb(rng, 16), 2: js}
        w("  {%s, 4, %s}," % (c_str("privy json: " + name), hx(U.cbor(m))))
        ninv += 1
    w("};")
    w("")

    # ---------------------------------------------------------------- plain JSON parser vectors
    w("struct JsonDoc { const char* hex; };")
    w("static const JsonDoc JSON_VALID[] = {")
    for js in JSON_VALID_EXTRA + [j for _, j in privy_valid()]:
        json.loads(js.decode("utf-8"))  # sanity: Python accepts it too
        w("  {%s}," % hx(js))
    w("};")
    w("static const JsonDoc JSON_INVALID[] = {")
    for js in JSON_INVALID_EXTRA + [j for _, j in PRIVY_INVALID if _json_syntax_invalid(j)]:
        w("  {%s}," % hx(js))
    w("};")
    w("")

    # ---------------------------------------------------------------- device-initiated messages
    w("struct Revoke { uint64_t chainId; const char* enforcer; const char* delegationHash; const char* digest; const char* rs;")
    w("  const char* resp; const char* respUr; };")
    w("static const Revoke REVOKE[] = {")
    for i in range(3):
        chain, enf, dh = [10143, 143, MAX64][i], raddr(rng), rb(rng, 32)
        d = revoke_digest(chain, enf, dh)
        rs = sign_p1(keys, d)
        resp = U.cbor({1: dh, 2: rs})
        w("  {%s, %s, %s, %s, %s, %s, %s}," % (u64s(chain), hx(enf), hx(dh), hx(d), hx(rs), hx(resp), c_str(ur_single("ripar-revoke", resp))))
    w("};")
    w("struct Panic { uint64_t chainId; const char* enforcer; uint64_t minEpoch; const char* digest; const char* rs;")
    w("  const char* resp; const char* respUr; };")
    w("static const Panic PANIC[] = {")
    for me in [0, 1, 23, 24, 255, 256, 65535, 65536, 0xFFFFFFFF, 0x100000000, MAX64]:
        chain, enf = 10143, raddr(rng)
        d = panic_digest(chain, enf, me)
        rs = sign_p1(keys, d)
        resp = U.cbor({1: me, 2: rs})
        w("  {%s, %s, %s, %s, %s, %s, %s}," % (u64s(chain), hx(enf), u64s(me), hx(d), hx(rs), hx(resp), c_str(ur_single("ripar-panic", resp))))
    w("};")
    w("struct Reopen { uint64_t chainId; const char* sentinel; const char* vault; const char* nonce; const char* digest;")
    w("  const char* rs; const char* resp; const char* respUr; };")
    w("static const Reopen REOPEN[] = {")
    for nonce in [0, 1, 255, 256, rng.getrandbits(100), MAX256, 1 << 248]:
        chain, sen, vault = 10143, raddr(rng), raddr(rng)
        d = reopen_digest(chain, sen, vault, nonce)
        rs = sign_p1(keys, d)
        resp = U.cbor({1: vault, 2: u256_min(nonce), 3: rs})
        w("  {%s, %s, %s, %s, %s, %s, %s, %s}," % (u64s(chain), hx(sen), hx(vault), u256s(nonce), hx(d), hx(rs), hx(resp),
                                                  c_str(ur_single("ripar-reopen", resp))))
    w("};")
    w("")

    # ---------------------------------------------------------------- multipart transport of requests
    w("// Multipart QR parts exactly as `make_request.py build` prints them (pure fragments, max 70 bytes, then mixed).")
    w("// completeAt = 1-based index of the part at which an optimal decoder has the whole message when the parts")
    w("// are fed in the listed order (the first pure part is deliberately left out).")
    w("struct Multi { const char* name; const char* cbor; const char* const* parts; size_t nparts; size_t completeAt; };")
    multis = [("cosign", "ripar-cosign-req", cosign_cbors[1]), ("mandate", "ripar-mandate-req", mandate_cbors[5]),
              ("privy", "ripar-privy-req", privy_cbors[5])]
    for i, (name, t, cb) in enumerate(multis):
        enc = U.FountainEncoder(cb, 70)
        seqs = list(range(2, enc.seq_len + 1)) + list(range(enc.seq_len + 1, enc.seq_len + 40))
        at = U.gf2_complete_at([enc.indexes(s) for s in seqs], enc.seq_len)
        assert at is not None
        parts = [U.ur_part(t, enc, s).upper() for s in seqs[:at]]
        w("static const char* const MULTI_PARTS_%d[] = {" % i)
        for p in parts:
            w("  %s," % c_str(p))
        w("};")
        multis[i] = (name, cb, i, len(parts), at)
    w("static const Multi MULTI[] = {")
    for name, cb, i, n, at in multis:
        w("  {%s, %s, MULTI_PARTS_%d, %d, %d}," % (c_str(name), hx(cb), i, n, at))
    w("};")
    w("")
    w("}  // namespace pv")
    return "\n".join(L) + "\n", ninv


def _json_syntax_invalid(js):
    """True if the document is not valid RFC 8259 JSON (Python json + our extra rules), i.e. json_parse_strict
    itself must refuse it (Privy-shape errors are excluded)."""
    try:
        s = js.decode("utf-8")
    except UnicodeDecodeError:
        return True
    if s.startswith("\ufeff") or "\\u0000" in s:
        return True
    seen_dup = [False]

    def hook(pairs):
        ks = [k for k, _ in pairs]
        if len(ks) != len(set(ks)):
            seen_dup[0] = True
        return dict(pairs)

    def bad_const(c):
        raise ValueError(c)
    try:
        v = json.loads(s, object_pairs_hook=hook, parse_constant=bad_const)
    except (ValueError, RecursionError):
        return True
    if seen_dup[0]:
        return True
    if _depth(v) > 16 or _has_lone_surrogate(v):
        return True
    return False


def _depth(v):
    if isinstance(v, dict):
        return 1 + max([_depth(x) for x in v.values()] or [0])
    if isinstance(v, list):
        return 1 + max([_depth(x) for x in v] or [0])
    return 0


def _has_lone_surrogate(v):
    if isinstance(v, str):
        return any(0xD800 <= ord(c) <= 0xDFFF for c in v)
    if isinstance(v, dict):
        return any(_has_lone_surrogate(k) or _has_lone_surrogate(x) for k, x in v.items())
    if isinstance(v, list):
        return any(_has_lone_surrogate(x) for x in v)
    return False


# ================================================================================================ self-test
def selftest(verbose=True):
    ok = [True]

    def t(name, cond):
        if not cond:
            ok[0] = False
            print("FAIL", name)
        elif verbose:
            print("ok  ", name)

    keys = demo_keys()
    rng = random.Random(1)
    t("demo K1 address matches crypto_vectors.h convention",
      eip55("0x" + h(keys["k1addr"])) == eip55("0x" + h(rc.eth_address(rc.pubkey(rc.K1, keys["k1"])))))
    for kind, maker in (("cosign", lambda: _mk_cosign(rng, 1)), ("mandate", lambda: _mk_mandate(rng, 1)),
                        ("deny", lambda: _mk_deny(rng, 0)), ("privy", lambda: {"json": privy_valid()[0][1]}),
                        ("pair", lambda: {"chainId": 10143, "registry": raddr(rng)})):
        f = maker()
        m = BUILDERS[kind](f)
        cb = U.cbor(m)
        t("%s: CBOR decode roundtrip" % kind, U.cbor(cbor_decode(cb)) == cb)
        parts = ur_parts(REQ_TYPES[kind], cb, 70)
        k2, cb2 = read_request(" ".join(parts))
        t("%s: multipart parts reassemble (%d parts)" % (kind, len(parts)), k2 == kind and cb2 == cb)
        t("%s: parts are QR-alphanumeric" % kind,
          all(set(p) <= set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:") for p in parts))
        k3, cb3 = read_request(ur_single(REQ_TYPES[kind], cb))
        t("%s: single-part UR reads back" % kind, k3 == kind and cb3 == cb)
        q = read_fields(kind, cbor_decode(cb))
        resp = simulate(kind, q, keys, salt16=rb(rng, 16))
        rur = ur_single(RESP_TYPES[kind], resp)
        pair_ur = ur_single("ripar-pair", simulate("pair", {"reqId": b"\x00" * 16, "chainId": 10143,
                                                             "registry": b"\x01" * 20}, keys))
        pk = parse_response(pair_ur)
        p1xy, k1a = unhex(pk.fields["p1Key"]), unhex(pk.fields["k1Address"])
        rep = parse_response(rur, (kind, cb), p1xy=p1xy, k1addr=k1a)
        t("%s: response verifies (%d checks)" % (kind, len(rep.checks)), rep.ok() and rep.checks and not rep.unverified)
        # tamper: flip one bit of the signature / a request field -> must fail
        mm = cbor_decode(resp)
        sk = 2
        sig = bytearray(mm[sk])
        sig[10] ^= 1
        mm[sk] = bytes(sig)
        bad = parse_response(ur_single(RESP_TYPES[kind], U.cbor(mm)), (kind, cb), p1xy=p1xy, k1addr=k1a)
        t("%s: tampered signature rejected" % kind, not bad.ok())
        if kind in ("cosign", "mandate", "deny", "pair"):
            mq = cbor_decode(cb)
            mq[2] = mq[2] + 1  # other chain
            bad2 = parse_response(rur, (kind, U.cbor(mq)), p1xy=p1xy, k1addr=k1a)
            t("%s: signature does not verify for another chainId" % kind, not bad2.ok())
        if kind == "cosign":
            mm = cbor_decode(resp)
            ev = bytearray(mm[3])
            ev[1] ^= 1
            mm[3] = bytes(ev)
            bad3 = parse_response(ur_single(RESP_TYPES[kind], U.cbor(mm)), (kind, cb), p1xy=p1xy)
            t("cosign: changed evidence breaks presenceHash binding", not bad3.ok())
    # device-initiated
    for utype, fields, dig in (
            ("ripar-revoke", {1: b"\x33" * 32}, lambda c, a: revoke_digest(c, a, b"\x33" * 32)),
            ("ripar-panic", {1: 9}, lambda c, a: panic_digest(c, a, 9)),
            ("ripar-reopen", {1: b"\x44" * 20, 2: u256_min(0)}, lambda c, a: reopen_digest(c, a, b"\x44" * 20, 0))):
        enf = b"\x55" * 20
        rs = sign_p1(keys, dig(10143, enf))
        mm = dict(fields)
        mm[max(fields) + 1] = rs
        rep = parse_response(ur_single(utype, U.cbor(mm)), None, p1xy=keys["p1xy"], chain=10143, contract=enf)
        t("%s verifies" % utype, rep.ok() and rep.checks and not rep.unverified)
        rep2 = parse_response(ur_single(utype, U.cbor(mm)), None, p1xy=keys["p1xy"], chain=10143, contract=b"\x56" * 20)
        t("%s: wrong contract rejected" % utype, not rep2.ok())
    # Privy allow-list (security review M1)
    v = privy_parse(privy_valid()[0][1])
    t("privy: wallet signer update parsed in full",
      (v["kind"], v["id"], v["app"], v["signers"]) ==
      ("wallet", "wl8yz4c2rq0q1cdz2q8a4", "cm0appid1234", [("kq7ks9z3n1v2lq4d7w0p8m3y", ["pol9x2"])]))
    v = privy_parse(privy_valid()[3][1])
    t("privy: the second (attacker) signer is kept", [x[0] for x in v["signers"]] == ["agent", "ATTACKERkq0000000000000000"])
    v = privy_parse(privy_valid()[5][1])
    t("privy: key quorum keys decoded from base64 SPKI", v["public_keys"][0] == keys["p1xy"] and v["threshold"] == 1)
    refused = 0
    for name, js in PRIVY_INVALID:
        try:
            privy_parse(js)
            t("privy refuses " + name, False)
        except ProtoError:
            refused += 1
    t("privy: all %d disallowed documents refused" % refused, refused == len(PRIVY_INVALID))
    try:
        simulate("privy", {"reqId": b"\x00" * 16, "json": PRIVY_INVALID[0][1]}, keys)
        t("simulate refuses the /rpc probe", False)
    except ProtoError:
        t("simulate refuses the /rpc probe", True)
    # token table (security review B3)
    q = read_fields("cosign", build_cosign_req(_mk_cosign(random.Random(5), 15)))
    t("token table: AUSD without keys 15/16 uses 6 decimals", token_check(q) == (True, 6, "AUSD"))
    for dec, sym in ((18, None), (None, "USDC")):
        q2 = dict(q)
        if dec is not None:
            q2.update(decimals=dec, hasDecimals=True)
        if sym is not None:
            q2.update(symbol=sym, hasSymbol=True)
        try:
            token_check(q2)
            t("token table refuses a lying key 15/16 (%s/%s)" % (dec, sym), False)
        except ProtoError:
            t("token table refuses a lying key 15/16 (%s/%s)" % (dec, sym), True)
    # deny from a co-sign review (MINOR 7): requestHash computed from the request, relay + agent from the context
    q = read_fields("cosign", build_cosign_req(_mk_cosign(random.Random(6), 1)))
    relay = b"f" * 20
    dr = ur_single("ripar-deny", simulate_deny_from_cosign(q, keys, 10143, relay, 7, salt16=bytes(16)))
    rep = parse_response(dr, ("cosign", U.cbor(build_cosign_req(dict(_mk_cosign(random.Random(6), 1))))),
                         p1xy=keys["p1xy"], contract=relay)
    t("deny from cosign verifies (%d checks)" % len(rep.checks), rep.ok() and rep.checks and not rep.unverified)
    rep = parse_response(dr, None, p1xy=keys["p1xy"], chain=10143, contract=b"g" * 20)
    t("deny from cosign: wrong relay rejected", not rep.ok())
    # typed caveats: the signable mandate decodes caveat by caveat
    f = _mk_mandate(random.Random(7), 5, keys["p1xy"])
    q = read_fields("mandate", build_mandate_req(f))
    dumps = [caveat_dump(10143, e, tt, 10143, f["_ctx"]["pulse"]) for e, tt in q["caveats"]]
    t("typed caveats encode + decode (%d)" % len(dumps), all(dumps) and dumps[0].startswith("pulse px=" + h(keys["p1xy"][:32])))
    t("pulse terms are 288 bytes", len(q["caveats"][0][1]) == 288)
    t("NonceEnforcer caveat has no decoder", caveat_dump(10143, unhex(MM_ENF["NonceEnforcer"]), b"\x00" * 32, 10143,
                                                         f["_ctx"]["pulse"]) is None)
    # builder guards
    for bad in ({"text": "x\ny"},):
        try:
            _text(bad["text"], 100, "t")
            t("control characters refused by the builder", False)
        except ProtoError:
            t("control characters refused by the builder", True)
    t("ai_text_trunc keeps <= 100 bytes on a char boundary",
      len(ai_text_trunc("\u20ac" * 40).encode()) == 99 and ai_text_trunc("a\nb") == "a b")
    t("u256_min(0) == 00", u256_min(0) == b"\x00" and u256_min(256) == b"\x01\x00")
    text, ninv = generate_vectors()
    t("vector generation (%d invalid requests)" % ninv, ninv > 150 and "COSIGN" in text)
    print("make_request selftest:", "PASS" if ok[0] else "FAIL")
    return ok[0]


# ================================================================================================ CLI
def _parse_fields(tokens):
    f = {}
    for tok in tokens:
        if tok.startswith("@"):
            with open(tok[1:], "r", encoding="utf-8") as fh:
                f.update(json.load(fh))
        elif tok.lstrip().startswith("{"):
            f.update(json.loads(tok))
        elif "=" in tok:
            k, v = tok.split("=", 1)
            try:
                f[k] = json.loads(v)
            except ValueError:
                f[k] = v
        else:
            raise ProtoError("cannot read field argument %r (use key=value, a JSON object or @file.json)" % tok)
    return f


def _p1_k1_from_args(a):
    p1 = unhex(a.p1) if a.p1 else None
    k1 = unhex(a.k1) if a.k1 else None
    if a.pair:
        rep = parse_response(read_arg_blob(a.pair))
        p1 = p1 or unhex(rep.fields["p1Key"])
        k1 = k1 or unhex(rep.fields["k1Address"])
    return p1, k1


def _main(argv):
    ap = argparse.ArgumentParser(prog="make_request.py", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd")
    b = sub.add_parser("build")
    b.add_argument("kind", choices=sorted(REQ_TYPES))
    b.add_argument("fields", nargs="*")
    b.add_argument("--reqid")
    b.add_argument("--uuid-tag", action="store_true")
    b.add_argument("--frag", type=int, default=70)
    b.add_argument("--extra", type=int, default=0)
    b.add_argument("--json", action="store_true")
    b.add_argument("--no-now", action="store_true", help="pair: do not add the current time as key 9")
    p = sub.add_parser("parse")
    p.add_argument("response")
    for opt in ("--req", "--pair", "--p1", "--k1", "--contract"):
        p.add_argument(opt)
    p.add_argument("--chain", type=lambda s: int(s, 0))
    s = sub.add_parser("simulate")
    s.add_argument("request")
    s.add_argument("--seed")
    k = sub.add_parser("demo-keys")
    k.add_argument("--seed")
    sub.add_parser("gen-vectors")
    sub.add_parser("check-vectors")
    sub.add_parser("selftest")
    a = ap.parse_args(argv[1:])

    if a.cmd == "build":
        f = _parse_fields(a.fields)
        if a.reqid:
            f["reqId"] = a.reqid
        if a.uuid_tag:
            f["uuidTag"] = True
        if a.kind == "pair" and "now" not in f and not a.no_now:
            f["now"] = int(time.time())  # advances the device's "not before" time (docs/PROTOCOL.md section 6)
        m = BUILDERS[a.kind](f)
        cb = U.cbor(m)
        t = REQ_TYPES[a.kind]
        single = ur_single(t, cb)
        parts = ur_parts(t, cb, a.frag, a.extra)
        rid = m[1].value if isinstance(m[1], U.Tag) else m[1]
        if a.json:
            print(json.dumps({"type": t, "reqId": h(rid), "cbor": h(cb), "ur": single, "parts": parts}, indent=1))
        else:
            print("# type   %s  (%d CBOR bytes, req-id %s)" % (t, len(cb), h(rid)))
            print("# cbor   %s" % h(cb))
            print("# single-part UR (%d chars):" % len(single))
            print(single)
            print("# %d multipart parts (pure, max %d-byte fragments%s) - loop them at ~300 ms per QR frame:"
                  % (len(parts), a.frag, ", + %d mixed" % a.extra if a.extra else ""))
            for x in parts:
                print(x)
        return 0
    if a.cmd == "parse":
        req = read_request(a.req) if a.req else None
        p1, k1 = _p1_k1_from_args(a)
        contract = unhex(a.contract) if a.contract else None
        rep = parse_response(read_arg_blob(a.response), req, p1xy=p1, k1addr=k1, chain=a.chain, contract=contract)
        out = dict(rep.fields)
        out["checks"] = [{"check": n, "ok": o} for n, o in rep.checks]
        out["unverified"] = rep.unverified
        out["result"] = "FAIL" if not rep.ok() else ("UNVERIFIED" if rep.unverified or not rep.checks else "VERIFIED")
        print(json.dumps(out, indent=1))
        return 1 if not rep.ok() else (3 if rep.unverified or not rep.checks else 0)
    if a.cmd == "simulate":
        keys = demo_keys(unhex(a.seed) if a.seed else DEMO_SEED)
        kind, cb = read_request(a.request)
        q = read_fields(kind, cbor_decode(cb))
        print(ur_single(RESP_TYPES[kind], simulate(kind, q, keys)))
        return 0
    if a.cmd == "demo-keys":
        keys = demo_keys(unhex(a.seed) if a.seed else DEMO_SEED)
        print(json.dumps({"k1Address": eip55("0x" + h(keys["k1addr"])), "p1Key": h(keys["p1xy"])}, indent=1))
        return 0
    if a.cmd in ("gen-vectors", "check-vectors"):
        text, _ = generate_vectors()
        if a.cmd == "gen-vectors":
            with open(VEC_PATH, "w", newline="\n", encoding="utf-8") as fh:
                fh.write(text)
            print("wrote", VEC_PATH)
            return 0
        try:
            with open(VEC_PATH, "r", encoding="utf-8") as fh:
                cur = fh.read()
        except IOError:
            cur = None
        if cur == text:
            print("vectors_protocol.h: up to date")
            return 0
        print("vectors_protocol.h: STALE (run: python tools/make_request.py gen-vectors)")
        return 1
    if a.cmd == "selftest":
        return 0 if selftest() else 1
    ap.print_help()
    return 2


if __name__ == "__main__":
    try:
        sys.exit(_main(sys.argv))
    except ProtoError as e:
        print("error:", e, file=sys.stderr)
        sys.exit(2)
