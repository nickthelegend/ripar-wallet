#!/usr/bin/env python3
"""Device-conformance vectors for the Ripar contracts (read by contracts/test/DeviceConformance.t.sol).

Every value comes from the firmware's own protocol reference, firmware/tools/make_request.py (the companion tool
the C++ firmware is host-tested against byte for byte). Its demo device (fixed DEMO_SEED = sha256("ripar demo seed"),
no pulse check) answers exactly like the real firmware. Requests with a request type go through the real path:
build_*_req -> CBOR -> UR (single part, and multipart pure fragments) -> read_request -> simulate -> response UR ->
parse_response. The device-initiated messages (revoke / panic / reopen) and the deny the device builds from a co-sign
review use exactly the functions the tool uses for them (revoke_digest / panic_digest / reopen_digest + sign_p1,
simulate_deny_from_cosign).

Sections: vault (the vault derivation of firmware v1.2), pair, mandate (pulse caveat), co-signs for the four call
shapes the device decodes (cosignErc20 = transfer,
cosignNative, cosignApprove, cosignTransferFrom), deny (from the ERC-20 co-sign review), denyRequest (ripar-deny-req from
the companion), revoke, panic, reopen, repair (the device lost its context after panic(1) / reopen(1): re-pair with
the on-chain floors as keys 10 / 11, a new mandate with epoch = floor and a MetaMask TimestampEnforcer caveat before the
pulse caveat, panic(2), reopen(2)) and erc20Decode (see below).

The firmware's own ERC-20 decode table (firmware/test/host/vectors_eip712_abi.h ERC20S, which the C++ abi.cpp is
host-tested against) is copied into the output after it is checked against make_request.decode_erc20, so the test can
compare the enforcer's payee / amount decode with the device's for every entry.

Before anything is written, every digest is rebuilt a second time with a hand-written EIP-712 encoder that uses the
type strings of contracts/SPEC.md / docs/PROTOCOL.md section 3 (and must agree with ref_eip712's generic encoder and
MetaMask EncoderLib port), and every signature is re-verified with ref_crypto (P-256 low-s + verify, secp256k1
recover). Any disagreement aborts with a CHECK FAILED message and exit code 1.

    python test/vectors/gen_device_vectors.py            write test/vectors/device_vectors.json (deterministic)
    python test/vectors/gen_device_vectors.py --check    exit 1 unless the JSON on disk is what this script writes
    python test/vectors/gen_device_vectors.py --out F    write F instead

Firmware v1.2 addresses: the device refuses every Ripar contract but the ones compiled into it, and derives its vault
from K1 (docs/PROTOCOL.md sections 2.1 and 4). So the vectors use the real pinned addresses on 10143 (make_request.py
RIPAR_REGISTRY / RIPAR_COSIGN / RIPAR_RELAY, MUSD_10143: RiparDeviceRegistry, PulseCosignEnforcer, RiparReputationRelay,
MockUSD), the real MetaMask v1.3.0 DelegationManager, SimpleFactory, HybridDeleGator implementation and EntryPoint v0.7,
and as vault / delegator the demo K1's derived vault 0xc36F625D426eBa8f1e0129276B284a939CD3A57D (the SimpleFactory
CREATE2 address, salt 0, of the kit's ERC1967Proxy init code). The vault section carries that init code, checked here
three ways: this script's own abi encoding, make_request.py vault_*, and the firmware's known answers
(firmware/test/host/vectors_protocol.h VAULT[] / DEMO_VAULT / PROXY_CREATION_KECCAK, which the C++ vault.cpp is
host-tested against), plus the on-chain-verified answer of docs/PROTOCOL.md 2.1 (make_request.DEMO_VAULT_KAT).
The other addresses (sentinel, agent, payees, ...) are fixed, fake (0x7e57... = "test") and non-zero.
The demo private keys in the output are public (derived from a published seed): never fund them.
"""
import argparse
import hashlib
import json
import os
import re
import sys

sys.dont_write_bytecode = True  # never drop a __pycache__ into firmware/tools


def _find_tools():
    env = os.environ.get("RIPAR_FW_TOOLS")
    if env:
        return env
    d = os.path.dirname(os.path.abspath(__file__))
    while True:
        cand = os.path.join(d, "firmware", "tools")
        if os.path.isfile(os.path.join(cand, "make_request.py")):
            return cand
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    # not found: the repository layout (contracts/test/vectors -> firmware/tools), relative to this file
    return os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "firmware",
                                         "tools"))


TOOLS = _find_tools()
sys.path.insert(0, TOOLS)
import make_request as MR  # noqa: E402

rc, E, U = MR.rc, MR.E, MR.U
keccak = MR.keccak256
sha256 = hashlib.sha256
ZERO20 = b"\x00" * 20

OUT_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "device_vectors.json")

# ================================================================================================ scenario
CHAIN = 10143  # Monad testnet
NOW = 1790467200  # 2026-09-27 00:00:00 UTC, the companion clock sent at pairing (key 9); > RIPAR_TIME_FLOOR
EXPIRY = NOW + 3600  # co-sign expiry: one hour after NOW (the device allows up to 7 days)
AGENT_ID = 17  # ERC-8004 agent id named in the mandate (key 10); the device files denials against it
SALT = 20260927  # delegation salt
LABEL = "Ripar conformance agent"
PER_TX_CAP = 25 * 10 ** 6  # 25 mUSD (MockUSD has 6 decimals)
PERIOD_CAP = 100 * 10 ** 6  # 100 mUSD per period
PERIOD = 86400  # one day
EPOCH = 0  # a new device's panic floor: the mandate epoch must equal it (docs/PROTOCOL.md section 4)
ERC20_AMOUNT = 40 * 10 ** 6  # 40 mUSD: above the per-tx AUTO cap and a new payee -> needs the human co-sign
NATIVE_VALUE = 5 * 10 ** 17  # 0.5 MON
PANIC_EPOCH = EPOCH + 1  # the device's next panic = floor + 1
REOPEN_NONCE = 1  # the device's last reopen nonce (0) + 1
APPROVE_AMOUNT = 30 * 10 ** 6  # 30 mUSD allowance for the spender (approve is never AUTO)
TRANSFER_FROM_AMOUNT = 15 * 10 ** 6  # 15 mUSD pulled from the holder to payee2 (transferFrom is never AUTO)
# lost-context re-pair (docs/PROTOCOL.md section 4, keys 10 / 11): after panic(1) and reopen(1) were relayed, the device
# lost its context and is paired again with the on-chain floors; its new mandate carries epoch = floor, its next panic
# is floor + 1 and its next reopen nonce floor + 1
REPAIR_NOW = NOW + 86400
REPAIR_MIN_EPOCH_FLOOR = PANIC_EPOCH  # = on-chain minEpoch(keyId) after the first panic
REPAIR_REOPEN_FLOOR = REOPEN_NONCE  # = on-chain lastReopenNonce(vault) after the first reopen
REPAIR_PANIC_EPOCH = REPAIR_MIN_EPOCH_FLOOR + 1
REPAIR_REOPEN_NONCE = REPAIR_REOPEN_FLOOR + 1
REPAIR_SALT = SALT + 1
TS_BEFORE = NOW + 30 * 86400  # MetaMask TimestampEnforcer caveat of the second mandate: usable before this time

# the canonical MetaMask v1.3.0 accounts contracts (the same on 10143 and 143; contracts/.work/vault-derivation.md)
SIMPLE_FACTORY = MR.VAULT_FACTORY
HYBRID_IMPL = MR.VAULT_IMPL
ENTRY_POINT = bytes.fromhex("0000000071727De22E5E9d8BAf0edAc6f37da032")  # ERC-4337 EntryPoint v0.7 (impl immutable)
VAULT_SALT = b"\x00" * 32  # the kit's deploySalt "0x", left-padded: Ripar always uses 0
# keccak256 of the 1008-byte ERC1967Proxy creation code (@metamask/delegation-abis@2.0.0), docs/PROTOCOL.md 2.1
PROXY_CREATION_KECCAK = "c8fb9314d27cddb08b374dd2bf47cd06c6fb879756ddfbedf522a8c58756a8e0"
DEMO_K1_ADDR = MR.demo_keys()["k1addr"]

A = {  # firmware v1.2: the real pinned / derived addresses where the device checks them, fake ("7e57" = test) elsewhere
    "delegationManager": MR.DELEGATION_MANAGER,  # MetaMask v1.3.0 (compiled in)
    "registry": MR.RIPAR_REGISTRY[CHAIN],  # RiparDeviceRegistry (compiled in)
    "enforcer": MR.RIPAR_COSIGN[CHAIN],  # PulseCosignEnforcer (compiled in)
    "sentinel": bytes.fromhex("7e57000000000000000000000000000000000003"),  # not compiled in: pinned as given
    "relay": MR.RIPAR_RELAY[CHAIN],  # RiparReputationRelay (compiled in on 10143)
    "vault": MR.vault_address(DEMO_K1_ADDR),  # delegator: the vault the device derives from its K1
    "agent": bytes.fromhex("7e57000000000000000000000000000000000006"),  # delegate = redeemer
    "token": MR.MUSD_10143,  # MockUSD (in the firmware token table on 10143 since v1.2)
    "payee": bytes.fromhex("7e57000000000000000000000000000000000008"),
    "spender": bytes.fromhex("7e57000000000000000000000000000000000009"),  # approve(spender, ..)
    "holder": bytes.fromhex("7e5700000000000000000000000000000000000a"),  # transferFrom(holder, payee2, ..)
    "payee2": bytes.fromhex("7e5700000000000000000000000000000000000b"),
    "timestampEnforcer": MR.unhex(MR.MM_ENF["TimestampEnforcer"]),  # real MetaMask v1.3.0 address (10143 and 143)
    "simpleFactory": SIMPLE_FACTORY,  # deploys the vault (CREATE2)
    "hybridDeleGatorImpl": HYBRID_IMPL,  # the vault's implementation (behind the ERC1967Proxy)
    "entryPoint": ENTRY_POINT,
}
# typed from docs/PROTOCOL.md (firmware v1.2 compiled-in table, vault known answer), independently of make_request.py
assert MR.h(A["delegationManager"]) == "db9b1e94b5b69df7e401ddbede43491141047db3"
assert MR.h(A["registry"]) == "a08a47c9d645926615cf04d69b7a048133f68c9f"
assert MR.h(A["enforcer"]) == "64d61fe5438981dc803ed61250fef024617ae7ee"
assert MR.h(A["relay"]) == "e433dca75ca6cd730b1006f51a26208b000ea9e2"
assert MR.h(A["token"]) == "b5b7eaffbf9bf68cbcc1ce8b5850b2ea9d6f9a2a"
assert MR.h(A["vault"]) == "c36f625d426eba8f1e0129276b284a939cd3a57d"
assert MR.h(A["simpleFactory"]) == "69aa2f9fe1572f1b640e1bbc512f5c3a734fc77c"
assert MR.h(A["hybridDeleGatorImpl"]) == "48dbe696a4d990079e039489ba2053b36e8ffec4"

# type strings typed here from contracts/SPEC.md "Structs" and docs/PROTOCOL.md section 3
DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
TYPE_STRINGS = {
    "Delegation": "Delegation(address delegate,address delegator,bytes32 authority,Caveat[] caveats,uint256 salt)"
                  "Caveat(address enforcer,bytes terms)",
    "Caveat": "Caveat(address enforcer,bytes terms)",
    "HumanApproval": "HumanApproval(bytes32 delegationHash,address delegator,address redeemer,address target,"
                     "uint256 value,bytes32 callDataHash,uint256 nonce,uint64 expiry,bytes32 presenceHash)",
    "Revoke": "Revoke(bytes32 delegationHash)",
    "Panic": "Panic(uint64 minEpoch)",
    "Reopen": "Reopen(address vault,uint256 nonce)",
    "Deny": "Deny(uint256 agentId,bytes32 requestHash,bytes32 presenceHash)",
    "BindDevice": "BindDevice(address owner,bytes32 px,bytes32 py)",
}
DOMAIN_NAME = {"delegationManager": "DelegationManager", "enforcer": "RiparPulseCosign",
               "registry": "RiparDeviceRegistry", "sentinel": "RiparSentinel", "relay": "RiparReputationRelay"}

CHECKS = []


def check(cond, what):
    if not cond:
        sys.stderr.write("gen_device_vectors: CHECK FAILED: %s\n" % what)
        sys.exit(1)
    CHECKS.append(what)


def fixed(label, n):
    """deterministic stand-in for a device TRNG value / companion random req-id"""
    return sha256(b"ripar conformance " + label.encode()).digest()[:n]


def hx(b):
    return "0x" + bytes(b).hex()


def ad(b):
    return MR.eip55("0x" + bytes(b).hex())


def word(x):
    return int(x).to_bytes(32, "big")


def aword(a):
    assert len(a) == 20
    return b"\x00" * 12 + bytes(a)


# ------------------------------------------------------------------ hand-written EIP-712 (second implementation)
def th(name):
    return keccak(TYPE_STRINGS[name].encode())


def m_domain(which):
    return keccak(keccak(DOMAIN_TYPE.encode()) + keccak(DOMAIN_NAME[which].encode()) + keccak(b"1") + word(CHAIN) +
                  aword(A[which]))


def m_struct(name, *words):
    for w in words:
        assert len(w) == 32
    return keccak(th(name) + b"".join(words))


def m_digest(which, struct_hash):
    return keccak(b"\x19\x01" + m_domain(which) + struct_hash)


# ------------------------------------------------------------------ signature re-verification (ref_crypto)
KEYS = MR.demo_keys()
P1PUB = rc.pubkey(rc.P1, KEYS["p1"])
K1PUB = rc.pubkey(rc.K1, KEYS["k1"])


def verify_p1(digest, rs, what):
    check(len(rs) == 64, what + ": P-256 signature is r||s (64 bytes)")
    r, s = int.from_bytes(rs[:32], "big"), int.from_bytes(rs[32:], "big")
    check(1 <= s <= rc.P1.n // 2, what + ": low-s")
    check(rc.verify(rc.P1, P1PUB, digest, r, s), what + ": P-256 signature verifies (ref_crypto)")
    bad = bytes([digest[0] ^ 1]) + digest[1:]
    check(not rc.verify(rc.P1, P1PUB, bad, r, s), what + ": P-256 signature fails for a tampered digest")
    check(rc.verify(rc.P1, P1PUB, digest, r, rc.P1.n - s),
          what + ": the high-s twin is plain-ECDSA valid (only the low-s rule rejects it)")
    return rs[:32], rs[32:]


def verify_k1(digest, rsv, what):
    check(len(rsv) == 65, what + ": K1 signature is r||s||v (65 bytes)")
    r, s, v = int.from_bytes(rsv[:32], "big"), int.from_bytes(rsv[32:64], "big"), rsv[64]
    check(v in (27, 28), what + ": v is 27/28")
    check(1 <= s <= rc.K1.n // 2, what + ": low-s")
    Q = rc.recover(rc.K1, digest, r, s, v - 27)
    check(Q is not None and rc.eth_address(Q) == KEYS["k1addr"], what + ": recovers the demo K1 address (ref_crypto)")
    check(rc.verify(rc.K1, K1PUB, digest, r, s), what + ": secp256k1 signature verifies")


# ------------------------------------------------------------------ request -> device -> response (make_request path)
def device_roundtrip(kind, fields, ev12=None, salt16=None, p1xy=None, k1addr=None):
    m = MR.BUILDERS[kind](fields)
    cb = U.cbor(m)
    req_ur = MR.ur_single(MR.REQ_TYPES[kind], cb)
    parts = MR.ur_parts(MR.REQ_TYPES[kind], cb, 70)  # the multipart QR loop the companion shows
    k2, cb2 = MR.read_request("\n".join(parts))
    check(k2 == kind and cb2 == cb, "%s: multipart UR (%d parts) reassembles to the request" % (kind, len(parts)))
    k1, cb1 = MR.read_request(req_ur)
    check(k1 == kind and cb1 == cb, "%s: single-part UR reads back" % kind)
    check(U.cbor(MR.cbor_decode(cb1)) == cb1, "%s: request CBOR is canonical" % kind)
    q = MR.read_fields(kind, MR.cbor_decode(cb1))
    resp = MR.simulate(kind, q, KEYS, ev12=ev12, salt16=salt16)
    resp_ur = MR.ur_single(MR.RESP_TYPES[kind], resp)
    rtype, rcb = MR.ur_read(resp_ur)
    check(rtype == MR.RESP_TYPES[kind] and rcb == resp, "%s: response UR round-trips" % kind)
    rep = MR.parse_response(resp_ur, (kind, cb), p1xy=p1xy, k1addr=k1addr)
    check(rep.ok() and rep.checks and not rep.unverified,
          "%s: make_request parse verifies the response (%d checks)" % (kind, len(rep.checks)))
    return {"m": m, "cb": cb, "req_ur": req_ur, "nparts": len(parts), "q": q, "resp": resp, "resp_ur": resp_ur,
            "r": MR.cbor_decode(resp), "rep": rep}


def device_initiated(utype, payload, p1xy, contract):
    resp = U.cbor(payload)
    resp_ur = MR.ur_single(utype, resp)
    rep = MR.parse_response(resp_ur, None, p1xy=p1xy, chain=CHAIN, contract=contract)
    check(rep.ok() and rep.checks and not rep.unverified, "%s: make_request parse verifies (%d checks)"
          % (utype, len(rep.checks)))
    return resp, resp_ur, rep


def msg(cb, ur):
    return {"cbor": hx(cb), "ur": ur}


# ------------------------------------------------------------------ the vault (firmware v1.2 derivation), second implementation
def own_vault_initcode(owner):
    """abi.encodeWithSignature("initialize(address,string[],uint256[],uint256[])", owner, [], [], []), encoded here:
    selector, the owner word, three offsets (0x80, 0xa0, 0xc0) and three empty arrays (a zero length word each)"""
    sel = keccak(b"initialize(address,string[],uint256[],uint256[])")[:4]
    return sel + aword(owner) + word(0x80) + word(0xA0) + word(0xC0) + word(0) * 3


def own_vault_args(owner):
    """abi.encode(address implementation, bytes initcode): the ERC1967Proxy constructor arguments"""
    init = own_vault_initcode(owner)
    return aword(HYBRID_IMPL) + word(0x40) + word(len(init)) + init + b"\x00" * (-len(init) % 32)


def own_vault(owner):
    """-> (init code = proxy creation code || args, its keccak, the SimpleFactory CREATE2 address with salt 0)"""
    init_code = MR.ERC1967_PROXY_CREATION + own_vault_args(owner)
    ich = keccak(init_code)
    return init_code, ich, keccak(b"\xff" + SIMPLE_FACTORY + VAULT_SALT + ich)[12:]


_VAULT_ROW = re.compile(r'\{"([0-9a-f]{40})", "([0-9a-f]+)", "([0-9a-f]+)", "([0-9a-f]{64})", "([0-9a-f]{40})", '
                        r'"(0x[0-9a-fA-F]{40})"\},')


def firmware_vault_vectors():
    """VAULT[], DEMO_VAULT and PROXY_CREATION_KECCAK of firmware/test/host/vectors_protocol.h (the known answers the C++
    vault.cpp is host-tested against), each entry checked against this script's own derivation and make_request's."""
    path = os.path.normpath(os.path.join(TOOLS, "..", "test", "host", "vectors_protocol.h"))
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    demo = re.search(r'static const char DEMO_VAULT\[\] = "([0-9a-f]{40})";', text).group(1)
    pk = re.search(r'static const char PROXY_CREATION_KECCAK\[\] = "([0-9a-f]{64})";', text).group(1)
    check(pk == PROXY_CREATION_KECCAK == keccak(MR.ERC1967_PROXY_CREATION).hex(),
          "vault: proxy creation code keccak == firmware PROXY_CREATION_KECCAK == docs/PROTOCOL.md 2.1")
    check(demo == MR.h(A["vault"]), "vault: firmware DEMO_VAULT == the vectors' vault")
    start = text.index("static const Vault VAULT[] = {")
    block = text[start:text.index("\n};", start)]
    rows = [ln.strip() for ln in block.split("\n")[1:] if ln.strip()]
    out = []
    for ln in rows:
        mt = _VAULT_ROW.fullmatch(ln)
        check(mt is not None, "VAULT row parses: " + ln[:60])
        owner = bytes.fromhex(mt.group(1))
        init_code, ich, vault = own_vault(owner)
        check(mt.group(2) == own_vault_initcode(owner).hex() == MR.vault_initcode(owner).hex(),
              "VAULT %s: initialize calldata == firmware == make_request" % mt.group(1))
        check(mt.group(3) == own_vault_args(owner).hex() == MR.vault_constructor_args(owner).hex(),
              "VAULT %s: proxy constructor args == firmware == make_request" % mt.group(1))
        check(mt.group(4) == ich.hex() == MR.vault_init_code_hash(owner).hex(),
              "VAULT %s: initCodeHash == firmware == make_request" % mt.group(1))
        check(mt.group(5) == vault.hex() == MR.vault_address(owner).hex() and mt.group(6) == ad(vault),
              "VAULT %s: vault address == firmware == make_request" % mt.group(1))
        out.append({"owner": ad(owner), "initCodeHash": hx(ich), "vault": ad(vault)})
    check(len(out) >= 8 and out[0]["owner"] == ad(DEMO_K1_ADDR), "VAULT: %d owners, the demo K1 first" % len(out))
    return out


FW_KIND = {"None": "none", "Transfer": "transfer", "Approve": "approve", "TransferFrom": "transferFrom",
           "Unknown": "unknown"}
_ERC20_ROW = re.compile(r'\{"([0-9a-f]*)", ripar::Erc20Call::(\w+), 0x([0-9a-f]{8})u, "([0-9a-f]{40})", '
                        r'"([0-9a-f]{40})", "([0-9a-f]{64})", "([^"]*)"\},')


def firmware_erc20_vectors():
    """ERC20S of firmware/test/host/vectors_eip712_abi.h (the C++ abi_decode_erc20 known answers), each entry checked
    against make_request.decode_erc20 (the independent Python decode)."""
    path = os.path.normpath(os.path.join(TOOLS, "..", "test", "host", "vectors_eip712_abi.h"))
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    start = text.index("static const Erc20 ERC20S[] = {")
    block = text[start:text.index("\n};", start)]
    rows = [ln.strip() for ln in block.split("\n")[1:] if ln.strip()]
    out = []
    for ln in rows:
        mt = _ERC20_ROW.fullmatch(ln)
        check(mt is not None, "ERC20S row parses: " + ln[:60])
        cd, kind = bytes.fromhex(mt.group(1)), FW_KIND[mt.group(2)]
        frm, to, amt = bytes.fromhex(mt.group(4)), bytes.fromhex(mt.group(5)), int(mt.group(6), 16)
        check(MR.decode_erc20(cd) == (kind, frm, to, amt),
              "ERC20S '%s': firmware decode == make_request.decode_erc20" % mt.group(7))
        check(kind in ("none", "unknown") or to != ZERO20 or amt != 0,
              "ERC20S '%s': distinguishable from an unmetered call by (payee, amount)" % mt.group(7))
        out.append({"calldata": hx(cd), "kind": MR.KIND_NUM[kind], "from": ad(frm), "to": ad(to),
                    "amount": hx(word(amt)), "note": mt.group(7)})
    kinds = set(v["kind"] for v in out)
    check(len(out) >= 40 and kinds == set(MR.KIND_NUM.values()), "ERC20S: %d entries covering all 5 kinds" % len(out))
    return {"source": "firmware/test/host/vectors_eip712_abi.h ERC20S", "kinds": MR.KIND_NUM, "count": len(out),
            "vectors": out}


# ================================================================================================ build
def build():
    for name in TYPE_STRINGS:
        check(E.encode_type(name, E.RIPAR_TYPES) == TYPE_STRINGS[name], "type string %s == ref_eip712" % name)
    check(th("Delegation").hex() == E.DELEGATION_TYPEHASH, "Delegation typehash == MetaMask Constants.sol")
    check(th("Caveat").hex() == E.CAVEAT_TYPEHASH, "Caveat typehash == MetaMask Constants.sol")
    check(keccak(DOMAIN_TYPE.encode()).hex() == E.EIP712_DOMAIN_TYPEHASH, "EIP712Domain typehash")
    for which, name in DOMAIN_NAME.items():
        check(m_domain(which) == E.domain_separator(E.domain_ripar(name, CHAIN, A[which])),
              "domain separator %s == ref_eip712" % name)

    # ---------------------------------------------------------------- demo device keys
    k1addr, p1xy = KEYS["k1addr"], KEYS["p1xy"]
    px, py = p1xy[:32], p1xy[32:]
    key_id = keccak(px + py)  # keccak256(abi.encode(bytes32 px, bytes32 py))
    check(rc.on_curve(rc.P1, P1PUB), "demo P1 key on P-256")
    check(rc.eth_address(K1PUB) == k1addr, "demo K1 address = keccak(pub)[12:]")

    # ---------------------------------------------------------------- the vault (derived from K1, firmware v1.2)
    vault_init_code, vault_ich, vault_addr = own_vault(k1addr)
    kat_k1, kat_ich, kat_vault = MR.DEMO_VAULT_KAT
    check(MR.unhex(kat_k1) == k1addr and MR.unhex(kat_ich) == vault_ich and MR.unhex(kat_vault) == vault_addr,
          "vault: demo K1 -> initCodeHash -> vault == the on-chain-verified answer (docs/PROTOCOL.md 2.1)")
    check(vault_addr == A["vault"] == MR.demo_keys()["vault"], "vault: the vectors' vault is the demo K1's derived vault")
    check(len(MR.ERC1967_PROXY_CREATION) == 1008 and len(vault_init_code) == 1008 + 352,
          "vault: init code = 1008-byte ERC1967Proxy creation code || 352-byte constructor args")
    fw_vaults = firmware_vault_vectors()
    vault_doc = {
        "note": "firmware v1.2 derives its vault from K1 (docs/PROTOCOL.md 2.1): SimpleFactory.deploy(initCode, salt) "
                "of the kit's ERC1967Proxy init code, owner K1; the device pins no other vault",
        "owner": ad(k1addr), "factory": ad(SIMPLE_FACTORY), "implementation": ad(HYBRID_IMPL),
        "entryPoint": ad(ENTRY_POINT), "salt": hx(VAULT_SALT),
        "proxyCreationCode": hx(MR.ERC1967_PROXY_CREATION), "proxyCreationCodeHash": "0x" + PROXY_CREATION_KECCAK,
        "initializeCalldata": hx(own_vault_initcode(k1addr)), "constructorArgs": hx(own_vault_args(k1addr)),
        "initCode": hx(vault_init_code), "initCodeHash": hx(vault_ich), "address": ad(vault_addr),
        "firmwareTableCount": len(fw_vaults), "firmwareTable": fw_vaults,
    }

    # ---------------------------------------------------------------- pair (ripar-pair-req -> ripar-pair)
    # keys 4 / 5 / 7 name the compiled-in contracts; no key 8: the device pins the vault it derives from K1
    pair_f = {"reqId": fixed("pair req-id", 16), "chainId": CHAIN, "registry": A["registry"],
              "manager": A["delegationManager"], "enforcer": A["enforcer"], "sentinel": A["sentinel"],
              "relay": A["relay"], "now": NOW}
    pr = device_roundtrip("pair", pair_f, salt16=fixed("salt pair", 16))
    check(8 not in pr["m"], "pair request: no key 8 (vault)")
    check(pr["r"][2] == k1addr and pr["r"][3] == p1xy, "pair response carries the demo K1 address and P1 key")
    check(MR.unhex(pr["rep"].fields["vault"]) == A["vault"], "parse of the pairing response: vault = the derived vault")
    bind_digest = m_digest("registry", m_struct("BindDevice", aword(k1addr), px, py))
    check(MR.unhex(pr["rep"].fields["bindDigest"]) == bind_digest, "BindDevice digest == hand-written EIP-712")
    check(MR.pair_digest(CHAIN, A["registry"], k1addr, p1xy) == bind_digest, "BindDevice digest == pair_digest")
    pair_r, pair_s = verify_p1(bind_digest, pr["r"][4], "pair P1")
    verify_k1(bind_digest, pr["r"][5], "pair K1")
    # from here on the companion knows the device only from the pairing response
    p1xy_c = MR.unhex(pr["rep"].fields["p1Key"])
    k1_c = MR.unhex(pr["rep"].fields["k1Address"])
    check(p1xy_c == p1xy and k1_c == k1addr, "pairing response parsed keys == demo keys")

    # ---------------------------------------------------------------- mandate (ripar-mandate-req -> eth-signature)
    def mandate(name, epoch, salt, label, extra_before=()):
        """One device-signed mandate: the extra (MetaMask) caveats first, then the pulse caveat with epoch = the
        device's panic floor (docs/PROTOCOL.md section 4 mandate policy)."""
        pulse = {"kind": "pulse", "enforcer": A["enforcer"], "p1Key": p1xy_c, "token": A["token"],
                 "perTxAutoCap": PER_TX_CAP, "periodAutoCap": PERIOD_CAP, "period": PERIOD, "epoch": epoch,
                 "newPayeeNeedsHuman": True, "sentinel": A["sentinel"]}
        mand_f = {"reqId": fixed(name + " req-id", 16), "chainId": CHAIN, "manager": A["delegationManager"],
                  "delegate": A["agent"], "delegator": A["vault"], "caveats": list(extra_before) + [pulse],
                  "salt": salt, "label": label, "agentId": AGENT_ID}
        mr = device_roundtrip("mandate", mand_f, salt16=fixed("salt " + name, 16), p1xy=p1xy_c, k1addr=k1_c)
        mq = mr["q"]
        pi = len(extra_before)  # index of the pulse caveat
        check(mq["authority"] == MR.ROOT, name + ": authority = ROOT (0xff..ff)")
        check(len(mq["caveats"]) == pi + 1, name + ": %d caveat(s)" % (pi + 1))
        pulse_hits = [i for i, (e, _t) in enumerate(mq["caveats"]) if e == A["enforcer"]]
        check(pulse_hits == [pi], name + ": exactly one caveat uses the pinned PulseCosignEnforcer (policy)")
        enf, terms = mq["caveats"][pi]
        terms_manual = (px + py + aword(A["token"]) + word(PER_TX_CAP) + word(PERIOD_CAP) + word(PERIOD) +
                        word(epoch) + word(1) + aword(A["sentinel"]))
        check(enf == A["enforcer"] and terms == terms_manual and len(terms) == 288,
              name + ": pulse terms == abi.encode(PulseTerms) (288 bytes)")
        check(terms == MR.terms_pulse(px, py, A["token"], PER_TX_CAP, PERIOD_CAP, PERIOD, epoch, True,
                                      A["sentinel"]), name + ": pulse terms == make_request terms_pulse")
        dumps = [MR.caveat_dump(CHAIN, e, t, CHAIN, A["enforcer"]) for e, t in mq["caveats"]]
        check(all(d is not None for d in dumps), name + ": the device has a strict decoder for every caveat (policy)")
        dump = dumps[pi]
        check(dump.startswith("pulse px=" + px.hex() + " py=" + py.hex()),
              name + ": device decodes the pulse caveat against the pinned enforcer (policy: own P1 key)")
        check(" epoch=%d " % epoch in dump and dump.endswith("sentinel=" + A["sentinel"].hex()),
              name + ": policy: epoch == device floor, sentinel == pinned sentinel")
        cav_hashes = b""
        for e, t in mq["caveats"]:
            ch = keccak(th("Caveat") + aword(e) + keccak(t))
            check(ch == E.mm_caveat_hash(e, t), name + ": caveat packet hash == EncoderLib")
            cav_hashes += ch
        dh = m_struct("Delegation", aword(A["agent"]), aword(A["vault"]), MR.ROOT, keccak(cav_hashes), word(salt))
        check(dh == MR.delegation_struct_hash(mq), name + ": delegation struct hash == make_request (generic EIP-712)")
        check(dh == E.mm_delegation_hash(A["agent"], A["vault"], MR.ROOT, mq["caveats"], salt),
              name + ": delegation struct hash == MetaMask EncoderLib port")
        check(MR.unhex(mr["rep"].fields["delegationHash"]) == dh, name + ": parse_response delegationHash")
        mand_digest = m_digest("delegationManager", dh)
        check(MR.unhex(mr["rep"].fields["digest"]) == mand_digest and MR.mandate_digest(mq) == mand_digest,
              name + ": digest == hand-written EIP-712 (DelegationManager domain)")
        check(mr["r"][1] == mand_f["reqId"], name + ": response echoes the req-id")
        mand_sig = mr["r"][2]
        verify_k1(mand_digest, mand_sig, name + " K1")
        doc = {
            "reqId": hx(mand_f["reqId"]), "request": msg(mr["cb"], mr["req_ur"]), "requestParts": mr["nparts"],
            "response": msg(mr["resp"], mr["resp_ur"]),
            "delegate": ad(A["agent"]), "delegator": ad(A["vault"]), "authority": hx(MR.ROOT), "salt": salt,
            "label": label, "agentId": AGENT_ID, "caveatCount": len(mq["caveats"]), "pulseIndex": pi,
            "caveats": [{"enforcer": ad(e), "terms": hx(t)} for e, t in mq["caveats"]],
            "terms": {"px": hx(px), "py": hx(py), "token": ad(A["token"]), "perTxAutoCap": PER_TX_CAP,
                      "periodAutoCap": PERIOD_CAP, "period": PERIOD, "epoch": epoch, "newPayeeNeedsHuman": True,
                      "sentinel": ad(A["sentinel"]), "hex": hx(terms)},
            "deviceDecode": dump if pi == 0 else dumps,
            "delegationHash": hx(dh), "digest": hx(mand_digest), "signature": hx(mand_sig),
        }
        return doc, dh

    mand_doc, dh = mandate("mandate", EPOCH, SALT, LABEL)

    # ---------------------------------------------------------------- co-signs (ripar-cosign-req -> ripar-cosign)
    def cosign(name, fields, payee, amount, nonce, salt_label, erc20_kind="transfer", erc20_from=ZERO20):
        base = {"reqId": fixed(name + " req-id", 16), "chainId": CHAIN, "enforcer": A["enforcer"],
                "delegationHash": dh, "delegator": A["vault"], "redeemer": A["agent"], "nonce": nonce,
                "expiry": EXPIRY}
        base.update(fields)
        ev12, salt16 = MR.demo_evidence(), fixed(salt_label, 16)
        cr = device_roundtrip("cosign", base, ev12=ev12, salt16=salt16, p1xy=p1xy_c)
        q = cr["q"]
        check(cr["r"][1] == base["reqId"] and cr["r"][3] == ev12 and cr["r"][4] == salt16,
              name + ": response = {req-id, r||s, evidence12, salt16}")
        presence = sha256(ev12 + salt16).digest()
        check(MR.unhex(cr["rep"].fields["presenceHash"]) == presence, name + ": presenceHash = sha256(ev12||salt16)")
        cdh = keccak(q["calldata"])
        words = [dh, aword(A["vault"]), aword(A["agent"]), aword(q["target"]), word(q["value"]), cdh, word(nonce),
                 word(EXPIRY)]
        sh = m_struct("HumanApproval", *(words + [presence]))
        request_hash = m_struct("HumanApproval", *(words + [b"\x00" * 32]))
        check(request_hash == MR.cosign_request_hash(q), name + ": requestHash (presence 0) == make_request")
        dg = m_digest("enforcer", sh)
        check(MR.unhex(cr["rep"].fields["digest"]) == dg and MR.cosign_digest(q, presence) == dg,
              name + ": HumanApproval digest == hand-written EIP-712")
        r, s = verify_p1(dg, cr["r"][2], name + " P1")
        args = word(nonce) + word(EXPIRY) + presence + r + s
        check(len(args) == 160 and MR.unhex(cr["rep"].fields["caveatArgs"]) == args,
              name + ": caveat args = abi.encode(nonce, expiry, presenceHash, r, s)")
        kind, frm, to, amt = MR.decode_erc20(q["calldata"])
        if kind == "none":
            check(to == ZERO20 and q["target"] == payee and q["value"] == amount, name + ": native send")
        else:
            # the device refuses an ERC-20 call with a native value (docs/PROTOCOL.md section 4)
            check(kind == erc20_kind and frm == erc20_from and to == payee and amt == amount and q["value"] == 0,
                  name + ": ERC-20 " + erc20_kind)
        if "ai" in fields:
            check(MR.ai_matches(q), name + ": AI claims match the device's own decode")
        else:
            check("claims" not in q, name + ": no AI claims (approve / transferFrom never match them)")
        ev = MR.evidence_fields(ev12)
        out = {
            "reqId": hx(base["reqId"]), "request": msg(cr["cb"], cr["req_ur"]), "requestParts": cr["nparts"],
            "response": msg(cr["resp"], cr["resp_ur"]),
            "delegationHash": hx(dh), "delegator": ad(A["vault"]), "redeemer": ad(A["agent"]),
            "target": ad(q["target"]), "value": q["value"], "calldata": hx(q["calldata"]), "callDataHash": hx(cdh),
            "nonce": nonce, "expiry": EXPIRY, "payee": ad(payee), "amount": amount,
            "evidence12": hx(ev12), "evidence": ev, "salt16": hx(salt16), "presenceHash": hx(presence),
            "structHash": hx(sh), "requestHash": hx(request_hash), "digest": hx(dg), "r": hx(r), "s": hx(s),
            "args": hx(args),
        }
        return out, cr

    c20, c20r = cosign("cosign erc20", {
        "target": A["token"], "value": 0, "transfer": {"to": A["payee"], "amount": ERC20_AMOUNT},
        "ai": {"text": "Pay invoice #2026-0927 (40 mUSD) to the usual design studio",
               "claims": {"to": A["payee"], "token": A["token"], "amount": ERC20_AMOUNT}},
        "budgetLeft": PERIOD_CAP, "decimals": 6, "symbol": "mUSD"}, A["payee"], ERC20_AMOUNT, 1, "salt cosign erc20")
    check(MR.unhex(c20["calldata"]) == bytes.fromhex("a9059cbb") + aword(A["payee"]) + word(ERC20_AMOUNT),
          "cosign erc20: calldata = transfer(payee, amount)")
    q20 = c20r["q"]
    check(q20["hasDecimals"] and q20["hasSymbol"] and MR.token_check(q20) == (True, 6, "mUSD"),
          "cosign erc20: MockUSD is in the firmware v1.2 token table on 10143 (6, mUSD): keys 15/16 must agree with it")
    c20["tokenDecimalsClaim"] = q20["decimals"]  # key 15 as sent (= the firmware token table: MockUSD has 6 decimals)
    c20["tokenSymbolClaim"] = q20["symbol"]  # key 16 as sent (= the firmware token table)
    cnat, _cnatr = cosign("cosign native", {
        "target": A["payee"], "value": NATIVE_VALUE,
        "ai": {"text": "Send 0.5 MON to the design studio",
               "claims": {"to": A["payee"], "token": b"\x00" * 20, "amount": NATIVE_VALUE}},
        "decimals": 18, "symbol": "MON"}, A["payee"], NATIVE_VALUE, 2, "salt cosign native")
    check(cnat["calldata"] == "0x", "cosign native: empty calldata")
    # the two other ERC-20 calls the device decodes (docs/PROTOCOL.md section 4, key 9): payee = spender / to
    capp, _cappr = cosign("cosign approve", {
        "target": A["token"], "value": 0, "approve": {"spender": A["spender"], "amount": APPROVE_AMOUNT},
        "decimals": 6, "symbol": "mUSD"}, A["spender"], APPROVE_AMOUNT, 3, "salt cosign approve", "approve")
    check(MR.unhex(capp["calldata"]) == bytes.fromhex("095ea7b3") + aword(A["spender"]) + word(APPROVE_AMOUNT),
          "cosign approve: calldata = approve(spender, amount)")
    ctf, _ctfr = cosign("cosign transferFrom", {
        "target": A["token"], "value": 0,
        "transferFrom": {"from": A["holder"], "to": A["payee2"], "amount": TRANSFER_FROM_AMOUNT},
        "decimals": 6, "symbol": "mUSD"}, A["payee2"], TRANSFER_FROM_AMOUNT, 4, "salt cosign transferFrom",
        "transferFrom", A["holder"])
    check(MR.unhex(ctf["calldata"]) == bytes.fromhex("23b872dd") + aword(A["holder"]) + aword(A["payee2"]) +
          word(TRANSFER_FROM_AMOUNT), "cosign transferFrom: calldata = transferFrom(holder, payee2, amount)")
    capp["kind"], ctf["kind"] = "approve", "transferFrom"
    ctf["from"] = ad(A["holder"])
    digests = [c["digest"] for c in (c20, cnat, capp, ctf)]
    check(len(set(digests)) == 4, "the four co-sign digests differ")

    # ---------------------------------------------------------------- deny from the co-sign review (hold SIGN 2 s)
    deny_salt = fixed("salt deny", 16)
    deny_resp = MR.simulate_deny_from_cosign(c20r["q"], KEYS, CHAIN, A["relay"], AGENT_ID, salt16=deny_salt)
    deny_ur = MR.ur_single("ripar-deny", deny_resp)
    rep = MR.parse_response(deny_ur, ("cosign", c20r["cb"]), p1xy=p1xy_c, contract=A["relay"])
    check(rep.ok() and rep.checks and not rep.unverified, "deny: make_request parse verifies (%d checks)"
          % len(rep.checks))
    dm = MR.cbor_decode(deny_resp)
    check(dm[1] == c20r["q"]["reqId"], "deny echoes the co-sign req-id")
    check(dm[3] == b"\x00" * 12 and dm[4] == deny_salt, "deny evidence is all-zero (no pulse), salt16 from the TRNG")
    check(dm[5] == AGENT_ID and dm[6] == MR.unhex(c20["requestHash"]), "deny agentId / requestHash")
    deny_presence = sha256(dm[3] + dm[4]).digest()
    check(MR.unhex(rep.fields["presenceHash"]) == deny_presence, "deny presenceHash = sha256(zero12 || salt16)")
    deny_digest = m_digest("relay", m_struct("Deny", word(AGENT_ID), dm[6], deny_presence))
    check(MR.unhex(rep.fields["digest"]) == deny_digest, "deny digest == hand-written EIP-712")
    deny_r, deny_s = verify_p1(deny_digest, dm[2], "deny P1")

    # ---------------------------------------------------------------- deny request from the companion
    # (ripar-deny-req -> ripar-deny): the companion names a request hash (here: the one of the native co-sign
    # request, which the companion can compute itself); the device signs it without the pulse (all-zero evidence,
    # firmware flows.cpp sign_deny) and echoes agentId / requestHash as keys 5 / 6
    dreq_f = {"reqId": fixed("deny request req-id", 16), "chainId": CHAIN, "relay": A["relay"], "agentId": AGENT_ID,
              "requestHash": MR.unhex(cnat["requestHash"])}
    drr = device_roundtrip("deny", dreq_f, ev12=bytes(12), salt16=fixed("salt deny request", 16), p1xy=p1xy_c)
    drm = drr["r"]
    check(drm[1] == dreq_f["reqId"] and drm[3] == bytes(12) and drm[4] == fixed("salt deny request", 16),
          "deny request: response = {req-id, r||s, zero evidence12, salt16, ..}")
    check(drm[5] == AGENT_ID and drm[6] == dreq_f["requestHash"], "deny request: keys 5 / 6 echo what was signed")
    dreq_presence = sha256(drm[3] + drm[4]).digest()
    dreq_digest = m_digest("relay", m_struct("Deny", word(AGENT_ID), drm[6], dreq_presence))
    check(MR.unhex(drr["rep"].fields["digest"]) == dreq_digest and MR.deny_digest(drr["q"], dreq_presence) ==
          dreq_digest, "deny request: digest == hand-written EIP-712")
    dreq_r, dreq_s = verify_p1(dreq_digest, drm[2], "deny request P1")
    check(dreq_digest != deny_digest, "the two deny digests differ")
    deny_req_doc = {
        "reqId": hx(dreq_f["reqId"]), "request": msg(drr["cb"], drr["req_ur"]), "requestParts": drr["nparts"],
        "response": msg(drr["resp"], drr["resp_ur"]), "requestHashOf": "cosignNative",
        "relay": ad(A["relay"]), "agentId": AGENT_ID, "requestHash": hx(drm[6]), "evidence12": hx(drm[3]),
        "salt16": hx(drm[4]), "presenceHash": hx(dreq_presence), "digest": hx(dreq_digest),
        "r": hx(dreq_r), "s": hx(dreq_s),
    }

    # ---------------------------------------------------------------- device-initiated: revoke / panic / reopen
    def revoke_msg(name, dhash):
        digest = m_digest("enforcer", m_struct("Revoke", dhash))
        check(MR.revoke_digest(CHAIN, A["enforcer"], dhash) == digest, name + ": digest == hand-written EIP-712")
        rs = MR.sign_p1(KEYS, MR.revoke_digest(CHAIN, A["enforcer"], dhash))
        resp, ur, rp = device_initiated("ripar-revoke", {1: dhash, 2: rs}, p1xy_c, A["enforcer"])
        check(MR.unhex(rp.fields["digest"]) == digest, name + ": parse digest")
        r, s = verify_p1(digest, rs, name + " P1")
        return {"delegationHash": hx(dhash), "digest": hx(digest), "r": hx(r), "s": hx(s), "response": msg(resp, ur)}

    def panic_msg(name, epoch):
        digest = m_digest("enforcer", m_struct("Panic", word(epoch)))
        check(MR.panic_digest(CHAIN, A["enforcer"], epoch) == digest, name + ": digest == hand-written EIP-712")
        rs = MR.sign_p1(KEYS, MR.panic_digest(CHAIN, A["enforcer"], epoch))
        resp, ur, rp = device_initiated("ripar-panic", {1: epoch, 2: rs}, p1xy_c, A["enforcer"])
        check(MR.unhex(rp.fields["digest"]) == digest, name + ": parse digest")
        r, s = verify_p1(digest, rs, name + " P1")
        return {"minEpoch": epoch, "digest": hx(digest), "r": hx(r), "s": hx(s), "response": msg(resp, ur)}

    def reopen_msg(name, nonce):
        digest = m_digest("sentinel", m_struct("Reopen", aword(A["vault"]), word(nonce)))
        check(MR.reopen_digest(CHAIN, A["sentinel"], A["vault"], nonce) == digest,
              name + ": digest == hand-written EIP-712")
        rs = MR.sign_p1(KEYS, MR.reopen_digest(CHAIN, A["sentinel"], A["vault"], nonce))
        resp, ur, rp = device_initiated("ripar-reopen", {1: A["vault"], 2: MR.u256_min(nonce), 3: rs}, p1xy_c,
                                        A["sentinel"])
        check(MR.unhex(rp.fields["digest"]) == digest, name + ": parse digest")
        r, s = verify_p1(digest, rs, name + " P1")
        return {"vault": ad(A["vault"]), "nonce": nonce, "digest": hx(digest), "r": hx(r), "s": hx(s),
                "response": msg(resp, ur)}

    revoke_doc = revoke_msg("revoke", dh)
    panic_doc = panic_msg("panic", PANIC_EPOCH)
    reopen_doc = reopen_msg("reopen", REOPEN_NONCE)

    # ---------------------------------------------------------------- lost context: re-pair with the on-chain floors
    pair2_f = dict(pair_f, reqId=fixed("repair req-id", 16), now=REPAIR_NOW, minEpoch=REPAIR_MIN_EPOCH_FLOOR,
                   reopenNonce=REPAIR_REOPEN_FLOOR)
    pr2 = device_roundtrip("pair", pair2_f, salt16=fixed("salt repair", 16))
    check(pr2["m"][10] == REPAIR_MIN_EPOCH_FLOOR and pr2["m"][11] == REPAIR_REOPEN_FLOOR,
          "re-pair request carries the floors as keys 10 / 11")
    check(pr2["r"][2] == k1addr and pr2["r"][3] == p1xy and pr2["r"][4] == pr["r"][4] and pr2["r"][5] == pr["r"][5],
          "re-pair: same keys, and the BindDevice signatures are the first pairing's (RFC 6979, floors not signed)")
    ts_cav = {"kind": "timestamp", "after": 0, "before": TS_BEFORE}
    mand2_doc, dh2 = mandate("repair mandate", REPAIR_MIN_EPOCH_FLOOR, REPAIR_SALT, LABEL + " (re-paired)",
                             [ts_cav])
    check(mand2_doc["caveats"][0]["enforcer"] == ad(A["timestampEnforcer"]) and mand2_doc["caveats"][0]["terms"] ==
          hx(word(TS_BEFORE)), "repair mandate: MetaMask TimestampEnforcer terms = after(16) || before(16)")
    check(mand2_doc["deviceDecode"][0] == "timestamp after=0 before=%d" % TS_BEFORE,
          "repair mandate: the device shows the timestamp bounds")
    check(dh2 != dh, "the two mandates differ")
    repair_doc = {
        "note": "the device lost its context after panic(%d) and reopen(%d) were relayed; it is paired again with "
                "the on-chain floors (keys 10 / 11) and signs a new mandate with epoch = floor" % (PANIC_EPOCH,
                                                                                                REOPEN_NONCE),
        "pair": {
            "reqId": hx(pair2_f["reqId"]), "request": msg(pr2["cb"], pr2["req_ur"]), "requestParts": pr2["nparts"],
            "response": msg(pr2["resp"], pr2["resp_ur"]), "now": REPAIR_NOW,
            "minEpochFloor": REPAIR_MIN_EPOCH_FLOOR, "reopenNonceFloor": REPAIR_REOPEN_FLOOR,
            "owner": ad(k1addr), "px": hx(px), "py": hx(py), "keyId": hx(key_id), "digest": hx(bind_digest),
            "r": hx(pr2["r"][4][:32]), "s": hx(pr2["r"][4][32:]), "k1Signature": hx(pr2["r"][5]),
        },
        "mandate": mand2_doc,
        "timestamp": {"enforcer": ad(A["timestampEnforcer"]), "after": 0, "before": TS_BEFORE},
        "panic": panic_msg("repair panic", REPAIR_PANIC_EPOCH),
        "reopen": reopen_msg("repair reopen", REPAIR_REOPEN_NONCE),
    }

    # ---------------------------------------------------------------- firmware ERC-20 decode table
    erc20_doc = firmware_erc20_vectors()

    # ---------------------------------------------------------------- document
    doc = {
        "description": "Ripar device-conformance vectors: requests built, answered by the make_request.py demo device "
                       "(DEMO_SEED = sha256('ripar demo seed'), responses byte-identical to firmware v1.2, no pulse "
                       "check) and parsed back. Generated by contracts/test/vectors/gen_device_vectors.py - do not "
                       "edit. Registry, enforcer, relay and MockUSD are the addresses compiled into firmware v1.2, the "
                       "vault is the demo K1's derived vault, the MetaMask contracts are the canonical v1.3.0 ones; "
                       "sentinel, agent and payees are fake.",
        "chainId": CHAIN,
        "now": NOW,
        "addresses": {k: ad(v) for k, v in A.items()},
        "domains": {k: {"name": DOMAIN_NAME[k], "version": "1", "separator": hx(m_domain(k))} for k in DOMAIN_NAME},
        "typeHashes": {k: hx(th(k)) for k in TYPE_STRINGS},
        "demo": {
            "note": "demo keys of a PUBLIC seed (firmware test vectors) - never fund them",
            "k1": ad(k1addr), "k1PrivateKey": hx(rc.i2b(KEYS["k1"])),
            "p1PrivateKey": hx(rc.i2b(KEYS["p1"])), "px": hx(px), "py": hx(py), "keyId": hx(key_id),
        },
        "vault": vault_doc,
        "pair": {
            "reqId": hx(pair_f["reqId"]), "request": msg(pr["cb"], pr["req_ur"]), "requestParts": pr["nparts"],
            "response": msg(pr["resp"], pr["resp_ur"]),
            "owner": ad(k1addr), "px": hx(px), "py": hx(py), "keyId": hx(key_id), "digest": hx(bind_digest),
            "r": hx(pair_r), "s": hx(pair_s), "k1Signature": hx(pr["r"][5]), "firmwareId": hx(pr["r"][6]),
        },
        "mandate": mand_doc,
        "cosignErc20": c20,
        "cosignNative": cnat,
        "cosignApprove": capp,
        "cosignTransferFrom": ctf,
        "deny": {
            "fromCosign": "cosignErc20", "reqId": hx(dm[1]), "response": msg(deny_resp, deny_ur),
            "relay": ad(A["relay"]), "agentId": AGENT_ID, "requestHash": hx(dm[6]), "evidence12": hx(dm[3]),
            "salt16": hx(dm[4]), "presenceHash": hx(deny_presence), "digest": hx(deny_digest),
            "r": hx(deny_r), "s": hx(deny_s),
        },
        "denyRequest": deny_req_doc,
        "revoke": revoke_doc,
        "panic": panic_doc,
        "reopen": reopen_doc,
        "repair": repair_doc,
        "erc20Decode": erc20_doc,
    }
    return json.dumps(doc, indent=2) + "\n"


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default=OUT_DEFAULT)
    ap.add_argument("--check", action="store_true", help="exit 1 unless --out already holds exactly this output")
    a = ap.parse_args(argv[1:])
    text = build()
    text2 = build()
    check(text == text2, "output is deterministic")
    if a.check:
        try:
            with open(a.out, "r", encoding="utf-8", newline="") as fh:
                cur = fh.read()
        except IOError:
            cur = None
        if cur != text:
            print("device_vectors.json: STALE (run: python test/vectors/gen_device_vectors.py)")
            return 1
        print("device_vectors.json: up to date (%d checks passed)" % (len(CHECKS) // 2))
        return 0
    with open(a.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    print("wrote %s (%d checks passed, make_request from %s)" % (a.out, len(CHECKS) // 2, TOOLS))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
