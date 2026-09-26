#!/usr/bin/env python3
"""Reference hashes for Ripar Wallet host tests (pure Python 3, stdlib only).

Import from other tools/tests:

    import sys; sys.path.insert(0, r"E:/Projects/ripar-wallet/firmware/tools")
    from ref_hashes import keccak256, sha256, crc32, eip55, short_addr, selector, h, unhex

Contents
  keccak256(b)          legacy Keccak-256 (Ethereum, pad 0x01) -> 32 bytes. NOT hashlib.sha3_256.
  sha3_256(b)           FIPS-202 SHA3-256 with the same sponge (pad 0x06), used to self-check the permutation
  sha256(b)             hashlib SHA-256 -> 32 bytes
  crc32(b)              zlib CRC-32 (IEEE, as used by BC-UR) -> int
  eip55(addr)           EIP-55 checksummed "0x..." (addr: 20 bytes or hex str)
  short_addr(addr)      "0x5aAe...eAed" exactly like firmware util.cpp short_addr()
  selector(sig)         keccak256(sig)[:4] (e.g. "transfer(address,uint256)")
  h(b) / unhex(s)       bytes -> lower hex (no 0x) / hex str (0x optional) -> bytes
  u256(x)               int -> 32-byte big-endian
  keccak_many / sha256_many   "hash of hashes over msg[:0..n]" aggregate used by test_hashes.cpp

Run `python ref_hashes.py` to self-test on the published vectors (exit code 0 = ok).
CLI: `python ref_hashes.py keccak <text>` | `keccak-hex <hex>` | `sha256 <text>` | `eip55 <hex addr>`.
"""
import hashlib
import sys
import zlib

_MASK = (1 << 64) - 1

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# rotation offsets r[x][y] (FIPS 202 table), lane index = x + 5*y
_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rol(v, n):
    n %= 64
    return ((v << n) | (v >> (64 - n))) & _MASK if n else v


def keccak_f1600(a):
    """In-place Keccak-f[1600] on a list of 25 lanes (a[x + 5*y]). Written from the FIPS 202 spec,
    independently of the table-driven C++ version."""
    for rc in _RC:
        # theta
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for i in range(25):
            a[i] ^= d[i % 5]
        # rho + pi: B[y, 2x+3y] = rot(A[x, y], r[x, y])
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(a[x + 5 * y], _ROT[x][y])
        # chi
        for y in range(5):
            row = b[5 * y:5 * y + 5]
            for x in range(5):
                a[x + 5 * y] = row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
        # iota
        a[0] ^= rc
    return a


def _sponge(data, rate, pad, outlen):
    data = bytes(data)
    st = [0] * 25
    msg = bytearray(data)
    msg.append(pad)
    while len(msg) % rate:
        msg.append(0)
    msg[-1] |= 0x80
    for off in range(0, len(msg), rate):
        blk = msg[off:off + rate]
        for i in range(rate // 8):
            st[i] ^= int.from_bytes(blk[8 * i:8 * i + 8], "little")
        keccak_f1600(st)
    out = b"".join(st[i].to_bytes(8, "little") for i in range(25))
    return out[:outlen]


def keccak256(data):
    """Ethereum Keccak-256 (legacy padding 0x01)."""
    if isinstance(data, str):
        data = data.encode()
    return _sponge(data, 136, 0x01, 32)


def sha3_256(data):
    """FIPS 202 SHA3-256 (padding 0x06) - only to cross-check the permutation against hashlib."""
    if isinstance(data, str):
        data = data.encode()
    return _sponge(data, 136, 0x06, 32)


def sha256(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(bytes(data)).digest()


def crc32(data):
    if isinstance(data, str):
        data = data.encode()
    return zlib.crc32(bytes(data)) & 0xFFFFFFFF


def h(b):
    return bytes(b).hex()


def unhex(s):
    s = s.strip()
    if s[:2] in ("0x", "0X"):
        s = s[2:]
    return bytes.fromhex(s)


def u256(x):
    return int(x).to_bytes(32, "big")


def _addr_bytes(addr):
    if isinstance(addr, str):
        addr = unhex(addr)
    addr = bytes(addr)
    if len(addr) != 20:
        raise ValueError("address must be 20 bytes")
    return addr


def eip55(addr):
    lower = _addr_bytes(addr).hex()
    hh = keccak256(lower.encode()).hex()
    return "0x" + "".join(c.upper() if c in "abcdef" and int(hh[i], 16) >= 8 else c for i, c in enumerate(lower))


def short_addr(addr):
    full = eip55(addr)
    return full[:6] + "..." + full[38:42]


def selector(sig):
    return keccak256(sig.encode())[:4]


def pattern(n):
    """Deterministic test message used by test_hashes.cpp: byte i = (i*7 + 3) & 0xff."""
    return bytes(((i * 7 + 3) & 0xFF) for i in range(n))


def keccak_many(nmax):
    """keccak256( keccak256(m[:0]) || keccak256(m[:1]) || ... || keccak256(m[:nmax]) ), m = pattern(nmax)."""
    m = pattern(nmax)
    return keccak256(b"".join(keccak256(m[:n]) for n in range(nmax + 1)))


def sha256_many(nmax):
    m = pattern(nmax)
    return sha256(b"".join(sha256(m[:n]) for n in range(nmax + 1)))


# ---------------------------------------------------------------- self-test
KECCAK_VECTORS = [
    (b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
    (b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
    (b"The quick brown fox jumps over the lazy dog",
     "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"),
    (b"Transfer(address,address,uint256)", "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"),
]
SHA256_VECTORS = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
]
EIP55_VECTORS = [  # from the EIP-55 specification
    "0x52908400098527886E0F7030069857D2E4169EE7",
    "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
    "0xde709f2102306220921060314715629080e2fb77",
    "0x27b1fdb04752bbc536007a920d24acb045561c26",
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
]


def selftest(verbose=True):
    bad = 0

    def ok(cond, what):
        nonlocal bad
        if not cond:
            bad += 1
            print("FAIL", what)
        elif verbose:
            print("ok  ", what)

    for msg, want in KECCAK_VECTORS:
        ok(keccak256(msg).hex() == want, "keccak256(%r)" % msg[:20])
    ok(selector("transfer(address,uint256)").hex() == "a9059cbb", "selector transfer")
    ok(selector("approve(address,uint256)").hex() == "095ea7b3", "selector approve")
    ok(selector("transferFrom(address,address,uint256)").hex() == "23b872dd", "selector transferFrom")
    # permutation cross-check against a trusted implementation: same sponge with SHA3 padding == hashlib
    for n in (0, 1, 3, 55, 56, 64, 135, 136, 137, 271, 272, 273, 500):
        m = pattern(n)
        ok(sha3_256(m) == hashlib.sha3_256(m).digest(), "sponge(pad 0x06) == hashlib.sha3_256, len %d" % n)
    for msg, want in SHA256_VECTORS:
        ok(sha256(msg).hex() == want, "sha256(%r)" % msg[:20])
    ok(crc32(b"123456789") == 0xCBF43926, "crc32('123456789')")
    for a in EIP55_VECTORS:
        ok(eip55(a.lower()) == a, "eip55 " + a)
    ok(short_addr("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed") == "0x5aAe...eAed", "short_addr")
    if verbose:
        print("keccak_many(300) =", keccak_many(300).hex())
        print("sha256_many(300) =", sha256_many(300).hex())
    print("ref_hashes selftest:", "PASS" if bad == 0 else "FAIL (%d)" % bad)
    return bad == 0


def _main(argv):
    if len(argv) >= 3:
        cmd, arg = argv[1], argv[2]
        if cmd == "keccak":
            print(keccak256(arg.encode()).hex())
        elif cmd == "keccak-hex":
            print(keccak256(unhex(arg)).hex())
        elif cmd == "sha256":
            print(sha256(arg.encode()).hex())
        elif cmd == "sha256-hex":
            print(sha256(unhex(arg)).hex())
        elif cmd == "eip55":
            print(eip55(arg))
        else:
            print(__doc__)
            return 2
        return 0
    return 0 if selftest() else 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
