#!/usr/bin/env python3
"""Independent pure-Python reference for firmware src/crypto.cpp (stdlib only: hashlib, hmac).

Written separately from the C++ (affine coordinates, Python big ints, plain double-and-add, pow(x, -1, m)),
so an agreement between the two is meaningful. Checked on import-free self-test against official vectors:

  * RFC 6979 A.2.5 (P-256, SHA-256, messages "sample" and "test"): public key, k, r, s
  * BIP-32 test vector 1 (secp256k1): every xprv/xpub of m/0H/1/2H/2/1000000000 (base58check decoded)
  * SLIP-0010 nist256p1 test vector 1, "derivation retry" and "seed retry" vectors
  * secp256k1 private key 1 -> 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf

    python tools/ref_crypto.py                 # self-test (exit 0 = PASS)
    python tools/ref_crypto.py gen [out.h]     # write test/host/crypto_vectors.h (deterministic)

Import:  sys.path.insert(0, "E:/Projects/ripar-wallet/firmware/tools"); import ref_crypto as rc
  rc.K1 / rc.P1 curves; rc.pubkey(C, d) -> (x, y); rc.sign(C, d, digest32, low_s=True) -> (r, s, recid)
  rc.verify(C, (x, y), digest32, r, s); rc.recover(C, digest32, r, s, recid) -> (x, y) | None
  rc.der(r, s) -> bytes; rc.master(C, seed) / rc.ckd_priv(C, (k, c), i) / rc.derive_path(C, seed, path) -> int
  rc.eth_address((x, y)) -> 20 bytes; rc.rfc6979_k(C, d, digest32, attempt=0) -> int

Firmware conventions mirrored here (see crypto.cpp):
  * nonce: RFC 6979 with HMAC-SHA256, h1 = the 32-byte digest itself. A candidate k whose R.x >= n (probability
    ~2^-128 on secp256k1, ~2^-64 on P-256) is treated like r == 0: the RFC 6979 loop continues, so recid is
    always 0/1 (never 2/3).
  * low-s: s > n/2 -> s = n - s and recid ^= 1.
  * BIP-32 (secp256k1): an invalid master / child key is an error (no retry). SLIP-10 (P-256): retry rules.
"""
import hashlib
import hmac
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ref_hashes import keccak256, eip55  # noqa: E402  (independent keccak, cross-checked vs hashlib sha3)


class CurveDef(object):
    def __init__(self, name, p, n, a, b, gx, gy, seed_key):
        self.name, self.p, self.n, self.a, self.b = name, p, n, a, b
        self.G = (gx, gy)
        self.seed_key = seed_key


# SEC 2 v2 section 2.4.1 (secp256k1) and FIPS 186-4 D.1.2.3 / SEC 2 2.4.2 (P-256 = secp256r1 = nist256p1)
K1 = CurveDef(
    "secp256k1",
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    a=0,
    b=7,
    gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    seed_key=b"Bitcoin seed",
)
P1 = CurveDef(
    "nist256p1",
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    a=-3,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    seed_key=b"Nist256p1 seed",
)
HARD = 0x80000000
PATH_K1 = [44 | HARD, 60 | HARD, 0 | HARD, 0, 0]
PATH_P1 = [7951 | HARD, 0 | HARD]


# ------------------------------------------------------------------ helpers
def i2b(x, n=32):
    return int(x).to_bytes(n, "big")


def b2i(b):
    return int.from_bytes(bytes(b), "big")


def h(b):
    return bytes(b).hex()


def unhex(s):
    s = s.strip()
    if s[:2] in ("0x", "0X"):
        s = s[2:]
    return bytes.fromhex(s)


def sha256(b):
    return hashlib.sha256(bytes(b)).digest()


def hmac256(k, m):
    return hmac.new(bytes(k), bytes(m), hashlib.sha256).digest()


def hmac512(k, m):
    return hmac.new(bytes(k), bytes(m), hashlib.sha512).digest()


# ------------------------------------------------------------------ affine EC arithmetic (None = infinity)
def on_curve(C, P):
    if P is None:
        return False
    x, y = P
    if not (0 <= x < C.p and 0 <= y < C.p):
        return False
    return (y * y - (x * x * x + C.a * x + C.b)) % C.p == 0


def ec_add(C, P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    p = C.p
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        lam = (3 * x1 * x1 + C.a) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def ec_mul(C, k, P):
    """plain right-to-left double-and-add (deliberately a different algorithm from the firmware's window)"""
    R = None
    Q = P
    k = int(k)
    if k < 0:
        raise ValueError("negative scalar")
    while k:
        if k & 1:
            R = ec_add(C, R, Q)
        Q = ec_add(C, Q, Q)
        k >>= 1
    return R


def pubkey(C, d):
    if not (1 <= d < C.n):
        return None
    return ec_mul(C, d, C.G)


def compress(P):
    x, y = P
    return bytes([2 | (y & 1)]) + i2b(x)


def xy64(P):
    return i2b(P[0]) + i2b(P[1])


def eth_address(P):
    return keccak256(xy64(P))[12:]


# ------------------------------------------------------------------ RFC 6979 (generic bits2int / bits2octets)
def _bits2int(b, qlen):
    v = b2i(b)
    blen = len(b) * 8
    if blen > qlen:
        v >>= blen - qlen
    return v


def _int2octets(x, rlen):
    return i2b(x, rlen)


def _bits2octets(b, q, qlen, rlen):
    z1 = _bits2int(b, qlen)
    z2 = z1 % q  # z1 < 2^qlen < 2q, so this is at most one subtraction (RFC: "z2 = z1 mod q")
    return _int2octets(z2, rlen)


def rfc6979_candidates(C, d, h1, raw=False):
    """yields the successive k candidates of RFC 6979 section 3.2 (HMAC-SHA256); h1 = H(m) as bytes.
    raw=True also yields out-of-range candidates (every T, as an int), for testing the reject step."""
    q = C.n
    qlen = q.bit_length()
    rlen = (qlen + 7) // 8
    hlen = 32
    V = b"\x01" * hlen
    K = b"\x00" * hlen
    xo = _int2octets(d, rlen)
    ho = _bits2octets(h1, q, qlen, rlen)
    K = hmac256(K, V + b"\x00" + xo + ho)
    V = hmac256(K, V)
    K = hmac256(K, V + b"\x01" + xo + ho)
    V = hmac256(K, V)
    while True:
        T = b""
        while len(T) * 8 < qlen:
            V = hmac256(K, V)
            T += V
        k = _bits2int(T, qlen)
        if raw or 1 <= k < q:
            yield k
        K = hmac256(K, V + b"\x00")
        V = hmac256(K, V)


def rfc6979_k(C, d, h1, attempt=0):
    g = rfc6979_candidates(C, d, h1)
    for _ in range(attempt):
        next(g)
    return next(g)


# ------------------------------------------------------------------ ECDSA
def _z(C, digest):
    return _bits2int(digest, C.n.bit_length())


def sign(C, d, digest, low_s=True):
    """-> (r, s, recid) with the firmware's conventions (see module docstring)"""
    assert len(digest) == 32
    if not (1 <= d < C.n):
        return None
    n = C.n
    z = _z(C, digest)
    for k in rfc6979_candidates(C, d, digest):
        R = ec_mul(C, k, C.G)
        x, y = R
        if x >= n:  # firmware: treat like an invalid r, continue the RFC 6979 loop (keeps recid in {0,1})
            continue
        r = x
        if r == 0:
            continue
        s = pow(k, -1, n) * (z + r * d) % n
        if s == 0:
            continue
        recid = y & 1
        if low_s and s > n // 2:
            s = n - s
            recid ^= 1
        return r, s, recid


def verify(C, P, digest, r, s):
    n = C.n
    if not on_curve(C, P):
        return False
    if not (1 <= r < n and 1 <= s < n):
        return False
    z = _z(C, digest)
    w = pow(s, -1, n)
    X = ec_add(C, ec_mul(C, z * w % n, C.G), ec_mul(C, r * w % n, P))
    if X is None:
        return False
    return X[0] % n == r


def _sqrt_mod(C, a):
    p = C.p
    assert p % 4 == 3
    y = pow(a, (p + 1) // 4, p)
    return y if y * y % p == a % p else None


def recover(C, digest, r, s, recid):
    n, p = C.n, C.p
    if recid not in (0, 1):
        return None
    if not (1 <= r < n and 1 <= s < n):
        return None
    x = r
    y = _sqrt_mod(C, (x * x * x + C.a * x + C.b) % p)
    if y is None:
        return None
    if (y & 1) != (recid & 1):
        y = p - y
    R = (x, y)
    z = _z(C, digest)
    rinv = pow(r, -1, n)
    Q = ec_add(C, ec_mul(C, (-z * rinv) % n, C.G), ec_mul(C, s * rinv % n, R))
    return Q


def der(r, s):
    def enc(v):
        b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b

    body = enc(r) + enc(s)
    return b"\x30" + bytes([len(body)]) + body


# ------------------------------------------------------------------ BIP-32 / SLIP-10 private derivation
def master(C, seed):
    I = hmac512(C.seed_key, seed)
    while True:
        il = b2i(I[:32])
        if 0 < il < C.n:
            return il, I[32:]
        if C is K1:
            return None  # BIP-32: invalid master key
        I = hmac512(C.seed_key, I)  # SLIP-10: S := I, restart


def ckd_priv(C, parent, i):
    k, c = parent
    if i & HARD:
        data = b"\x00" + i2b(k) + i.to_bytes(4, "big")
    else:
        data = compress(ec_mul(C, k, C.G)) + i.to_bytes(4, "big")
    I = hmac512(c, data)
    while True:
        il = b2i(I[:32])
        if il < C.n:
            ki = (il + k) % C.n
            if ki != 0:
                return ki, I[32:]
        if C is K1:
            return None  # BIP-32: proceed with the next index (caller's job)
        I = hmac512(c, b"\x01" + I[32:] + i.to_bytes(4, "big"))  # SLIP-10 retry


def derive_ext(C, seed, path):
    e = master(C, seed)
    for i in path:
        if e is None:
            return None
        e = ckd_priv(C, e, i)
    return e


def derive_path(C, seed, path):
    e = derive_ext(C, seed, path)
    return None if e is None else e[0]


# ------------------------------------------------------------------ base58check (for the BIP-32 xprv/xpub strings)
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check_decode(s):
    v = 0
    for ch in s:
        v = v * 58 + _B58.index(ch)
    raw = v.to_bytes((v.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + raw
    payload, chk = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != chk:
        raise ValueError("bad base58 checksum: " + s)
    return payload


def parse_xkey(s):
    """-> (version, depth, fingerprint, child, chain, keydata33)"""
    p = b58check_decode(s)
    assert len(p) == 78, len(p)
    return p[:4], p[4], p[5:9], b2i(p[9:13]), p[13:45], p[45:78]


# ------------------------------------------------------------------ official vectors
RFC6979_P256 = {
    "x": 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721,
    "Ux": 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6,
    "Uy": 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299,
    "sample": (0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60,
               0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716,
               0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8),
    "test": (0xD16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0,
             0xF1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367,
             0x019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083),
}

BIP32_TV1_SEED = "000102030405060708090a0b0c0d0e0f"
BIP32_TV1 = [  # (path, xpub, xprv) from BIP-32
    ([], "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
     "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"),
    ([0 | HARD], "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
     "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"),
    ([0 | HARD, 1], "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
     "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"),
    ([0 | HARD, 1, 2 | HARD], "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
     "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"),
    ([0 | HARD, 1, 2 | HARD, 2], "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
     "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"),
    ([0 | HARD, 1, 2 | HARD, 2, 1000000000],
     "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
     "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"),
]

# SLIP-0010, "Test vector 1 for nist256p1": (path, chain code, private, compressed public)
SLIP10_P256_TV1 = [
    ([], "beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea",
     "612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2",
     "0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8"),
    ([0 | HARD], "3460cea53e6a6bb5fb391eeef3237ffd8724bf0a40e94943c98b83825342ee11",
     "6939694369114c67917a182c59ddb8cafc3004e63ca5d3b84403ba8613debc0c",
     "0384610f5ecffe8fda089363a41f56a5c7ffc1d81b59a612d0d649b2d22355590c"),
    ([0 | HARD, 1], "4187afff1aafa8445010097fb99d23aee9f599450c7bd140b6826ac22ba21d0c",
     "284e9d38d07d21e4e281b645089a94f4cf5a5a81369acf151a1c3a57f18b2129",
     "03526c63f8d0b4bbbf9c80df553fe66742df4676b241dabefdef67733e070f6844"),
    ([0 | HARD, 1, 2 | HARD], "98c7514f562e64e74170cc3cf304ee1ce54d6b6da4f880f313e8204c2a185318",
     "694596e8a54f252c960eb771a3c41e7e32496d03b954aeb90f61635b8e092aa7",
     "0359cf160040778a4b14c5f4d7b76e327ccc8c4a6086dd9451b7482b5a4972dda0"),
    ([0 | HARD, 1, 2 | HARD, 2], "ba96f776a5c3907d7fd48bde5620ee374d4acfd540378476019eab70790c63a0",
     "5996c37fd3dd2679039b23ed6f70b506c6b56b3cb5e424681fb0fa64caf82aaa",
     "029f871f4cb9e1c97f9f4de9ccd0d4a2f2a171110c61178f84430062230833ff20"),
    ([0 | HARD, 1, 2 | HARD, 2, 1000000000], "b9b7b82d326bb9cb5b5b121066feea4eb93d5241103c9e7a18aad40f1dde8059",
     "21c4f269ef0a5fd1badf47eeacebeeaa3de22eb8e5b0adcd0f27dd99d34d0119",
     "02216cd26d31147f72427a453c443ed2cde8a1e53c9cc44e5ddf739725413fe3f4"),
]
# SLIP-0010 "Test derivation retry for nist256p1" (seed = TV1 seed)
SLIP10_P256_RETRY = [
    ([28578 | HARD], "e94c8ebe30c2250a14713212f6449b20f3329105ea15b652ca5bdfc68f6c65c2",
     "06f0db126f023755d0b8d86d4591718a5210dd8d024e3e14b6159d63f53aa669",
     "02519b5554a4872e8c9c1c847115363051ec43e93400e030ba3c36b52a3e70a5b7"),
    ([28578 | HARD, 33941], "9e87fe95031f14736774cd82f25fd885065cb7c358c1edf813c72af535e83071",
     "092154eed4af83e078ff9b84322015aefe5769e31270f62c3f66c33888335f3a",
     "0235bfee614c0d5b2cae260000bb1d0d84b270099ad790022c1ae0b2e782efe120"),
]
# SLIP-0010 "Test seed retry for nist256p1"
SLIP10_P256_SEED_RETRY = ("a7305bc8df8d0951f0cb224c0e95d7707cbdf2c6ce7e8d481fec69c7ff5e9446",
                          "7762f9729fed06121fd13f326884c82f59aa95c57ac492ce8c9654e60efd130c",
                          "3b8c18469a4634517d6d0b65448f8e6c62091b45540a1743c5846be55d47d88f",
                          "0383619fadcde31063d8c5cb00dbfe1713f3e6fa169d8541a798752a1c1ca0cb20")


def selftest(verbose=True):
    fails = []

    def ck(cond, what):
        if not cond:
            fails.append(what)
        if verbose:
            print(("ok   " if cond else "FAIL ") + what)

    for C in (K1, P1):
        ck(on_curve(C, C.G), "%s: G on curve" % C.name)
        ck(ec_mul(C, C.n, C.G) is None, "%s: n*G = infinity" % C.name)
        ck(ec_mul(C, C.n - 1, C.G) == (C.G[0], C.p - C.G[1]), "%s: (n-1)*G = -G" % C.name)
        ck(C.p % 4 == 3, "%s: p = 3 mod 4" % C.name)

    # RFC 6979 A.2.5
    v = RFC6979_P256
    U = pubkey(P1, v["x"])
    ck(U == (v["Ux"], v["Uy"]), "RFC6979 A.2.5 public key")
    for msg in ("sample", "test"):
        k, r, s = v[msg]
        dg = sha256(msg.encode())
        ck(rfc6979_k(P1, v["x"], dg) == k, "RFC6979 A.2.5 k(%s)" % msg)
        r2, s2, rid = sign(P1, v["x"], dg, low_s=False)
        ck((r2, s2) == (r, s), "RFC6979 A.2.5 raw (r,s)(%s)" % msg)
        r3, s3, rid3 = sign(P1, v["x"], dg, low_s=True)
        ck(r3 == r and s3 == min(s, P1.n - s), "RFC6979 A.2.5 low-s (%s)" % msg)
        ck(verify(P1, U, dg, r, s) and verify(P1, U, dg, r3, s3), "RFC6979 A.2.5 verify (%s)" % msg)
        ck(recover(P1, dg, r3, s3, rid3) == U and recover(P1, dg, r2, s2, rid) == U,
           "RFC6979 A.2.5 recover (%s)" % msg)

    # BIP-32 TV1
    seed = unhex(BIP32_TV1_SEED)
    for path, xpub, xprv in BIP32_TV1:
        _, depth, _, _, chain, kd = parse_xkey(xprv)
        _, depth2, _, _, chain2, pub = parse_xkey(xpub)
        e = derive_ext(K1, seed, path)
        ok = (e is not None and depth == len(path) and kd[0] == 0 and e[0] == b2i(kd[1:]) and e[1] == chain
              and chain2 == chain and compress(pubkey(K1, e[0])) == pub)
        ck(ok, "BIP32 TV1 m/%s" % "/".join(("%dH" % (i & 0x7FFFFFFF)) if i & HARD else str(i) for i in path))

    # SLIP-10 nist256p1
    for name, vec in (("TV1", SLIP10_P256_TV1), ("retry", SLIP10_P256_RETRY)):
        for path, cc, pk, pub in vec:
            e = derive_ext(P1, seed, path)
            ok = (e is not None and e[0] == b2i(unhex(pk)) and e[1] == unhex(cc)
                  and compress(pubkey(P1, e[0])) == unhex(pub))
            ck(ok, "SLIP10 nist256p1 %s %s" % (name, path))
    sd, cc, pk, pub = SLIP10_P256_SEED_RETRY
    e = master(P1, unhex(sd))
    ck(e == (b2i(unhex(pk)), unhex(cc)) and compress(pubkey(P1, e[0])) == unhex(pub), "SLIP10 nist256p1 seed retry")
    # the seed-retry vector really exercises the retry (first IL is invalid)
    ck(b2i(hmac512(P1.seed_key, unhex(sd))[:32]) >= P1.n, "SLIP10 seed retry: first IL >= n")
    # ... and the derivation-retry vector really exercises the child retry (first IL of m/28578H/33941 >= n)
    kp, cp = derive_ext(P1, seed, [28578 | HARD])
    ck(b2i(hmac512(cp, compress(ec_mul(P1, kp, P1.G)) + (33941).to_bytes(4, "big"))[:32]) >= P1.n,
       "SLIP10 derivation retry: first IL >= n")

    # secp256k1 private key 1 -> well-known address
    ck(eip55(eth_address(pubkey(K1, 1))) == "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf", "k1 priv 1 -> address")

    # DER sanity
    ck(der(1, 1) == unhex("3006020101020101"), "DER small")
    ck(der(0x80, 0x7f) == unhex("30070202008002017f"), "DER high bit pad")

    print("ref_crypto selftest: %s" % ("PASS" if not fails else "FAIL (%d): %s" % (len(fails), fails)))
    return not fails


# ------------------------------------------------------------------ vector generation for test/host/test_crypto.cpp
def _prng(label):
    """deterministic byte stream: sha256(label || counter)"""
    ctr = 0
    while True:
        for b in sha256(label + ctr.to_bytes(4, "big")):
            yield b
        ctr += 1


def _take(g, n):
    return bytes(next(g) for _ in range(n))


def _carr(b):
    return "\"" + h(b) + "\""


def gen_vectors(out_path):
    lines = []
    w = lines.append
    w("// GENERATED by tools/ref_crypto.py gen -- do not edit. Independent Python reference values for test_crypto.cpp.")
    w("// Hex strings (no 0x). curve: 0 = secp256k1, 1 = P-256.")
    w("#pragma once")
    w("")

    # --- ECDSA vectors
    w("struct EcdsaVec {")
    w("  int curve;")
    w("  const char* priv;    // 32 B")
    w("  const char* digest;  // 32 B")
    w("  const char* pub;     // 64 B X||Y")
    w("  const char* rs;      // 64 B r||s, low-s (what ecdsa_sign must return)")
    w("  int recid;           // recid of the low-s signature")
    w("  const char* rs_raw;  // 64 B r||s before low-s normalisation")
    w("  int recid_raw;")
    w("  const char* der;     // strict DER of rs")
    w("  const char* addr;    // eth address (k1 only, else \"\")")
    w("};")
    w("static const EcdsaVec ECDSA_VECS[] = {")
    count = 0
    for C, ci in ((K1, 0), (P1, 1)):
        g = _prng(b"ripar-ecdsa-" + C.name.encode())
        cases = []
        # edge private keys and digests
        cases.append((1, bytes(32)))
        cases.append((2, b"\xff" * 32))  # digest >= n (reduced mod n)
        cases.append((C.n - 1, i2b(C.n)))  # digest == n  -> z = 0
        cases.append((C.n - 2, i2b(C.n - 1)))
        cases.append(((C.n - 1) // 2, i2b(C.n + 5)))
        cases.append((0x100000000, sha256(b"sample")))
        for _ in range(40):
            d = 0
            while not (1 <= d < C.n):
                d = b2i(_take(g, 32))
            cases.append((d, _take(g, 32)))
        for d, dg in cases:
            P = pubkey(C, d)
            r, s, rid = sign(C, d, dg, True)
            rr, sr, ridr = sign(C, d, dg, False)
            assert verify(C, P, dg, r, s) and recover(C, dg, r, s, rid) == P
            assert verify(C, P, dg, rr, sr) and recover(C, dg, rr, sr, ridr) == P
            addr = eth_address(P) if C is K1 else b""
            w("    {%d, %s, %s, %s, %s, %d, %s, %d, %s, %s}," % (
                ci, _carr(i2b(d)), _carr(dg), _carr(xy64(P)), _carr(i2b(r) + i2b(s)), rid,
                _carr(i2b(rr) + i2b(sr)), ridr, _carr(der(r, s)), _carr(addr)))
            count += 1
    w("};")
    w("")

    # --- raw RFC 6979 DRBG candidates 0..3 (exercises the reject step K = HMAC_K(V||0x00), V = HMAC_K(V))
    w("struct NonceVec {")
    w("  int curve;")
    w("  const char* priv;")
    w("  const char* digest;")
    w("  const char* cand[4];  // raw candidates T_0..T_3")
    w("};")
    w("static const NonceVec NONCE_VECS[] = {")
    g = _prng(b"ripar-nonce")
    for C, ci in ((K1, 0), (P1, 1)):
        for j in range(4):
            d = 1 + b2i(_take(g, 32)) % (C.n - 1)
            dg = bytes([0xFF]) * 32 if j == 0 else _take(g, 32)
            gen = rfc6979_candidates(C, d, dg, raw=True)
            cands = [next(gen) for _ in range(4)]
            w("    {%d, %s, %s, {%s}}," % (ci, _carr(i2b(d)), _carr(dg), ", ".join(_carr(i2b(k)) for k in cands)))
    w("};")
    w("")

    # --- DER edge cases (independent of signing)
    w("struct DerVec {")
    w("  const char* rs;")
    w("  const char* der;")
    w("};")
    w("static const DerVec DER_VECS[] = {")
    der_cases = [
        (1, 1), (0x7F, 0x80), (0x80, 0x7F), (0xFF, 0x100), (0x7FFF, 0x8000),
        (K1.n - 1, P1.n - 1), ((1 << 255), (1 << 255) - 1), ((1 << 256) - 1, 1),
        (0x00FF << 240, 0x0080 << 240), (0x80 << 240, 0x01 << 248), (b2i(b"\x00" * 31 + b"\x80"), 5),
        (0, 0), (0x01 << 8, 0x7F << 248),
    ]
    g = _prng(b"ripar-der")
    for _ in range(20):
        # random lengths with a random number of leading zero bytes and random top bits
        lz1, lz2 = next(g) % 6, next(g) % 6
        r = b2i(b"\x00" * lz1 + _take(g, 32 - lz1))
        s = b2i(b"\x00" * lz2 + _take(g, 32 - lz2))
        der_cases.append((r, s))
    for r, s in der_cases:
        w("    {%s, %s}," % (_carr(i2b(r) + i2b(s)), _carr(der(r, s))))
    w("};")
    w("")

    # --- derivation vectors: random seeds / paths, plus the product paths
    w("struct DeriveVec {")
    w("  int curve;")
    w("  const char* seed;")
    w("  int depth;")
    w("  unsigned path[6];")
    w("  const char* priv;   // 32 B result of derive_path")
    w("  const char* chain;  // 32 B chain code of the final node")
    w("};")
    w("static const DeriveVec DERIVE_VECS[] = {")
    g = _prng(b"ripar-derive")
    for C, ci in ((K1, 0), (P1, 1)):
        for j in range(14):
            seed = _take(g, [16, 32, 64, 17, 1, 100][j % 6])
            if j < 2:
                path = PATH_K1 if C is K1 else PATH_P1
            else:
                depth = next(g) % 6
                path = []
                for _ in range(depth):
                    raw = b2i(_take(g, 4))
                    path.append(raw if next(g) & 1 else raw & 0x7FFFFFFF)
            e = derive_ext(C, seed, path)
            assert e is not None
            pp = list(path) + [0] * (6 - len(path))
            w("    {%d, %s, %d, {%s}, %s, %s}," % (ci, _carr(seed), len(path), ", ".join("0x%08Xu" % x for x in pp),
                                                  _carr(i2b(e[0])), _carr(e[1])))
    w("};")
    w("")

    # --- product keys for a fixed demo seed (sha256("ripar demo seed")) -> handy for other agents' tests
    seed = sha256(b"ripar demo seed")
    k1 = derive_path(K1, seed, PATH_K1)
    p1 = derive_path(P1, seed, PATH_P1)
    w("// seed = sha256(\"ripar demo seed\"); K1 = m/44'/60'/0'/0/0 (secp256k1), P1 = m/7951'/0' (P-256)")
    w("static const char DEMO_SEED[] = %s;" % _carr(seed))
    w("static const char DEMO_K1_PRIV[] = %s;" % _carr(i2b(k1)))
    w("static const char DEMO_K1_ADDR[] = %s;" % _carr(eth_address(pubkey(K1, k1))))
    w("static const char DEMO_P1_PRIV[] = %s;" % _carr(i2b(p1)))
    w("static const char DEMO_P1_PUB[] = %s;" % _carr(xy64(pubkey(P1, p1))))
    w("")

    # --- SHA-512 / HMAC vectors from hashlib over pattern lengths
    w("struct HashVec {")
    w("  unsigned klen;  // HMAC key = pattern(klen) with byte i = (i*13 + 7) & 0xff")
    w("  unsigned mlen;  // message = pattern(mlen) with byte i = (i*7 + 3) & 0xff")
    w("  const char* sha512;       // sha512(message)")
    w("  const char* hmac_sha256;  // HMAC-SHA256(key, message)")
    w("  const char* hmac_sha512;")
    w("};")
    w("static const HashVec HASH_VECS[] = {")
    for klen, mlen in [(0, 0), (1, 1), (20, 3), (32, 55), (63, 56), (64, 63), (65, 64), (100, 111), (128, 112),
                       (129, 127), (200, 128), (131, 129), (7, 239), (37, 240), (64, 255), (128, 256), (13, 1000)]:
        key = bytes((i * 13 + 7) & 0xFF for i in range(klen))
        msg = bytes((i * 7 + 3) & 0xFF for i in range(mlen))
        w("    {%du, %du, %s, %s, %s}," % (klen, mlen, _carr(hashlib.sha512(msg).digest()), _carr(hmac256(key, msg)),
                                         _carr(hmac512(key, msg))))
    w("};")
    w("")
    w("// %d ECDSA vectors" % count)
    with open(out_path, "w", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print("wrote %s (%d ECDSA vectors)" % (out_path, count))


def _main(argv):
    if len(argv) >= 2 and argv[1] == "gen":
        ok = selftest(verbose=False)
        if not ok:
            return 1
        out = argv[2] if len(argv) >= 3 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "test",
                                                             "host", "crypto_vectors.h")
        gen_vectors(os.path.normpath(out))
        return 0
    return 0 if selftest(verbose=True) else 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
