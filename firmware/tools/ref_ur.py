#!/usr/bin/env python3
"""Reference BC-UR (BCR-2020-005 / BCR-2020-012 / BCR-2024-001) for the Ripar Wallet host tests.
Pure Python 3, stdlib only (hashlib, zlib). Written from the Blockchain Commons specs and a port of the
bc-ur C++ reference (bytewords.cpp, xoshiro256.cpp, random-sampler.cpp, fountain-utils.cpp,
fountain-encoder.cpp); independent of firmware/src/ur.cpp.

Import from other tools/tests:

    import sys; sys.path.insert(0, r"E:/Projects/ripar-wallet/firmware/tools")
    import ref_ur as U

Contents
  WORDS                         the 256 bytewords (index = byte value)
  bw_encode(data, style)        bytewords of data||crc32(data) BE; style 'minimal' | 'standard' | 'uri'
  bw_decode(s, style)           inverse; raises ValueError on bad word / bad CRC
  Xoshiro256(seed_bytes)        xoshiro256** seeded with SHA-256(seed); .from_str() / .from_crc32()
  RandomSampler(probs)          Vose alias sampler, bc-ur variant (reverse index order, LIFO lists)
  choose_degree / shuffled / choose_fragments(seq_num, seq_len, checksum)   fountain utils
  find_nominal_fragment_length / partition_message
  FountainEncoder(msg, max_frag_len, min_frag_len=10)   .part(seq_num) -> (seq, len, msglen, crc, data)
  cbor(obj)                     minimal canonical CBOR: int, bytes, str, list, dict, bool, None, Tag(n, v)
  ur_single(type, cbor_bytes)   "ur:type/<minimal bytewords>"  (lower case, as the reference)
  ur_part(type, enc, seq_num)   "ur:type/seq-len/<bytewords of part CBOR>"
  make_message(n, seed="Wolf")  the reference test message (Xoshiro256(seed).next_data(n))
  gf2_complete_at(parts, seq_len)  index (1-based count) at which a list of index-sets reaches full rank

Run `python ref_ur.py` to self-test against the official bc-ur test vectors (exit 0 = ok).
CLI: `python ref_ur.py gen-cpp`  prints the generated data block used by test/host/test_cbor_ur.cpp
     `python ref_ur.py bw <hex>` | `unbw <minimal bytewords>` | `ur <type> <cbor hex>`
     `python ref_ur.py parts <type> <cbor hex> <max_frag_len> <first> <count>`
"""
import hashlib
import sys
import zlib

# --------------------------------------------------------------------------------------------------------------
# Bytewords (BCR-2020-012). Same 1024-char string as bc-ur src/bytewords.cpp.
_BW = ("ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabiasbluebodybragbrewbulbbuzzcalmcashcatschefcity"
       "clawcodecolacookcostcruxcurlcuspcyandarkdatadaysdelidicedietdoordowndrawdropdrumdulldutyeacheasyechoedgeepic"
       "evenexamexiteyesfactfairfernfigsfilmfishfizzflapflewfluxfoxyfreefrogfuelfundgalagamegeargemsgiftgirlglowgood"
       "graygrimgurugushgyrohalfhanghardhawkheathelphighhillholyhopehornhutsicedideaidleinchinkyintoirisironitemjade"
       "jazzjoinjoltjowljudojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwiknoblamblavalazyleaflegsliarlimplion"
       "listlogoloudloveluaulucklungmainmanymathmazememomenumeowmildmintmissmonknailnavyneednewsnextnoonnotenumbobey"
       "oboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolposepuffpumapurrquadquizraceramprealredorichroadrockroof"
       "rubyruinrunsrustsafesagascarsetssilkskewslotsoapsolosongstubsurfswantacotasktaxitenttiedtimetinytoiltombtoys"
       "triptunatwinuglyundouniturgeuservastveryvetovialvibeviewvisavoidvowswallwandwarmwaspwavewaxywebswhatwhenwhiz"
       "wolfworkyankyawnyellyogayurtzapszerozestzinczonezoom")
WORDS = [_BW[i:i + 4] for i in range(0, len(_BW), 4)]
_MIN = {w[0] + w[3]: i for i, w in enumerate(WORDS)}
_FULL = {w: i for i, w in enumerate(WORDS)}


def crc32(b):
    return zlib.crc32(bytes(b)) & 0xFFFFFFFF


def be32(x):
    return (x & 0xFFFFFFFF).to_bytes(4, "big")


def bw_encode(data, style="minimal"):
    data = bytes(data) + be32(crc32(data))
    if style == "minimal":
        return "".join(WORDS[b][0] + WORDS[b][3] for b in data)
    sep = " " if style == "standard" else "-"
    return sep.join(WORDS[b] for b in data)


def bw_decode(s, style="minimal"):
    s = s.lower()
    if style == "minimal":
        if len(s) % 2:
            raise ValueError("odd length")
        out = []
        for i in range(0, len(s), 2):
            w = s[i:i + 2]
            if w not in _MIN:
                raise ValueError("bad word %r" % w)
            out.append(_MIN[w])
    else:
        sep = " " if style == "standard" else "-"
        out = []
        for w in s.split(sep):
            if w not in _FULL:
                raise ValueError("bad word %r" % w)
            out.append(_FULL[w])
    if len(out) < 5:
        raise ValueError("too short")
    body, chk = bytes(out[:-4]), bytes(out[-4:])
    if be32(crc32(body)) != chk:
        raise ValueError("bad checksum")
    return body


# --------------------------------------------------------------------------------------------------------------
# Xoshiro256** exactly as bc-ur xoshiro256.cpp
_M64 = (1 << 64) - 1
_TWO64 = 18446744073709551616.0  # (double)UINT64_MAX + 1


def _rotl(x, k):
    return ((x << k) | (x >> (64 - k))) & _M64


class Xoshiro256:
    def __init__(self, seed_bytes):
        d = hashlib.sha256(bytes(seed_bytes)).digest()
        self.s = [int.from_bytes(d[8 * i:8 * i + 8], "big") for i in range(4)]

    @classmethod
    def from_str(cls, s):
        return cls(s.encode("utf-8"))

    @classmethod
    def from_crc32(cls, c):
        return cls(be32(c))

    def next(self):
        s = self.s
        result = (_rotl((s[1] * 5) & _M64, 7) * 9) & _M64
        t = (s[1] << 17) & _M64
        s[2] ^= s[0]
        s[3] ^= s[1]
        s[1] ^= s[2]
        s[0] ^= s[3]
        s[2] ^= t
        s[3] = _rotl(s[3], 45)
        return result

    def next_double(self):
        return float(self.next()) / _TWO64  # int -> double is correctly rounded, as in C++

    def next_int(self, low, high):
        return int(self.next_double() * float(high - low + 1)) + low

    def next_byte(self):
        return self.next_int(0, 255)

    def next_data(self, n):
        return bytes(self.next_byte() for _ in range(n))


class RandomSampler:
    """bc-ur random-sampler.cpp (Vose alias method, Schwarz variant with reversed index order)."""

    def __init__(self, probs):
        assert all(p >= 0 for p in probs)
        total = 0.0
        for p in probs:  # std::accumulate: plain left-to-right sum (NOT Python's compensated sum())
            total += p
        assert total > 0
        n = len(probs)
        P = [(d * float(n)) / total for d in probs]
        S, L = [], []
        for i in range(n - 1, -1, -1):
            (S if P[i] < 1 else L).append(i)
        probs_ = [0.0] * n
        aliases = [0] * n
        while S and L:
            a = S.pop()
            g = L.pop()
            probs_[a] = P[a]
            aliases[a] = g
            P[g] += P[a] - 1
            (S if P[g] < 1 else L).append(g)
        while L:
            probs_[L.pop()] = 1.0
        while S:
            probs_[S.pop()] = 1.0
        self.probs, self.aliases = probs_, aliases

    def next(self, rng_double):
        r1 = rng_double()
        r2 = rng_double()
        n = len(self.probs)
        i = int(float(n) * r1)
        return i if r2 < self.probs[i] else self.aliases[i]


def choose_degree(seq_len, rng):
    sampler = RandomSampler([1.0 / i for i in range(1, seq_len + 1)])
    return sampler.next(rng.next_double) + 1


def shuffled(items, rng):
    remaining = list(items)
    result = []
    while remaining:
        idx = rng.next_int(0, len(remaining) - 1)
        result.append(remaining.pop(idx))
    return result


def choose_fragments(seq_num, seq_len, checksum):
    """0-based fragment indexes (sorted) mixed into part seq_num (seq_num is 1-based)."""
    if seq_num <= seq_len:
        return [seq_num - 1]
    rng = Xoshiro256(be32(seq_num) + be32(checksum))
    degree = choose_degree(seq_len, rng)
    sh = shuffled(range(seq_len), rng)
    return sorted(sh[:degree])


def find_nominal_fragment_length(message_len, min_fragment_len, max_fragment_len):
    assert message_len > 0 and min_fragment_len > 0 and max_fragment_len >= min_fragment_len
    max_count = message_len // min_fragment_len
    frag_len = None
    for count in range(1, max_count + 1):
        frag_len = -(-message_len // count)  # ceil (exact; the C++ ceil(double) is exact for these sizes)
        if frag_len <= max_fragment_len:
            break
    assert frag_len is not None
    return frag_len


def partition_message(message, frag_len):
    frags = []
    for i in range(0, len(message), frag_len):
        f = message[i:i + frag_len]
        frags.append(bytes(f) + b"\0" * (frag_len - len(f)))
    return frags


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


class FountainEncoder:
    def __init__(self, message, max_fragment_len, min_fragment_len=10, frag_len=None):
        self.message = bytes(message)
        self.msg_len = len(self.message)
        self.checksum = crc32(self.message)
        self.frag_len = frag_len or find_nominal_fragment_length(self.msg_len, min_fragment_len, max_fragment_len)
        self.frags = partition_message(self.message, self.frag_len)
        self.seq_len = len(self.frags)

    def indexes(self, seq_num):
        return choose_fragments(seq_num, self.seq_len, self.checksum)

    def part(self, seq_num):
        data = bytes(self.frag_len)
        for i in self.indexes(seq_num):
            data = xor_bytes(data, self.frags[i])
        return (seq_num, self.seq_len, self.msg_len, self.checksum, data)

    def part_cbor(self, seq_num):
        return cbor(list(self.part(seq_num)))


# --------------------------------------------------------------------------------------------------------------
# Minimal canonical CBOR encoder (RFC 8949 preferred serialization: shortest heads, definite lengths)
class Tag:
    def __init__(self, tag, value):
        self.tag, self.value = tag, value


def _head(major, v):
    assert 0 <= v <= _M64
    if v < 24:
        return bytes([(major << 5) | v])
    if v <= 0xFF:
        return bytes([(major << 5) | 24, v])
    if v <= 0xFFFF:
        return bytes([(major << 5) | 25]) + v.to_bytes(2, "big")
    if v <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + v.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + v.to_bytes(8, "big")


def cbor(obj):
    if obj is None:
        return b"\xf6"
    if obj is True:
        return b"\xf5"
    if obj is False:
        return b"\xf4"
    if isinstance(obj, int):
        return _head(0, obj) if obj >= 0 else _head(1, -1 - obj)
    if isinstance(obj, (bytes, bytearray)):
        return _head(2, len(obj)) + bytes(obj)
    if isinstance(obj, str):
        b = obj.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(obj, (list, tuple)):
        return _head(4, len(obj)) + b"".join(cbor(x) for x in obj)
    if isinstance(obj, dict):
        return _head(5, len(obj)) + b"".join(cbor(k) + cbor(v) for k, v in obj.items())
    if isinstance(obj, Tag):
        return _head(6, obj.tag) + cbor(obj.value)
    raise TypeError(type(obj))


# --------------------------------------------------------------------------------------------------------------
# UR strings
def ur_single(ur_type, cbor_bytes):
    return "ur:%s/%s" % (ur_type, bw_encode(cbor_bytes))


def ur_part(ur_type, enc, seq_num):
    return "ur:%s/%d-%d/%s" % (ur_type, seq_num, enc.seq_len, bw_encode(enc.part_cbor(seq_num)))


def make_message(n, seed="Wolf"):
    return Xoshiro256.from_str(seed).next_data(n)


def make_message_ur_cbor(n, seed="Wolf"):
    return cbor(make_message(n, seed))


def gf2_complete_at(index_sets, seq_len):
    """Feeds index sets in order into a GF(2) basis; returns the 1-based position at which the rank reaches
    seq_len (i.e. the earliest point an optimal decoder can finish), or None."""
    basis = {}  # pivot bit -> row mask
    for k, idxs in enumerate(index_sets, 1):
        m = 0
        for i in idxs:
            m ^= 1 << i
        while m:
            p = m & -m
            if p in basis:
                m ^= basis[p]
            else:
                basis[p] = m
                break
        if len(basis) == seq_len:
            return k
    return None


# --------------------------------------------------------------------------------------------------------------
# Official vectors (bc-ur test/test.cpp, BCR-2020-012, BCR-2024-001)
OFFICIAL = {
    "bytewords_1_in": bytes([0, 1, 2, 128, 255]),
    "bytewords_1_std": "able acid also lava zoom jade need echo taxi",
    "bytewords_1_uri": "able-acid-also-lava-zoom-jade-need-echo-taxi",
    "bytewords_1_min": "aeadaolazmjendeoti",
    "bytewords_2_in": bytes([
        245, 215, 20, 198, 241, 235, 69, 59, 209, 205, 165, 18, 150, 158, 116, 135, 229, 212, 19, 159, 17, 37, 239,
        240, 253, 11, 109, 191, 37, 242, 38, 120, 223, 41, 156, 189, 242, 254, 147, 204, 66, 163, 216, 175, 191, 72,
        169, 54, 32, 60, 144, 230, 210, 137, 184, 197, 33, 113, 88, 14, 157, 31, 177, 46, 1, 115, 205, 69, 225, 150,
        65, 235, 58, 144, 65, 240, 133, 69, 113, 247, 63, 53, 242, 165, 160, 144, 26, 13, 79, 237, 133, 71, 82, 69,
        254, 165, 138, 41, 85, 24]),
    "bytewords_2_min": ("yktsbbswwnwmfefrttsnonbgmtnnjyltvwtybwnebydawswtzcbdjnrsdawzdsksurdtnsrywzzemusffwottppersfdptenc"
                        "xfnmhvatdldroskcljshdbantctpadmadjksnfevymtfpwmftmhfpwtlpfejsylfhecwzonnbmhcybtgwwelpflgmfezeonle"
                        "dtgocsfzhycypf"),
    "spec_in": bytes.fromhex("d99d6ca20150c7098580125e2ab0981253468b2dbc5202c11947da"),
    "spec_min": "tantjzoeadgdstaslplabghydrpfmkbggufgludprfgmaosecffltnsoaawkbd",
    "spec_crc": 0xC904F40B,
    "rng_1": [42, 81, 85, 8, 82, 84, 76, 73, 70, 88, 2, 74, 40, 48, 77, 54, 88, 7, 5, 88, 37, 25, 82, 13, 69, 59, 30,
              39, 11, 82, 19, 99, 45, 87, 30, 15, 32, 22, 89, 44, 92, 77, 29, 78, 4, 92, 44, 68, 92, 69, 1, 42, 89,
              50, 37, 84, 63, 34, 32, 3, 17, 62, 40, 98, 82, 89, 24, 43, 85, 39, 15, 3, 99, 29, 20, 42, 27, 10, 85,
              66, 50, 35, 69, 70, 70, 74, 30, 13, 72, 54, 11, 5, 70, 55, 91, 52, 10, 43, 43, 52],
    "shuffle": [[6, 4, 9, 3, 10, 5, 7, 8, 1, 2], [10, 8, 6, 5, 1, 2, 3, 9, 7, 4], [6, 4, 5, 8, 9, 3, 2, 1, 7, 10],
                [7, 3, 5, 1, 10, 9, 4, 8, 2, 6], [8, 5, 7, 10, 2, 1, 4, 3, 9, 6], [4, 3, 5, 6, 10, 2, 7, 8, 9, 1],
                [5, 1, 3, 9, 4, 6, 2, 10, 7, 8], [2, 1, 10, 8, 9, 4, 7, 6, 3, 5], [6, 7, 10, 4, 8, 9, 2, 3, 1, 5],
                [10, 2, 1, 7, 9, 5, 6, 3, 4, 8]],
    "degrees": [11, 3, 6, 5, 2, 1, 2, 11, 1, 3, 9, 10, 10, 4, 2, 1, 1, 2, 1, 1, 5, 2, 4, 10, 3, 2, 1, 1, 3, 11, 2, 6,
                2, 9, 9, 2, 6, 7, 2, 5, 2, 4, 3, 1, 6, 11, 2, 11, 3, 1, 6, 3, 1, 4, 5, 3, 6, 1, 1, 3, 1, 2, 2, 1, 4, 5,
                1, 1, 9, 1, 1, 6, 4, 1, 5, 1, 2, 2, 3, 1, 1, 5, 2, 6, 1, 7, 11, 1, 8, 1, 5, 1, 1, 2, 2, 6, 4, 10, 1, 2,
                5, 5, 5, 1, 1, 4, 1, 1, 1, 3, 5, 5, 5, 1, 4, 3, 3, 5, 1, 11, 3, 2, 8, 1, 2, 1, 1, 4, 5, 2, 1, 1, 1, 5,
                6, 11, 10, 7, 4, 7, 1, 5, 3, 1, 1, 9, 1, 2, 5, 5, 2, 2, 3, 10, 1, 3, 2, 3, 3, 1, 1, 2, 1, 3, 2, 2, 1,
                3, 8, 4, 1, 11, 6, 3, 1, 1, 1, 1, 1, 3, 1, 2, 1, 10, 1, 1, 8, 2, 7, 1, 2, 1, 9, 2, 10, 2, 1, 3, 4, 10],
    "choose_fragments": [[0], [1], [2], [3], [4], [5], [6], [7], [8], [9], [10], [9], [2, 5, 6, 8, 9, 10], [8], [1, 5],
                         [1], [0, 2, 4, 5, 8, 10], [5], [2], [2], [0, 1, 3, 4, 5, 7, 9, 10],
                         [0, 1, 2, 3, 5, 6, 8, 9, 10], [0, 2, 4, 5, 7, 8, 9, 10], [3, 5], [4],
                         [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10], [0, 1, 3, 4, 5, 6, 7, 9, 10], [6], [5, 6], [7]],
    "single_part_ur": ("ur:bytes/hdeymejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtgwdpfnsboxgwlbaawzuefywkdplrsrj"
                       "ynbvygabwjldapfcsdwkbrkch"),
    "ur_encoder_parts": [
        "ur:bytes/1-9/lpadascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtdkgslpgh",
        "ur:bytes/2-9/lpaoascfadaxcywenbpljkhdcagwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsgmghhkhstlrdcxaefz",
        "ur:bytes/3-9/lpaxascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjksopdzmol",
        "ur:bytes/4-9/lpaaascfadaxcywenbpljkhdcasotkhemthydawydtaxneurlkosgwcekonertkbrlwmplssjtammdplolsbrdzcrtas",
        "ur:bytes/5-9/lpahascfadaxcywenbpljkhdcatbbdfmssrkzmcwnezelennjpfzbgmuktrhtejscktelgfpdlrkfyfwdajldejokbwf",
        "ur:bytes/6-9/lpamascfadaxcywenbpljkhdcackjlhkhybssklbwefectpfnbbectrljectpavyrolkzczcpkmwidmwoxkilghdsowp",
        "ur:bytes/7-9/lpatascfadaxcywenbpljkhdcavszmwnjkwtclrtvaynhpahrtoxmwvwatmedibkaegdosftvandiodagdhthtrlnnhy",
        "ur:bytes/8-9/lpayascfadaxcywenbpljkhdcadmsponkkbbhgsoltjntegepmttmoonftnbuoiyrehfrtsabzsttorodklubbuyaetk",
        "ur:bytes/9-9/lpasascfadaxcywenbpljkhdcajskecpmdckihdyhphfotjojtfmlnwmadspaxrkytbztpbauotbgtgtaeaevtgavtny",
        "ur:bytes/10-9/lpbkascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtwdkiplzs",
        "ur:bytes/11-9/lpbdascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjkvetiiapk",
        "ur:bytes/12-9/lpbnascfadaxcywenbpljkhdcarllaluzmdmgstospeyiefmwejlwtpedamktksrvlcygmzemovovllarodtmtbnptrs",
        "ur:bytes/13-9/lpbtascfadaxcywenbpljkhdcamtkgtpknghchchyketwsvwgwfdhpgmgtylctotzopdrpayoschcmhplffziachrfgd",
        "ur:bytes/14-9/lpbaascfadaxcywenbpljkhdcapazewnvonnvdnsbyleynwtnsjkjndeoldydkbkdslgjkbbkortbelomueekgvstegt",
        "ur:bytes/15-9/lpbsascfadaxcywenbpljkhdcaynmhpddpzmversbdqdfyrehnqzlugmjzmnmtwmrouohtstgsbsahpawkditkckynwt",
        "ur:bytes/16-9/lpbeascfadaxcywenbpljkhdcawygekobamwtlihsnpalnsghenskkiynthdzotsimtojetprsttmukirlrsbtamjtpd",
        "ur:bytes/17-9/lpbyascfadaxcywenbpljkhdcamklgftaxykpewyrtqzhydntpnytyisincxmhtbceaykolduortotiaiaiafhiaoyce",
        "ur:bytes/18-9/lpbgascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtntwkbkwy",
        "ur:bytes/19-9/lpbwascfadaxcywenbpljkhdcadekicpaajootjzpsdrbalpeywllbdsnbinaerkurspbncxgslgftvtsrjtksplcpeo",
        "ur:bytes/20-9/lpbbascfadaxcywenbpljkhdcayapmrleeleaxpasfrtrdkncffwjyjzgyetdmlewtkpktgllepfrltataztksmhkbot",
    ],
    # BCR-2020-005 examples: a single-part ur:seed and part 1 of 3 of the same 54-byte message
    "seed_ur": ("ur:seed/oyadhdeynteelblrcygldwvarflojtcywyjytpdkfwprylienshnjnpluypmamtkmybsjkspvseesawmrltdlnlgkplfbkq"
                "zzoglfeoyaegslobemohs"),
    "seed_part1": "ur:seed/1-3/lpadaxcsencylobemohsgmoyadhdeynteelblrcygldwvarflojtcywyjydmylgdsa",
    # BCR-2024-001: CBOR of part 1 of the raw make_message(256) (not CBOR-wrapped) at max fragment length 30
    "part1_cbor": "8501091901001a0167aa07581d916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3c",
}

# the "random sampler" vector (probabilities 1,2,4,8, seed "Wolf", 500 samples)
OFFICIAL_SAMPLER = [int(c) for c in (
    "3333333023333122133233112113131202103331333313232233332330333312332221221231303233333333231332022311"
    "2323333233333231211313223331333333332323312331323332313032113132333320331302133113123330232013332223"
    "3333233332332023333211121333223312303233330223223333132333332231302133333333133332223113220321210333"
    "2232120033233233333222333331132231101323323323322223222221233222233202133330333322313332333233332321"
    "3333220123203333331332322333332233222133331232332323332312321133233233001332333313303233133333330332")]



def selftest(verbose=True):
    ok = True

    def chk(name, cond):
        nonlocal ok
        if not cond:
            ok = False
        if verbose or not cond:
            print("%-4s %s" % ("ok" if cond else "FAIL", name))

    O = OFFICIAL
    chk("bytewords table: 256 words of 4 letters", len(WORDS) == 256 and all(len(w) == 4 for w in WORDS))
    chk("bytewords table: words unique", len(set(WORDS)) == 256)
    chk("bytewords table: first+last letter pairs unique", len(_MIN) == 256)
    chk("bytewords table: first 3 / last 3 letters unique",
        len({w[:3] for w in WORDS}) == 256 and len({w[1:] for w in WORDS}) == 256)
    chk("bytewords table: sorted", WORDS == sorted(WORDS))
    chk("bytewords_1 standard", bw_encode(O["bytewords_1_in"], "standard") == O["bytewords_1_std"])
    chk("bytewords_1 uri", bw_encode(O["bytewords_1_in"], "uri") == O["bytewords_1_uri"])
    chk("bytewords_1 minimal", bw_encode(O["bytewords_1_in"]) == O["bytewords_1_min"])
    chk("bytewords_1 decode", bw_decode(O["bytewords_1_min"]) == O["bytewords_1_in"])
    chk("bytewords_2 minimal", bw_encode(O["bytewords_2_in"]) == O["bytewords_2_min"])
    chk("bytewords_2 decode", bw_decode(O["bytewords_2_min"]) == O["bytewords_2_in"])
    chk("spec vector crc", crc32(O["spec_in"]) == O["spec_crc"])
    chk("spec vector minimal", bw_encode(O["spec_in"]) == O["spec_min"])
    rng = Xoshiro256.from_str("Wolf")
    chk("xoshiro rng_1", [rng.next() % 100 for _ in range(100)] == O["rng_1"])
    chk("find_nominal_fragment_length 1", find_nominal_fragment_length(12345, 1005, 1955) == 1764)
    chk("find_nominal_fragment_length 2", find_nominal_fragment_length(12345, 1005, 30000) == 12345)
    rng = Xoshiro256.from_str("Wolf")
    sampler = RandomSampler([1, 2, 4, 8])
    chk("random sampler (500)", [sampler.next(rng.next_double) for _ in range(500)] == OFFICIAL_SAMPLER)
    rng = Xoshiro256.from_str("Wolf")
    chk("shuffle", [shuffled(range(1, 11), rng) for _ in range(10)] == O["shuffle"])
    msg = make_message(1024)
    fl = find_nominal_fragment_length(len(msg), 10, 100)
    nfr = len(partition_message(msg, fl))
    degs = [choose_degree(nfr, Xoshiro256.from_str("Wolf-%d" % k)) for k in range(1, 201)]
    chk("choose_degree (200)", degs == O["degrees"])
    got = [choose_fragments(s, nfr, crc32(msg)) for s in range(1, 31)]
    chk("choose_fragments (30)", got == O["choose_fragments"])
    if got != O["choose_fragments"] and verbose:
        for s, (a, b) in enumerate(zip(got, O["choose_fragments"]), 1):
            if a != b:
                print("     seq %d got %s want %s" % (s, a, b))
    chk("single part UR", ur_single("bytes", make_message_ur_cbor(50)) == O["single_part_ur"])
    enc = FountainEncoder(make_message_ur_cbor(256), 30)
    parts = [ur_part("bytes", enc, s) for s in range(1, 21)]
    chk("UR encoder 20 parts", parts == O["ur_encoder_parts"])
    if parts != O["ur_encoder_parts"] and verbose:
        for a, b in zip(parts, O["ur_encoder_parts"]):
            if a != b:
                print("     got  %s\n     want %s" % (a, b))
    chk("part 1 CBOR (BCR-2024-001, raw 256-byte message)",
        FountainEncoder(make_message(256), 30).part_cbor(1).hex() == O["part1_cbor"])
    seed_msg = bw_decode(O["seed_ur"].split("/")[-1])
    chk("spec ur:seed single part is valid bytewords", len(seed_msg) == 54)
    chk("spec ur:seed part 1-3 == our encoder", ur_part("seed", FountainEncoder(seed_msg, 18), 1) == O["seed_part1"])
    # round trip of the official parts through the Python decoder of bytewords
    chk("official parts decode", all(bw_decode(p.split("/")[-1]) == enc.part_cbor(i + 1)
                                     for i, p in enumerate(O["ur_encoder_parts"])))
    if verbose:
        print("ref_ur selftest: %s" % ("PASS" if ok else "FAIL"))
    return ok


# --------------------------------------------------------------------------------------------------------------
# C++ data generator for test/host/test_cbor_ur.cpp
def _cpp_bytes(name, b):
    lines = ["static const uint8_t %s[%d] = {" % (name, max(1, len(b)))]
    for i in range(0, len(b), 20):
        lines.append("    " + ", ".join("0x%02x" % x for x in b[i:i + 20]) + ",")
    lines.append("};")
    return "\n".join(lines)


def _cpp_strings(name, strs):
    out = ["static const char* const %s[] = {" % name]
    for s in strs:
        # split long literals so lines stay readable (adjacent literals concatenate)
        chunks = [s[i:i + 100] for i in range(0, len(s), 100)] or [""]
        out.append("    " + "\n    ".join('"%s"' % c for c in chunks) + ",")
    out.append("};")
    return "\n".join(out)


def gen_stream_message(n):
    """Deterministic protocol-like CBOR message of about n bytes: {1: reqid16, 2: 10143, 9: pattern bytes}."""
    body = bytes(((i * 7 + 3) & 0xFF) for i in range(n))
    return cbor({1: bytes(range(16)), 2: 10143, 9: body, 16: "USDC"})


def gen_cpp():
    out = ["// ---- BEGIN generated by tools/ref_ur.py gen-cpp (do not edit by hand) ----"]
    # 1) official 256-byte message: decoded CBOR (0x59 0x01 0x00 || make_message(256))
    m256 = make_message_ur_cbor(256)
    out.append(_cpp_bytes("kWolf256Cbor", m256))
    out.append("static const uint32_t kWolf256Crc = 0x%08xu;" % crc32(m256))
    m50 = make_message_ur_cbor(50)
    out.append(_cpp_bytes("kWolf50Cbor", m50))
    # 2) choose_fragments official case: 1024-byte message, 11 fragments
    msg = make_message(1024)
    out.append("static const uint32_t kWolf1024Crc = 0x%08xu;" % crc32(msg))
    out.append("static const size_t kWolf1024SeqLen = %d;" % len(partition_message(msg, find_nominal_fragment_length(
        len(msg), 10, 100))))
    # 3) python fountain streams on a protocol-like message
    sm = gen_stream_message(700)
    enc = FountainEncoder(sm, 67)
    out.append(_cpp_bytes("kStreamMsg", sm))
    out.append("static const size_t kStreamSeqLen = %d, kStreamFragLen = %d;" % (enc.seq_len, enc.frag_len))
    out.append("static const uint32_t kStreamCrc = 0x%08xu;" % enc.checksum)
    # mixed-only stream: seq_len+1 .. until full rank (+ a few more)
    first = enc.seq_len + 1
    seqs = list(range(first, first + 200))
    done = gf2_complete_at([enc.indexes(s) for s in seqs], enc.seq_len)
    assert done is not None
    mixed = seqs[:done]
    out.append("// mixed parts only: seq %d..%d; an optimal (GF(2)) decoder completes exactly at the last one" % (
        mixed[0], mixed[-1]))
    out.append(_cpp_strings("kStreamMixed", [ur_part("ripar-cosign-req", enc, s) for s in mixed]))
    out.append("static const size_t kStreamMixedCount = %d;" % len(mixed))
    # index sets of these parts (for checking ur_choose_fragments)
    idx_lines = ["static const char* const kStreamMixedIdx[] = {"]
    for s in mixed:
        idx_lines.append('    "%s",' % ",".join(str(i) for i in enc.indexes(s)))
    idx_lines.append("};")
    out.append("\n".join(idx_lines))
    # pure parts out of order with duplicates
    order = [7, 3, 3, 11, 1, 9, 7, 2, 10, 5, 4, 8, 6]
    assert sorted(set(order)) == list(range(1, enc.seq_len + 1)), (order, enc.seq_len)
    out.append(_cpp_strings("kStreamPureShuffled", [ur_part("ripar-cosign-req", enc, s) for s in order]))
    out.append("static const size_t kStreamPureShuffledCount = %d;" % len(order))
    # a mix: 5 pure parts + mixed parts from a later window until complete
    pure5 = [2, 4, 6, 8, 10]
    window = list(range(enc.seq_len + 50, enc.seq_len + 250))
    combo_sets = [enc.indexes(s) for s in pure5] + [enc.indexes(s) for s in window]
    done2 = gf2_complete_at(combo_sets, enc.seq_len)
    assert done2 is not None
    combo = pure5 + window[:done2 - len(pure5)]
    out.append("// 5 pure parts then mixed parts; completes exactly at the last one")
    out.append(_cpp_strings("kStreamCombo", [ur_part("ripar-cosign-req", enc, s) for s in combo]))
    out.append("static const size_t kStreamComboCount = %d;" % len(combo))
    # second message (different checksum) for the restart test
    sm2 = gen_stream_message(300)
    enc2 = FountainEncoder(sm2, 67)
    out.append(_cpp_bytes("kStream2Msg", sm2))
    out.append(_cpp_strings("kStream2Pure", [ur_part("ripar-cosign-req", enc2, s) for s in range(1, enc2.seq_len + 1)]))
    out.append("static const size_t kStream2Count = %d;" % enc2.seq_len)
    # BCR-2020-005 ur:seed example: the single part, and parts 1..6 of the same message (part 1 is the spec's)
    seed_msg = bw_decode(OFFICIAL["seed_ur"].split("/")[-1])
    senc = FountainEncoder(seed_msg, 18)
    assert ur_part("seed", senc, 1) == OFFICIAL["seed_part1"]
    out.append(_cpp_bytes("kSeedMsg", seed_msg))
    out.append(_cpp_strings("kSeedParts", [ur_part("seed", senc, s) for s in range(1, 7)]))
    out.append("// fragment indexes of ur:seed parts 1..6: %s" % [senc.indexes(s) for s in range(1, 7)])
    # single-part UR of a protocol-like map, upper case as the device emits it
    small = cbor({1: bytes(range(16)), 2: bytes(64), 3: bytes(12), 4: bytes(16)})
    out.append(_cpp_bytes("kSmallCbor", small))
    out.append('static const char* const kSmallUr = "%s";' % ur_single("ripar-cosign", small).upper())
    out.append("// ---- END generated ----")
    return "\n".join(out)


def _main(argv):
    if len(argv) >= 2 and argv[1] == "gen-cpp":
        print(gen_cpp())
        return 0
    if len(argv) == 3 and argv[1] == "bw":
        print(bw_encode(bytes.fromhex(argv[2])))
        return 0
    if len(argv) == 3 and argv[1] == "unbw":
        print(bw_decode(argv[2]).hex())
        return 0
    if len(argv) == 4 and argv[1] == "ur":
        print(ur_single(argv[2], bytes.fromhex(argv[3])))
        return 0
    if len(argv) == 7 and argv[1] == "parts":
        enc = FountainEncoder(bytes.fromhex(argv[3]), int(argv[4]))
        for s in range(int(argv[5]), int(argv[5]) + int(argv[6])):
            print(ur_part(argv[2], enc, s))
        return 0
    if len(argv) > 1:
        print(__doc__)
        return 2
    return 0 if selftest() else 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
