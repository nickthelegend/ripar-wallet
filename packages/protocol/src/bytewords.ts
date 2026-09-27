// Bytewords (BCR-2020-012) and CRC-32, as firmware/tools/ref_ur.py.
import { ProtoError } from './errors.js';

const BW =
  'ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabiasbluebodybragbrewbulbbuzzcalmcashcatschefcity' +
  'clawcodecolacookcostcruxcurlcuspcyandarkdatadaysdelidicedietdoordowndrawdropdrumdulldutyeacheasyechoedgeepic' +
  'evenexamexiteyesfactfairfernfigsfilmfishfizzflapflewfluxfoxyfreefrogfuelfundgalagamegeargemsgiftgirlglowgood' +
  'graygrimgurugushgyrohalfhanghardhawkheathelphighhillholyhopehornhutsicedideaidleinchinkyintoirisironitemjade' +
  'jazzjoinjoltjowljudojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwiknoblamblavalazyleaflegsliarlimplion' +
  'listlogoloudloveluaulucklungmainmanymathmazememomenumeowmildmintmissmonknailnavyneednewsnextnoonnotenumbobey' +
  'oboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolposepuffpumapurrquadquizraceramprealredorichroadrockroof' +
  'rubyruinrunsrustsafesagascarsetssilkskewslotsoapsolosongstubsurfswantacotasktaxitenttiedtimetinytoiltombtoys' +
  'triptunatwinuglyundouniturgeuservastveryvetovialvibeviewvisavoidvowswallwandwarmwaspwavewaxywebswhatwhenwhiz' +
  'wolfworkyankyawnyellyogayurtzapszerozestzinczonezoom';

/** the 256 bytewords, index = byte value */
export const WORDS: readonly string[] = Array.from({ length: 256 }, (_, i) => BW.slice(4 * i, 4 * i + 4));
const MINIMAL = new Map<string, number>(WORDS.map((w, i) => [w[0]! + w[3]!, i]));
const FULL = new Map<string, number>(WORDS.map((w, i) => [w, i]));

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

/** CRC-32 (ISO-HDLC, zlib.crc32) as an unsigned 32-bit number */
export function crc32(data: Uint8Array): number {
  let c = 0xffffffff;
  for (let i = 0; i < data.length; i++) c = CRC_TABLE[(c ^ data[i]!) & 0xff]! ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

export function be32(x: number): Uint8Array {
  return Uint8Array.of((x >>> 24) & 0xff, (x >>> 16) & 0xff, (x >>> 8) & 0xff, x & 0xff);
}

export type BytewordsStyle = 'minimal' | 'standard' | 'uri';

/** bytewords of data ‖ crc32(data) (big-endian); lower case, as the reference */
export function bytewordsEncode(data: Uint8Array, style: BytewordsStyle = 'minimal'): string {
  const all = new Uint8Array(data.length + 4);
  all.set(data);
  all.set(be32(crc32(data)), data.length);
  if (style === 'minimal') {
    let s = '';
    for (const b of all) s += WORDS[b]![0]! + WORDS[b]![3]!;
    return s;
  }
  return Array.from(all, (b) => WORDS[b]!).join(style === 'standard' ? ' ' : '-');
}

/** inverse of bytewordsEncode (case-insensitive); bad word / too short / bad CRC -> ProtoError */
export function bytewordsDecode(s: string, style: BytewordsStyle = 'minimal'): Uint8Array {
  const t = s.toLowerCase();
  const out: number[] = [];
  if (style === 'minimal') {
    if (t.length % 2) throw new ProtoError('bytewords: odd length');
    for (let i = 0; i < t.length; i += 2) {
      const v = MINIMAL.get(t.slice(i, i + 2));
      if (v === undefined) throw new ProtoError(`bytewords: bad word ${JSON.stringify(t.slice(i, i + 2))}`);
      out.push(v);
    }
  } else {
    for (const w of t.split(style === 'standard' ? ' ' : '-')) {
      const v = FULL.get(w);
      if (v === undefined) throw new ProtoError(`bytewords: bad word ${JSON.stringify(w)}`);
      out.push(v);
    }
  }
  if (out.length < 5) throw new ProtoError('bytewords: too short');
  const body = Uint8Array.from(out.slice(0, -4));
  const chk = be32(crc32(body));
  const got = out.slice(-4);
  if (chk.some((b, i) => b !== got[i])) throw new ProtoError('bytewords: bad checksum');
  return body;
}
