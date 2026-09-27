// ERC-20 calldata: builders (ref_eip712.calldata) and the independent decode of make_request.py decode_erc20
// (the device and the PulseCosignEnforcer decode exactly transfer / approve / transferFrom).
import { type Address, type BytesLike, type IntLike, addrWord, bytesToBigInt, concatBytes, isZero, toAddr, toBytes, toInt, unhex, word, MAX256 } from './bytes.js';
import { ProtoError } from './errors.js';
import { toChecksumAddress } from './hash.js';

export const SEL_TRANSFER = unhex('a9059cbb');
export const SEL_APPROVE = unhex('095ea7b3');
export const SEL_TRANSFER_FROM = unhex('23b872dd');

function amountWord(a: IntLike): Uint8Array {
  const v = toInt(a);
  if (v < 0n || v > MAX256) throw new ProtoError('amount does not fit uint256');
  return word(v);
}

/** transfer(address to, uint256 amount) */
export function erc20Transfer(to: BytesLike, amount: IntLike): Uint8Array {
  return concatBytes(SEL_TRANSFER, addrWord(toAddr(to, 'transfer.to')), amountWord(amount));
}

/** approve(address spender, uint256 amount) */
export function erc20Approve(spender: BytesLike, amount: IntLike): Uint8Array {
  return concatBytes(SEL_APPROVE, addrWord(toAddr(spender, 'approve.spender')), amountWord(amount));
}

/** transferFrom(address from, address to, uint256 amount) */
export function erc20TransferFrom(from: BytesLike, to: BytesLike, amount: IntLike): Uint8Array {
  return concatBytes(
    SEL_TRANSFER_FROM,
    addrWord(toAddr(from, 'transferFrom.from')),
    addrWord(toAddr(to, 'transferFrom.to')),
    amountWord(amount),
  );
}

export type Erc20Kind = 'none' | 'transfer' | 'approve' | 'transferFrom' | 'unknown';
/** C++ Erc20Call::Kind numbering (device_vectors.json erc20Decode.kinds) */
export const ERC20_KIND_NUM: Record<Erc20Kind, number> = { none: 0, transfer: 1, approve: 2, transferFrom: 3, unknown: 4 };

export interface Erc20Call {
  kind: Erc20Kind;
  /** transferFrom only, else the zero address */
  from: Uint8Array;
  /** recipient / spender, else the zero address */
  to: Uint8Array;
  amount: bigint;
}

const Z20 = new Uint8Array(20);

/** make_request decode_erc20: empty calldata = native ('none'); exactly-ABI-sized transfer / approve / transferFrom */
export function decodeErc20(calldata: BytesLike): Erc20Call {
  const cd = toBytes(calldata, null, 'calldata');
  const unknown: Erc20Call = { kind: 'unknown', from: Z20, to: Z20, amount: 0n };
  if (cd.length === 0) return { kind: 'none', from: Z20, to: Z20, amount: 0n };
  if (cd.length < 4) return unknown;
  const sel = cd.subarray(0, 4);
  const eq = (a: Uint8Array): boolean => a.every((x, i) => x === sel[i]);
  let kind: Erc20Kind;
  let words: number;
  if (eq(SEL_TRANSFER)) [kind, words] = ['transfer', 2];
  else if (eq(SEL_APPROVE)) [kind, words] = ['approve', 2];
  else if (eq(SEL_TRANSFER_FROM)) [kind, words] = ['transferFrom', 3];
  else return unknown;
  if (cd.length !== 4 + 32 * words) return unknown;
  const w = Array.from({ length: words }, (_, i) => cd.subarray(4 + 32 * i, 36 + 32 * i));
  for (const a of w.slice(0, -1)) if (!isZero(a.subarray(0, 12))) return unknown;
  if (kind === 'transferFrom') {
    return { kind, from: w[0]!.slice(12), to: w[1]!.slice(12), amount: bytesToBigInt(w[2]!) };
  }
  return { kind, from: Z20, to: w[0]!.slice(12), amount: bytesToBigInt(w[1]!) };
}

/** a display form of an ERC-20 decode */
export function describeErc20(c: Erc20Call): { kind: Erc20Kind; from: Address; to: Address; amount: bigint } {
  return { kind: c.kind, from: toChecksumAddress(c.from), to: toChecksumAddress(c.to), amount: c.amount };
}
