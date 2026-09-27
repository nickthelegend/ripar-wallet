// ViemChain against a scripted JSON-RPC (viem custom transport, nothing leaves the process): a transaction is signed
// locally and its hash computed BEFORE the broadcast, so a broadcast error still yields TxPendingError with the hash,
// nonce and signed bytes; the receipt / nonce / re-broadcast helpers settlePending() relies on; token symbols.
import { describe, expect, it } from 'vitest';
import { custom, encodeAbiParameters, keccak256, parseTransaction, type Hex } from 'viem';
import { generatePrivateKey, privateKeyToAddress } from 'viem/accounts';
import { TxPendingError, ViemChain } from '../src/chain.js';
import { chainFor, LocalKeySigner } from '../src/signer.js';
import { DEP, ENFORCER, MUSD } from './helpers/fixture.js';

type Handler = (method: string, params: unknown[]) => unknown;

const BLOCK = {
  number: '0x10',
  hash: `0x${'11'.repeat(32)}`,
  parentHash: `0x${'22'.repeat(32)}`,
  timestamp: '0x6553f100',
  baseFeePerGas: '0x3b9aca00',
  gasLimit: '0x1c9c380',
  gasUsed: '0x0',
  transactions: [],
};

function makeChain(handler: Handler, opts: { receiptTimeoutMs?: number } = {}) {
  const calls: { method: string; params: unknown[] }[] = [];
  const transport = custom(
    {
      async request({ method, params }: { method: string; params?: unknown }) {
        const p = (params ?? []) as unknown[];
        calls.push({ method, params: p });
        const out = handler(method, p);
        if (out instanceof Error) throw out;
        if (out !== undefined) return out;
        switch (method) {
          case 'eth_chainId':
            return '0x279f';
          case 'eth_estimateGas':
            return '0x5208';
          case 'eth_getTransactionCount':
            return p[1] === 'pending' ? '0x7' : '0x6';
          case 'eth_getBlockByNumber':
            return BLOCK;
          case 'eth_blockNumber':
            return '0x10';
          case 'eth_maxPriorityFeePerGas':
            return '0x3b9aca00';
          case 'eth_gasPrice':
            return '0x77359400';
          case 'eth_getTransactionReceipt':
            return null;
          default:
            throw new Error(`unexpected ${method}`);
        }
      },
    },
    { retryCount: 0 },
  );
  const chain = chainFor(10143, 'http://127.0.0.1:9');
  const pk = generatePrivateKey();
  const signer = new LocalKeySigner(pk, chain, transport);
  const vc = new ViemChain({ chain, transport, signer, manager: DEP.delegationManager, enforcer: ENFORCER, gasMarginPercent: 20, ...opts });
  return { vc, calls, agent: privateKeyToAddress(pk) };
}

describe('ViemChain.send: sign, hash, then broadcast', () => {
  it('a broadcast error becomes TxPendingError carrying the precomputed hash, nonce and signed bytes', async () => {
    let sent: Hex | null = null;
    const { vc } = makeChain((method, params) => {
      if (method === 'eth_sendRawTransaction') {
        sent = params[0] as Hex;
        return new Error('request timed out');
      }
      return undefined;
    });
    const err = (await vc.send(MUSD, '0xa9059cbb', 0n).catch((e: unknown) => e)) as TxPendingError;
    expect(err).toBeInstanceOf(TxPendingError);
    expect(sent).not.toBeNull();
    expect(err.raw).toBe(sent);
    expect(err.hash).toBe(keccak256(sent!));
    expect(err.nonce).toBe(7); // the PENDING nonce
    expect(err.gasLimit).toBe(25_200n); // 21000 + 20%
    expect(err.reason).toMatch(/^broadcast: /);
    const tx = parseTransaction(sent!);
    expect(tx).toMatchObject({ type: 'eip1559', nonce: 7, chainId: 10143, gas: 25_200n });
    expect(tx.to?.toLowerCase()).toBe(MUSD.toLowerCase());
    expect(tx.maxFeePerGas).toBeGreaterThan(0n);
  });

  it('falls back to a legacy gas price without a base fee', async () => {
    let sent: Hex | null = null;
    const { vc } = makeChain((method, params) => {
      if (method === 'eth_getBlockByNumber') return { ...BLOCK, baseFeePerGas: null };
      if (method === 'eth_sendRawTransaction') {
        sent = params[0] as Hex;
        return new Error('nonce too low');
      }
      return undefined;
    });
    const err = (await vc.send(MUSD, '0x', 0n).catch((e: unknown) => e)) as TxPendingError;
    expect(err).toBeInstanceOf(TxPendingError);
    expect(parseTransaction(sent!)).toMatchObject({ type: 'legacy', gasPrice: 2_000_000_000n, nonce: 7 });
    expect(err.hash).toBe(keccak256(sent!));
  });

  it('a receipt that never comes is TxPendingError with the same hash', async () => {
    let sent: Hex | null = null;
    const { vc } = makeChain(
      (method, params) => {
        if (method === 'eth_sendRawTransaction') {
          sent = params[0] as Hex;
          return keccak256(sent);
        }
        return undefined;
      },
      { receiptTimeoutMs: 300 },
    );
    const err = (await vc.send(MUSD, '0x', 0n).catch((e: unknown) => e)) as TxPendingError;
    expect(err).toBeInstanceOf(TxPendingError);
    expect(err.hash).toBe(keccak256(sent!));
    expect(err.nonce).toBe(7);
    expect(err.reason).not.toMatch(/^broadcast/);
  });

  it('a revert at estimation sends nothing', async () => {
    const { vc, calls } = makeChain((method) => (method === 'eth_estimateGas' ? Object.assign(new Error('execution reverted'), { code: 3, data: '0x' }) : undefined));
    await expect(vc.send(MUSD, '0x', 0n)).rejects.toMatchObject({ name: 'ChainRevertError' });
    expect(calls.some((c) => c.method === 'eth_sendRawTransaction' || c.method === 'eth_getTransactionCount')).toBe(false);
  });
});

describe('ViemChain settle helpers', () => {
  it('txStatus: no receipt = pending, an RPC failure = unknown (never evidence of a drop)', async () => {
    let fail = false;
    const { vc } = makeChain((method) => (method === 'eth_getTransactionReceipt' && fail ? new Error('502 bad gateway') : undefined));
    const h = `0x${'aa'.repeat(32)}` as Hex;
    expect((await vc.txStatus(h)).status).toBe('pending');
    fail = true;
    expect((await vc.txStatus(h)).status).toBe('unknown');
  });

  it('accountNonce reads the LATEST nonce; rebroadcast ignores "already known" only', async () => {
    let answer: Error | Hex = new Error('already known');
    const { vc, calls } = makeChain((method) => (method === 'eth_sendRawTransaction' ? answer : undefined));
    expect(await vc.accountNonce()).toBe(6);
    expect(calls.at(-1)!.params[1]).toBe('latest');
    await expect(vc.rebroadcast('0x02')).resolves.toBeUndefined();
    answer = `0x${'bb'.repeat(32)}`;
    await expect(vc.rebroadcast('0x02')).resolves.toBeUndefined();
    answer = new Error('nonce too low');
    await expect(vc.rebroadcast('0x02')).rejects.toThrow(/nonce too low/);
  });

  it('tokenInfo keeps only a printable ASCII symbol', async () => {
    const tok = (symbol: string) =>
      makeChain((method, params) => {
        if (method !== 'eth_call') return undefined;
        const data = (params[0] as { data: Hex }).data;
        if (data.startsWith('0x313ce567')) return encodeAbiParameters([{ type: 'uint8' }], [6]);
        if (data.startsWith('0x95d89b41')) return encodeAbiParameters([{ type: 'string' }], [symbol]);
        return new Error('unexpected call');
      }).vc;
    expect(await tok('EVIL\u0000‮\u{1F600}').tokenInfo(MUSD)).toEqual({ decimals: 6, symbol: '?' });
    expect(await tok('A'.repeat(17)).tokenInfo(MUSD)).toEqual({ decimals: 6, symbol: '?' });
    expect(await tok('mUSD').tokenInfo(MUSD)).toEqual({ decimals: 6, symbol: 'mUSD' });
  });
});
