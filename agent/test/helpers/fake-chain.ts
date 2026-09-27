// An in-memory RiparChain for unit tests: a TypeScript model of PulseCosignEnforcer v1.2 (AUTO path in the enforcer's
// order via autoPathDecision, HUMAN path with the real P-256 check, single-use nonces and digests, v1.2 known-payee
// rule), token balances, the sentinel lane and the relay's attestApproval. Reverts are real ABI-encoded custom errors
// decoded by the agent's decoder, like on chain. The agent account has a nonce: every transaction is "signed" with the
// pending nonce (fake raw bytes, hash = keccak256(raw)) and can be mined at once, hidden from the RPC (receipt and
// nonce not visible yet), left in the mempool after a failed broadcast, or never received by the node at all.
import {
  DELEGATION_MANAGER,
  autoPathDecision,
  bytesToBigInt,
  computeAutoBudget,
  cosignDigest,
  decodeErc20,
  decodePulseTerms,
  hashDelegation,
  p256Verify,
  rolloverPeriod,
  toChecksumAddress,
  toHex,
  type AutoBudget,
  type Delegation,
} from '@ripar/protocol';
import { encodeErrorResult, keccak256, toHex as vHex, type Address, type Hex } from 'viem';
import { TxPendingError, type Execution, type MandateLiveness, type RiparChain, type SignedTx, type TxOutcome, type TxStatus } from '../../src/chain.js';
import { ChainRevertError, RIPAR_ERRORS_ABI, decodeRevertData } from '../../src/errors.js';
import { ZERO_ADDRESS } from '../../src/util.js';

const key = (...p: (string | bigint)[]): string => p.map((x) => String(x).toLowerCase()).join(':');

export function revertWith(name: string, args: readonly unknown[] = []): never {
  const data = encodeErrorResult({ abi: RIPAR_ERRORS_ABI, errorName: name, args } as never);
  throw new ChainRevertError(decodeRevertData(data), 'estimate');
}

export class FakeChain implements RiparChain {
  readonly chainId: number;
  readonly manager: Address = DELEGATION_MANAGER;
  readonly enforcer: Address;
  time: bigint;
  lane = true;
  balances = new Map<string, bigint>();
  tokens = new Map<string, { decimals: number; symbol: string }>();
  owners = new Map<string, Address>();
  known = new Set<string>();
  periods = new Map<string, { spent: bigint; start: bigint }>();
  nonces = new Set<string>();
  consumed = new Set<string>();
  revoked = new Set<string>();
  minEpochs = new Map<string, bigint>();
  disabled = new Set<string>();
  redeems: { path: 'auto' | 'human'; execution: Execution; args: Hex; hash: Hex }[] = [];
  attests: { relay: Address; agentId: bigint; digest: Hex }[] = [];
  /** the next redeem() throws this custom error (at estimation) */
  failNext: { name: string; args?: unknown[] } | null = null;
  /** redeem() throws a network error (not a revert) */
  networkDown = false;
  /** the next redeem() is sent but its receipt cannot be read (TxPendingError); its real outcome is revealed by confirmAll() */
  unconfirmedNext: 'success' | 'reverted' | null = null;
  /**
   * the next redeem()'s broadcast call errors (TxPendingError with nonce + raw): 'accepted' = the node took it anyway
   * (mempool, executed by mineAll()), 'rejected' = the node never got it (only a re-broadcast can deliver it)
   */
  broadcastErrorNext: 'accepted' | 'rejected' | null = null;
  /** the next redeem() signs (onSigned runs) and then the process "dies" before the broadcast: a plain Error */
  crashAfterSignNext = false;
  /** every transaction the node accepted, index = nonce (the agent account's nonces are contiguous) */
  txs: FakeTx[] = [];
  /** every transaction ever signed, by raw bytes (lower case) */
  signed = new Map<string, FakeTx>();
  /** raw transactions passed to rebroadcast() */
  rebroadcasts: Hex[] = [];
  private block = 1000n;

  constructor(
    readonly agent: Address,
    enforcer: Address,
    opts: { chainId?: number; time?: bigint } = {},
  ) {
    this.enforcer = enforcer;
    this.chainId = opts.chainId ?? 10143;
    this.time = opts.time ?? 1_790_500_000n;
  }

  setBalance(token: Address, holder: Address, v: bigint): void {
    this.balances.set(key(token, holder), v);
  }

  balance(token: Address, holder: Address): bigint {
    return this.balances.get(key(token, holder)) ?? 0n;
  }

  async getChainId(): Promise<number> {
    return this.chainId;
  }
  async now(): Promise<bigint> {
    return this.time;
  }
  async nativeBalance(a: Address): Promise<bigint> {
    return this.balance(ZERO_ADDRESS, a);
  }
  async tokenBalance(token: Address, a: Address): Promise<bigint> {
    return this.balance(token, a);
  }
  async tokenInfo(token: Address): Promise<{ decimals: number; symbol: string }> {
    const t = this.tokens.get(token.toLowerCase());
    if (!t) throw new Error(`no token ${token}`);
    return t;
  }
  async hasCode(a: Address): Promise<boolean> {
    return this.owners.has(a.toLowerCase()) || this.tokens.has(a.toLowerCase());
  }
  async autoBudget(dh: Hex, terms: Hex): Promise<AutoBudget> {
    return computeAutoBudget(terms, this.periods.get(key(dh)) ?? { spent: 0n, start: 0n }, this.time);
  }
  async periodSpent(dh: Hex): Promise<{ spent: bigint; start: bigint }> {
    return this.periods.get(key(dh)) ?? { spent: 0n, start: 0n };
  }
  async laneOpen(_sentinel: Address, _vault: Address): Promise<boolean> {
    return this.lane;
  }
  async isKnownPayee(dh: Hex, payee: Address): Promise<boolean> {
    return this.known.has(key(dh, payee));
  }
  async nonceUsed(dh: Hex, nonce: bigint): Promise<boolean> {
    return this.nonces.has(key(dh, nonce));
  }
  async mandateLiveness(dh: Hex, keyId: Hex): Promise<MandateLiveness> {
    return { revoked: this.revoked.has(key(keyId, dh)), disabled: this.disabled.has(key(dh)), minEpoch: this.minEpochs.get(key(keyId)) ?? 0n };
  }
  async vaultOwner(vault: Address): Promise<Address | null> {
    return this.owners.get(vault.toLowerCase()) ?? null;
  }

  async txStatus(hash: Hex): Promise<TxStatus> {
    const tx = this.txs.find((t) => t.hash === hash);
    return tx?.state === 'mined' && tx.status ? tx.status : { status: 'pending' };
  }

  /** the LATEST nonce the RPC shows: mined transactions up to the first one still pending or hidden */
  async accountNonce(): Promise<number> {
    const i = this.txs.findIndex((t) => t.state !== 'mined');
    return i < 0 ? this.txs.length : i;
  }

  async rebroadcast(raw: Hex): Promise<void> {
    this.rebroadcasts.push(raw);
    const tx = this.signed.get(raw.toLowerCase());
    if (!tx) throw new Error('invalid raw transaction (fake)');
    if (this.txs.includes(tx)) return; // "already known" is not an error (RiparChain contract)
    if (tx.nonce < this.txs.length) throw new Error('nonce too low (fake)');
    tx.state = 'mempool';
    this.txs.push(tx);
  }

  /** the receipts of every unconfirmed transaction become readable */
  confirmAll(): void {
    for (const t of this.txs) if (t.state === 'hidden') t.state = 'mined';
  }

  /** mines the mempool in nonce order: each transaction runs now (a revert makes a reverted receipt) */
  mineAll(): void {
    for (const t of this.txs) {
      if (t.state !== 'mempool') continue;
      try {
        t.status = t.run();
      } catch (e) {
        if (!(e instanceof ChainRevertError)) throw e;
        this.block++;
        t.status = { status: 'reverted', gasUsed: 50_000n, blockNumber: this.block };
      }
      t.state = 'mined';
    }
  }

  /** another transaction of the agent's account (e.g. sent with the same key elsewhere) is mined: it takes the next nonce */
  useNonceElsewhere(): void {
    const tx = this.sign('elsewhere', () => ({ status: 'success' }));
    this.block++;
    tx.state = 'mined';
    tx.status = { status: 'success', gasUsed: 21_000n, blockNumber: this.block };
    this.txs.push(tx);
  }

  /** a signed transaction with the account's pending nonce; not broadcast yet */
  private sign(tag: string, run: () => TxStatus): FakeTx {
    const nonce = this.txs.length;
    const raw = vHex(`fake-tx:${this.chainId}:${this.agent}:${nonce}:${this.signed.size}:${tag}`);
    const tx: FakeTx = { nonce, raw, hash: keccak256(raw), run, state: 'signed' };
    this.signed.set(raw.toLowerCase(), tx);
    return tx;
  }

  async redeem(d: Delegation, execution: Execution, args: Hex = '0x', onSigned?: (tx: SignedTx) => void): Promise<TxOutcome> {
    const announce = (tx: FakeTx) => onSigned?.({ hash: tx.hash, gasLimit: 120_000n, nonce: tx.nonce, raw: tx.raw });
    if (this.crashAfterSignNext) {
      this.crashAfterSignNext = false;
      const tx: FakeTx = this.sign(`redeem:${args}`, () => this.execute(d, execution, args, tx.hash));
      announce(tx);
      throw new Error('the process died after signing, before the broadcast (fake)');
    }
    if (this.networkDown) throw new Error('fetch failed (fake network down)');
    if (this.unconfirmedNext === 'reverted') {
      this.unconfirmedNext = null;
      const tx = this.sign(`lost:${args}`, () => ({ status: 'reverted' }));
      this.block++;
      tx.state = 'hidden';
      tx.status = { status: 'reverted', gasUsed: 50_000n, blockNumber: this.block };
      announce(tx);
      this.txs.push(tx);
      throw new TxPendingError(tx.hash, 120_000n, 'receipt timeout (fake)', tx.nonce, tx.raw);
    }
    if (this.failNext) {
      const f = this.failNext;
      this.failNext = null;
      revertWith(f.name, f.args ?? []);
    }
    const bc = this.broadcastErrorNext;
    if (bc) {
      this.broadcastErrorNext = null;
      const tx: FakeTx = this.sign(`redeem:${args}`, () => this.execute(d, execution, args, tx.hash));
      announce(tx);
      if (bc === 'accepted') {
        tx.state = 'mempool';
        this.txs.push(tx);
      }
      const why = bc === 'accepted' ? 'request timed out (fake: the node accepted it)' : 'connection reset (fake: the node never got it)';
      throw new TxPendingError(tx.hash, 120_000n, `broadcast: ${why}`, tx.nonce, tx.raw);
    }
    // executed at once: a revert here is an estimation revert (nothing signed is recorded as sent)
    const tx: FakeTx = this.sign(`redeem:${args}`, () => this.execute(d, execution, args, tx.hash));
    const st = tx.run();
    announce(tx);
    tx.status = st;
    this.txs.push(tx);
    if (this.unconfirmedNext === 'success') {
      this.unconfirmedNext = null;
      tx.state = 'hidden';
      throw new TxPendingError(tx.hash, 120_000n, 'receipt timeout (fake)', tx.nonce, tx.raw);
    }
    tx.state = 'mined';
    return { hash: tx.hash, gasLimit: 120_000n, gasUsed: st.gasUsed ?? 0n, blockNumber: st.blockNumber ?? this.block };
  }

  /** the redemption itself (the enforcer's hook + the transfer); throws a decoded revert */
  private execute(d: Delegation, execution: Execution, args: Hex, hash: Hex): TxStatus {
    if (d.delegate.toLowerCase() !== this.agent.toLowerCase()) revertWith('InvalidDelegate');
    const cav = d.caveats.find((c) => c.enforcer.toLowerCase() === this.enforcer.toLowerCase());
    if (!cav) throw new Error('no pulse caveat');
    const t = decodePulseTerms(cav.terms);
    const dh = hashDelegation(d);
    const keyId = keccak256(t.p1Key);
    if (this.disabled.has(key(dh))) revertWith('CannotUseADisabledDelegation');
    if (this.revoked.has(key(keyId, dh))) revertWith('DelegationRevoked');
    if (t.epoch < (this.minEpochs.get(key(keyId)) ?? 0n)) revertWith('StaleEpoch');
    const dec = decodeErc20(execution.callData);
    const payee = dec.kind === 'none' ? execution.target : toChecksumAddress(dec.to);
    const amount = dec.kind === 'none' ? execution.value : dec.amount;
    let path: 'auto' | 'human';
    if (args === '0x') {
      path = 'auto';
      const stored = this.periods.get(key(dh)) ?? { spent: 0n, start: 0n };
      const r = autoPathDecision(t, execution, { laneOpen: this.lane, payeeKnown: this.known.has(key(dh, payee)), stored, now: this.time });
      if (r.path === 'human') revertWith(r.reason === 'lane-closed' ? 'LaneClosed' : 'HumanRequired');
      const ro = rolloverPeriod(stored.spent, stored.start, t.period, this.time);
      this.transfer(d.delegator, execution, dec.kind, payee, amount);
      this.periods.set(key(dh), { spent: ro.spent + amount, start: ro.start === 0n ? this.time : ro.start });
    } else {
      path = 'human';
      const a = Buffer.from(args.slice(2), 'hex');
      if (a.length !== 160) revertWith('InvalidArgs');
      const nonce = bytesToBigInt(a.subarray(0, 32));
      const expiry = bytesToBigInt(a.subarray(32, 64));
      const ph = a.subarray(64, 96);
      const r = bytesToBigInt(a.subarray(96, 128));
      const s = bytesToBigInt(a.subarray(128, 160));
      if (this.time > expiry) revertWith('CosignExpired');
      const digest = toHex(
        cosignDigest(
          {
            chainId: this.chainId,
            enforcer: this.enforcer,
            delegationHash: dh,
            delegator: d.delegator,
            redeemer: this.agent,
            target: execution.target,
            value: execution.value,
            calldata: execution.callData,
            nonce,
            expiry,
          },
          ph,
        ),
      );
      if (this.consumed.has(digest) || this.nonces.has(key(dh, nonce))) revertWith('CosignReplayed');
      if (!p256Verify(t.p1Key, Buffer.from(digest.slice(2), 'hex'), r, s)) revertWith('BadCosign');
      this.transfer(d.delegator, execution, dec.kind, payee, amount);
      this.consumed.add(digest);
      this.nonces.add(key(dh, nonce));
      const meterable = /^0x0{40}$/.test(t.token)
        ? dec.kind === 'none' && execution.value > 0n
        : dec.kind === 'transfer' && execution.target.toLowerCase() === t.token.toLowerCase() && execution.value === 0n && amount > 0n;
      if (meterable) this.known.add(key(dh, payee));
    }
    this.redeems.push({ path, execution, args, hash });
    this.block++;
    return { status: 'success', gasUsed: 100_000n, blockNumber: this.block };
  }

  private transfer(vault: Address, e: Execution, kind: string, payee: Address, amount: bigint): void {
    const token = kind === 'none' ? ZERO_ADDRESS : e.target;
    const bal = this.balance(token, vault);
    if (bal < amount) revertWith('ERC20InsufficientBalance', [vault, bal, amount]);
    this.setBalance(token, vault, bal - amount);
    this.setBalance(token, payee, this.balance(token, payee) + amount);
  }

  async attestApproval(relay: Address, agentId: bigint, digest: Hex): Promise<TxOutcome> {
    if (!this.consumed.has(digest)) revertWith('NotConsumed');
    if (this.attests.some((a) => a.digest === digest)) revertWith('AlreadyAttested');
    this.attests.push({ relay, agentId, digest });
    this.block++;
    const tx = this.sign(`attest:${digest}`, () => ({ status: 'success' }));
    tx.state = 'mined';
    tx.status = { status: 'success', gasUsed: 80_000n, blockNumber: this.block };
    this.txs.push(tx);
    return { hash: tx.hash, gasLimit: 90_000n, gasUsed: 80_000n, blockNumber: this.block };
  }
}

/** a transaction of the agent's account in the fake node */
export interface FakeTx {
  nonce: number;
  raw: Hex;
  hash: Hex;
  run: () => TxStatus;
  /** signed = never reached the node; mempool = accepted, not mined; hidden = mined, the RPC does not show it yet */
  state: 'signed' | 'mempool' | 'hidden' | 'mined';
  status?: TxStatus;
}
