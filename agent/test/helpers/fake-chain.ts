// An in-memory RiparChain for unit tests: a TypeScript model of PulseCosignEnforcer v1.2 (AUTO path in the enforcer's
// order via autoPathDecision, HUMAN path with the real P-256 check, single-use nonces and digests, v1.2 known-payee
// rule), token balances, the sentinel lane and the relay's attestApproval. Reverts are real ABI-encoded custom errors
// decoded by the agent's decoder, like on chain.
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
import { TxPendingError, type Execution, type MandateLiveness, type RiparChain, type TxOutcome, type TxStatus } from '../../src/chain.js';
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
  private statuses = new Map<string, TxStatus>();
  private hidden = new Map<string, TxStatus>();
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
    return this.statuses.get(hash) ?? { status: 'pending' };
  }

  /** the receipts of every unconfirmed transaction become readable */
  confirmAll(): void {
    for (const [h, st] of this.hidden) this.statuses.set(h, st);
    this.hidden.clear();
  }

  async redeem(d: Delegation, execution: Execution, args: Hex = '0x'): Promise<TxOutcome> {
    if (this.networkDown) throw new Error('fetch failed (fake network down)');
    if (this.unconfirmedNext === 'reverted') {
      this.unconfirmedNext = null;
      const h = keccak256(vHex(`lost:${this.block}:${args}`));
      this.hidden.set(h, { status: 'reverted', gasUsed: 50_000n, blockNumber: this.block });
      throw new TxPendingError(h, 120_000n, 'receipt timeout (fake)');
    }
    if (this.failNext) {
      const f = this.failNext;
      this.failNext = null;
      revertWith(f.name, f.args ?? []);
    }
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
    const hash = keccak256(vHex(`${this.block}:${this.redeems.length}:${args}`));
    this.redeems.push({ path, execution, args, hash });
    this.block++;
    const st: TxStatus = { status: 'success', gasUsed: 100_000n, blockNumber: this.block };
    if (this.unconfirmedNext === 'success') {
      this.unconfirmedNext = null;
      this.hidden.set(hash, st);
      throw new TxPendingError(hash, 120_000n, 'receipt timeout (fake)');
    }
    this.statuses.set(hash, st);
    return { hash, gasLimit: 120_000n, gasUsed: 100_000n, blockNumber: this.block };
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
    return { hash: keccak256(vHex(`attest:${digest}`)), gasLimit: 90_000n, gasUsed: 80_000n, blockNumber: this.block };
  }
}
