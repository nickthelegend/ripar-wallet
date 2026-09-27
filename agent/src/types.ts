// Domain types persisted in agent/data/*.json. Amounts and other uint256 values are decimal strings (JSON-safe).
import type { EscalationReason } from '@ripar/protocol';
import type { Address, Hash, Hex } from 'viem';

/** a framework Delegation in JSON form (salt as a decimal string) */
export interface DelegationJson {
  delegate: Address;
  delegator: Address;
  authority: Hex;
  caveats: { enforcer: Address; terms: Hex; args: Hex }[];
  salt: string;
  signature: Hex;
}

export interface PulseTermsJson {
  enforcer: Address;
  terms: Hex;
  px: Hex;
  py: Hex;
  /** px‖py */
  p1Key: Hex;
  /** keccak256(abi.encode(px, py)) */
  keyId: Hex;
  /** metered asset, zero = native */
  token: Address;
  perTxAutoCap: string;
  periodAutoCap: string;
  period: number;
  epoch: string;
  newPayeeNeedsHuman: boolean;
  sentinel: Address;
}

export interface StoredMandate {
  delegation: DelegationJson;
  delegationHash: Hex;
  /** = delegation.delegator: the canonical HybridDeleGator of `owner` */
  vault: Address;
  /** K1 recovered from the mandate signature (the vault's EOA owner) */
  owner: Address;
  pulse: PulseTermsJson;
  /** the other caveats, by MetaMask enforcer kind */
  otherCaveats: { enforcer: Address; kind: string; terms: Hex }[];
  /** ERC-8004 agent id the device files denials against (mandate request key 10), when known */
  agentId?: string;
  label?: string;
  source: 'delegation' | 'device-qr';
  receivedAt: number;
  status: 'active' | 'dead';
  deadReason?: string;
  warnings: string[];
}

export interface Invoice {
  id: string;
  vendor: string;
  /** the payee of record */
  payee: Address;
  /** 'mUSD' | 'native' | 'AUSD' | 0x token address */
  token: string;
  /** decimal token units, e.g. "2.50" */
  amount: string;
  /** UNTRUSTED text */
  memo?: string;
  recurring?: { intervalSeconds: number };
  /** unix s; absent = due now */
  dueAt?: number;
}

export type InvoiceStatus = 'open' | 'escalated' | 'paid' | 'denied' | 'failed';

export interface InvoiceState {
  status: InvoiceStatus;
  /** recurring invoices: next time the invoice is due */
  nextDueAt?: number;
  paidCount: number;
  payments: string[];
  escalationId?: string;
  lastError?: string;
  /** an AUTO redemption that was sent but not confirmed: the invoice is not paid again until it settles */
  pendingTx?: { hash: Hash; gasLimit: string; to: Address; token: Address; amount: string; at: number };
  updatedAt: number;
}

export type EscalationStatus = 'pending' | 'submitting' | 'executed' | 'failed' | 'denied' | 'expired';

export type EscalationWhy = EscalationReason | 'payee-redirect' | 'chain-human-required' | 'chain-lane-closed';

/** buildRequest('cosign', ...) fields in JSON form (docs/PROTOCOL.md ripar-cosign-req) */
export interface CosignRequestJson {
  chainId: number;
  enforcer: Address;
  delegationHash: Hex;
  delegator: Address;
  redeemer: Address;
  target: Address;
  value: string;
  calldata: Hex;
  nonce: string;
  expiry: number;
  risk?: { src: string; category: string; label: string; ageDays: number };
  ai: { text: string; claims: { to: Address; token: Address; amount: string } };
  budgetLeft: string;
  decimals?: number;
  symbol?: string;
}

export interface Escalation {
  id: string;
  status: EscalationStatus;
  createdAt: number;
  updatedAt: number;
  invoiceId?: string;
  reason: EscalationWhy;
  reasonText: string;
  /** the single execution the HUMAN redemption will run */
  execution: { target: Address; value: string; callData: Hex };
  /** what the device must co-sign (the companion builds / shows the QR) */
  cosign: CosignRequestJson;
  /** the same request prebuilt by the agent: single-part UR and multipart parts (upper case) */
  request: { type: 'ripar-cosign-req'; reqId: Hex; ur: string; parts: string[] };
  /** hashStruct(HumanApproval) with presenceHash = 0: the requestHash of a device deny from this review */
  requestHash: Hex;
  display: { vendor?: string; payee: Address; amount: string; symbol: string; token: Address; memo?: string; redirectedFrom?: Address };
  planner?: string;
  /** the verified co-sign being redeemed (set before sending; txHash once sent) */
  submission?: { approvalDigest: Hex; presenceHash: Hex; txHash?: Hash; gasLimit?: string; at: number };
  result?: {
    txHash: Hash;
    gasUsed: string;
    gasLimit: string;
    blockNumber: string;
    approvalDigest: Hex;
    presenceHash: Hex;
    paymentId: string;
    attest?: { txHash?: Hash; error?: string };
  };
  error?: { name: string; message: string; at: number };
  deny?: { at: number; verified: boolean; requestHash?: Hex; note?: string };
}

export interface PaymentRecord {
  id: string;
  invoiceId?: string;
  escalationId?: string;
  path: 'auto' | 'human';
  txHash: Hash;
  gasUsed: string;
  gasLimit: string;
  blockNumber: string;
  to: Address;
  /** zero = native */
  token: Address;
  amount: string;
  at: number;
}
