// The payments this phone relays from the vault (personal mandate), persisted so a restart resumes the same round:
// the request shown to the device keeps its req-id and single-use nonce until it is answered, expires or is replaced.
import { type PaymentRecord, store } from './store';

export function newPaymentId(): string {
  const b = new Uint8Array(6);
  globalThis.crypto.getRandomValues(b);
  return `p${Date.now().toString(36)}${Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')}`;
}

export function addPayment(p: PaymentRecord): void {
  store.set((s) => ({ payments: [p, ...s.payments.filter((x) => x.id !== p.id)].slice(0, 200) }));
}

export function updatePayment(id: string, patch: Partial<PaymentRecord>): void {
  store.set((s) => ({ payments: s.payments.map((p) => (p.id === id ? { ...p, ...patch } : p)) }));
}

export function paymentById(id: string): PaymentRecord | null {
  return store.get().payments.find((p) => p.id === id) ?? null;
}

/** remembers a co-sign nonce handed out for a mandate (never handed out again) */
export function rememberNonce(delegationHash: string, nonce: bigint): void {
  const k = delegationHash.toLowerCase();
  store.set((s) => ({ nonces: { ...s.nonces, [k]: [...new Set([...(s.nonces[k] ?? []), nonce.toString()])] } }));
}
