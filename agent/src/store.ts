// Persistent state in agent/data/*.json (gitignored): mandate.json, escalations.json, payments.json, invoices.json.
// Each write goes to a temporary file first and is then renamed over the old one, so a crash never leaves half a file.
import { copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { toJson } from './util.js';
import type { Escalation, Invoice, InvoiceState, PaymentRecord, StoredMandate } from './types.js';

export class JsonStore {
  constructor(readonly dir: string) {
    mkdirSync(dir, { recursive: true });
  }

  path(name: string): string {
    return resolve(this.dir, name);
  }

  read<T>(name: string, fallback: T): T {
    const p = this.path(name);
    if (!existsSync(p)) return fallback;
    return JSON.parse(readFileSync(p, 'utf8')) as T;
  }

  write(name: string, value: unknown): void {
    writeJsonAtomic(this.path(name), value);
  }
}

export function writeJsonAtomic(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, toJson(value, 2) + '\n', 'utf8');
  renameSync(tmp, path);
}

/** the agent's state, loaded once and written through on every change */
export class AgentStore {
  readonly files: JsonStore;
  mandate: StoredMandate | null;
  escalations: Record<string, Escalation>;
  payments: PaymentRecord[];
  invoices: Invoice[];
  invoiceState: Record<string, InvoiceState>;

  constructor(dataDir: string, private readonly invoicesPath: string, invoicesExamplePath?: string) {
    this.files = new JsonStore(dataDir);
    this.mandate = this.files.read<StoredMandate | null>('mandate.json', null);
    this.escalations = idRecord<Escalation>(this.files.read<unknown>('escalations.json', {}), 'escalations.json');
    this.payments = this.files.read<PaymentRecord[]>('payments.json', []);
    if (!existsSync(invoicesPath) && invoicesExamplePath && existsSync(invoicesExamplePath)) {
      mkdirSync(dirname(invoicesPath), { recursive: true });
      copyFileSync(invoicesExamplePath, invoicesPath);
    }
    this.invoices = existsSync(invoicesPath) ? parseInvoices(readFileSync(invoicesPath, 'utf8')) : [];
    this.invoiceState = idRecord<InvoiceState>(this.files.read<unknown>('invoice-state.json', {}), 'invoice-state.json');
  }

  saveMandate(): void {
    this.files.write('mandate.json', this.mandate);
  }

  saveEscalations(): void {
    this.files.write('escalations.json', this.escalations);
  }

  savePayments(): void {
    this.files.write('payments.json', this.payments);
  }

  saveInvoiceState(): void {
    this.files.write('invoice-state.json', this.invoiceState);
  }

  /** replaces the invoice list (the file at INVOICES) */
  setInvoices(list: Invoice[]): void {
    this.invoices = parseInvoices(toJson({ invoices: list }));
    writeJsonAtomic(this.invoicesPath, { invoices: this.invoices });
  }
}

/**
 * A prototype-less copy of a JSON object keyed by ids. Ids reach these records from URLs and files, and on a plain
 * object `rec['__proto__']` or `rec['constructor']` would resolve to Object.prototype members: a write through such an
 * entry would pollute every object in the process. With a null prototype only own entries exist.
 */
export function idRecord<T>(v: unknown, what = 'record'): Record<string, T> {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new Error(`${what}: expected a JSON object`);
  const out = Object.create(null) as Record<string, T>;
  for (const [k, x] of Object.entries(v as Record<string, T>)) out[k] = x;
  return out;
}

/** own entry of an id-keyed record (never an inherited Object.prototype member) */
export function ownEntry<T>(rec: Record<string, T>, id: string): T | undefined {
  return Object.hasOwn(rec, id) ? rec[id] : undefined;
}

/** validates an invoices file ({invoices: [...]} or a bare array) */
export function parseInvoices(text: string): Invoice[] {
  const o = JSON.parse(text) as unknown;
  const list = Array.isArray(o) ? o : (o as { invoices?: unknown }).invoices;
  if (!Array.isArray(list)) throw new Error('invoices: expected {"invoices": [...]}');
  const ids = new Set<string>();
  return list.map((x, i) => {
    const v = x as Record<string, unknown>;
    const where = `invoices[${i}]`;
    if (typeof v.id !== 'string' || !/^[A-Za-z0-9_.:-]{1,32}$/.test(v.id)) throw new Error(`${where}.id: 1..32 of [A-Za-z0-9_.:-]`);
    if (ids.has(v.id)) throw new Error(`${where}.id: duplicate ${v.id}`);
    ids.add(v.id);
    if (typeof v.vendor !== 'string' || v.vendor.length > 64) throw new Error(`${where}.vendor: a string of at most 64 characters`);
    if (typeof v.payee !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(v.payee)) throw new Error(`${where}.payee: an address`);
    if (typeof v.token !== 'string') throw new Error(`${where}.token: 'mUSD' | 'native' | 'AUSD' | 0x address`);
    if (typeof v.amount !== 'string' || !/^\d{1,30}(\.\d{1,36})?$/.test(v.amount)) throw new Error(`${where}.amount: a decimal string`);
    if (v.memo !== undefined && typeof v.memo !== 'string') throw new Error(`${where}.memo: a string`);
    const rec = v.recurring as { intervalSeconds?: unknown } | undefined;
    if (rec !== undefined && (typeof rec !== 'object' || !Number.isInteger(rec.intervalSeconds) || (rec.intervalSeconds as number) < 1)) {
      throw new Error(`${where}.recurring.intervalSeconds: a positive integer`);
    }
    if (v.dueAt !== undefined && !Number.isInteger(v.dueAt)) throw new Error(`${where}.dueAt: unix seconds`);
    return {
      id: v.id,
      vendor: v.vendor,
      payee: v.payee as Invoice['payee'],
      token: v.token,
      amount: v.amount,
      ...(v.memo !== undefined ? { memo: v.memo as string } : {}),
      ...(rec !== undefined ? { recurring: { intervalSeconds: rec.intervalSeconds as number } } : {}),
      ...(v.dueAt !== undefined ? { dueAt: v.dueAt as number } : {}),
    };
  });
}
