// Drives the WASM device emulator (firmware/emu/dist, the real firmware C++ in deterministic TEST mode) like a user:
// scan the companion's QR parts, page the review, thumb on the pulse sensor, press SIGN, read the response QR.
// The emulator is always labelled EMULATOR (its pairing carries the emulator firmware id).
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import type * as EmuModule from '../../../firmware/emu/dist/ripar-emu.js';
import { REPO } from './anvil.js';

export type Emu = EmuModule.RiparEmulator;
export type EmuState = EmuModule.EmuState;
export const EMULATOR_PATH = resolve(REPO, 'firmware/emu/dist/ripar-emu.mjs');

export async function createEmulator(seedHex: string): Promise<Emu> {
  const mod = (await import(pathToFileURL(EMULATOR_PATH).href)) as typeof EmuModule;
  return mod.RiparEmulator.create({ test: { seed: seedHex } });
}

export class Device {
  constructor(readonly emu: Emu) {}

  state(): EmuState {
    return this.emu.state();
  }

  home(): void {
    let s = this.emu.state();
    for (let i = 0; i < 4 && s.screen !== 'home'; i++) s = this.emu.key('press');
    if (s.screen !== 'home') throw new Error(`not home: ${s.screen}`);
  }

  /** HOME -> SCAN -> every part until complete; returns the screen it lands on */
  scan(parts: string[]): EmuState {
    let s = this.emu.state();
    if (s.screen !== 'scan') s = this.emu.key('press');
    if (s.screen !== 'scan') throw new Error(`expected SCAN, got ${s.screen}`);
    for (const p of parts) {
      const r = this.emu.scan(p);
      if (r.result === 'complete') break;
      if (r.result !== 'accepted' && r.result !== 'ignored') throw new Error(`scan: ${r.result} ${r.hint}`);
    }
    return this.emu.state();
  }

  /** every review line as "label: value" */
  reviewText(): string {
    const r = this.emu.state().review;
    return r ? r.lines.map((l) => `${l.label}: ${l.value}`).join('\n') : '';
  }

  pageToEnd(): EmuState {
    let s = this.emu.state();
    for (let i = 0; i < 100 && s.screen === 'review' && !s.review!.allSeen; i++) s = this.emu.key('press');
    return s;
  }

  /** last review page -> PULSE -> thumb -> ARMED -> SIGN -> the response QR text */
  pulseAndSign(): string {
    this.pageToEnd();
    let s = this.emu.key('press');
    if (s.screen !== 'pulse') throw new Error(`expected PULSE, got ${s.screen}`);
    this.emu.finger({ on: true, bpm: 72 });
    s = this.emu.tickUntil((x) => x.screen === 'armed', { maxMs: 20_000, stepMs: 20 });
    if (s.screen !== 'armed') throw new Error(`pulse gate did not arm: ${s.screen}`);
    s = this.emu.key('press');
    this.emu.finger({ on: false });
    if (s.screen !== 'qr' || !s.qr?.signed) throw new Error(`expected a signed QR, got ${s.screen}`);
    return s.qr.text;
  }

  /** on a co-sign review: hold SIGN 2 s -> the device builds the deny -> short press signs it (no pulse) */
  denyFromReview(): string {
    let s = this.emu.key('hold2');
    if (s.job !== 'deny') throw new Error(`expected the deny review, got ${s.job}`);
    this.pageToEnd();
    s = this.emu.key('press');
    if (s.screen !== 'qr') throw new Error(`expected the deny QR, got ${s.screen}`);
    return s.qr!.text;
  }
}
