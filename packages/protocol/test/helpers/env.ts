// Paths and process helpers of the test suite. Python runs with -B (never writes __pycache__ into firmware/tools).
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

export const REPO = resolve(__dirname, '../../../..');
export const TOOLS = resolve(REPO, 'firmware/tools');
export const MAKE_REQUEST = resolve(TOOLS, 'make_request.py');
export const ORACLE = resolve(__dirname, '../py/oracle.py');
export const VECTORS_PATH = resolve(REPO, 'contracts/test/vectors/device_vectors.json');
export const EMULATOR_PATH = resolve(REPO, 'firmware/emu/dist/ripar-emu.mjs');
export const INTERFACES = resolve(REPO, 'contracts/src/interfaces');
export const PY = process.env.RIPAR_PYTHON || 'python';

const pyEnv = (): NodeJS.ProcessEnv => ({ ...process.env, PYTHONDONTWRITEBYTECODE: '1', PYTHONIOENCODING: 'utf-8' });

/** runs test/py/oracle.py <cmd> with JSON on stdin, returns the parsed JSON it prints */
export function oracle<T = unknown>(cmd: string, input: unknown = {}): T {
  const p = spawnSync(PY, ['-B', ORACLE, cmd], {
    input: Buffer.from(JSON.stringify(input), 'utf8'),
    env: pyEnv(),
    maxBuffer: 512 << 20,
  });
  if (p.error) throw new Error(`cannot run ${PY}: ${p.error.message}`);
  if (p.status !== 0) throw new Error(`oracle ${cmd} failed (${p.status}):\n${p.stderr.toString('utf8')}`);
  return JSON.parse(p.stdout.toString('utf8')) as T;
}

/** runs firmware/tools/make_request.py with the given arguments */
export function makeRequest(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const p = spawnSync(PY, ['-B', MAKE_REQUEST, ...args], { env: pyEnv(), maxBuffer: 64 << 20 });
  if (p.error) throw new Error(`cannot run ${PY}: ${p.error.message}`);
  return { status: p.status, stdout: p.stdout.toString('utf8'), stderr: p.stderr.toString('utf8') };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function readJson<T = any>(path: string): T {
  return JSON.parse(readFileSync(path, 'utf8')) as T;
}

/** 0x-hex -> bytes (test-local, independent of the library under test) */
export function hexToBytes(h: string): Uint8Array {
  const s = h.startsWith('0x') ? h.slice(2) : h;
  return Uint8Array.from(Buffer.from(s, 'hex'));
}

export function bytesToHex(b: Uint8Array): string {
  return '0x' + Buffer.from(b).toString('hex');
}
