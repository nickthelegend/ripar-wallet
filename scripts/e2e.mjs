#!/usr/bin/env node
// Ripar end-to-end story, headless, against a running dev stack (scripts/dev-stack.sh: an anvil fork of Monad testnet
// with the Ripar contracts deployed and the agent service running).
//
//   node scripts/e2e.mjs [--stack F:/tmp/ripar-devstack/stack.json] [--show-review]
//   scripts/dev-stack.sh e2e                      # starts a stack, runs this, stops the stack
//
// The DEVICE is the WASM emulator (firmware/emu/dist: the firmware's own C++, labelled EMULATOR), driven like a user
// (SIGN key, synthetic thumb on the pulse sensor). The COMPANION is the companion app's own code (companion/src/lib and
// companion/src/device: request planning, the QR exchange over the EmulatorTransport, response verification, chain
// writes with explicit gas limits, the agent client) on top of @ripar/protocol; its courier is anvil's unlocked dev
// account #0, exactly like the companion's "Anvil dev account" courier. The AGENT is the real agent service over HTTP.
// The story:
//   keys-only pairing -> full pairing with the derived vault -> registerDevice -> deploy + fund the vault -> mandate
//   signed by the emulator -> the agent takes it -> the first payment to a vendor on the agent's list escalates
//   (new payee) -> emulator co-sign, finger on -> HUMAN redemption -> AUTO payment to that payee within the caps ->
//   over-cap payment escalates -> the prompt-injected invoice: the device review shows AI claims MISMATCH, the user
//   denies (hold 2 s) -> the deny is relayed (attestDenial through the forked live ERC-8004 registries) -> CRE close
//   through the impersonated KeystoneForwarder -> AUTO refused (LaneClosed) while the HUMAN path still works -> device
//   REOPEN from its menu -> AUTO ok -> device PANIC -> every payment reverts StaleEpoch -> a new mandate at the new
//   epoch -> REVOKE from the device menu -> even a co-sign signed before the revoke reverts DelegationRevoked.
// Every step is asserted; a compact transcript is printed. Every transaction goes to the local anvil (the script
// refuses a non-local RPC); no private key is used or read here (anvil signs for its unlocked account, the agent signs
// for itself, the forwarder is impersonated).
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..');

// The companion code and @ripar/protocol are TypeScript: run under tsx with the 'ripar-source' export condition (the
// protocol from source, as the companion's Vite build and the agent do).
if (!process.env.RIPAR_E2E_CHILD) {
  const loader = pathToFileURL(createRequire(import.meta.url).resolve('tsx')).href;
  const r = spawnSync(process.execPath, ['--conditions=ripar-source', '--import', loader, fileURLToPath(import.meta.url), ...process.argv.slice(2)], {
    stdio: 'inherit',
    env: { ...process.env, RIPAR_E2E_CHILD: '1' },
  });
  process.exit(r.status ?? 1);
}

// ------------------------------------------------------------------------------------------------------ options
const argv = process.argv.slice(2);
if (argv.includes('--help') || argv.includes('-h')) {
  console.log(readFileSync(fileURLToPath(import.meta.url), 'utf8').split('\n').slice(1, 22).map((l) => l.replace(/^\/\/ ?/, '')).join('\n'));
  process.exit(0);
}
const opt = (name) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};
const SHOW_REVIEW = argv.includes('--show-review') || !!process.env.RIPAR_SHOW_REVIEW;
const STACK_PATH =
  opt('--stack') ?? process.env.RIPAR_STACK ?? (existsSync('F:/tmp') ? 'F:/tmp/ripar-devstack/stack.json' : resolve(process.env.TMPDIR ?? '/tmp', 'ripar-devstack/stack.json'));

// ------------------------------------------------------------------------------------------------------ modules
const src = (p) => pathToFileURL(resolve(REPO, p)).href;
const P = await import('@ripar/protocol');
const viem = await import('viem');
const Transport = await import(src('companion/src/device/transport.ts'));
const EmuT = await import(src('companion/src/device/emulator.ts'));
const Pairing = await import(src('companion/src/lib/flows/pairing.ts'));
const Vault = await import(src('companion/src/lib/flows/vault.ts'));
const Mandate = await import(src('companion/src/lib/flows/mandate.ts'));
const Cosign = await import(src('companion/src/lib/flows/cosign.ts'));
const Kill = await import(src('companion/src/lib/flows/killswitch.ts'));
const Chain = await import(src('companion/src/lib/chain.ts'));
const Clients = await import(src('companion/src/lib/clients.ts'));
const Networks = await import(src('companion/src/lib/networks.ts'));
const Agent = await import(src('companion/src/lib/agent.ts'));
const Reads = await import(src('companion/src/lib/reads.ts'));
const Preview = await import(src('companion/src/lib/review-preview.ts'));
const Activity = await import(src('companion/src/lib/activity.ts'));
const Emu = await import(src('firmware/emu/dist/ripar-emu.mjs'));

const { DELEGATION_MANAGER, PULSE_COSIGN_ENFORCER_ABI, RIPAR_REPUTATION_RELAY_ABI, RIPAR_SENTINEL_ABI, ERC8004_IDENTITY_ABI, ERC173_OWNER_ABI } = P;
const { encodeAbiParameters, encodeFunctionData, erc20Abi, createWalletClient, http } = viem;

// the demo invoices (agent/data/invoices.example.json)
const CLOUDNEST = '0xFc8Eb32DF5BD4B08E6326a3118a94f55BeCBE7e9';
const STUDIO_ARC = '0x7923d9Cd734e67671335546dAd9b43a529b61294';
const LABELWORKS = '0x6A25dF78B9c4C7022cF1A7F04a0110747Cab6e82';
const ATTACKER = '0x069ef010B46a838FeCD98ADD1E60a407Ef6E575a';
const M = (x) => BigInt(Math.round(x * 1e6)); // mUSD base units (6 decimals)

// ------------------------------------------------------------------------------------------------------ transcript
const T0 = Date.now();
let stepNo = 0;
const short = (h) => (typeof h === 'string' && h.length > 14 ? `${h.slice(0, 8)}..${h.slice(-4)}` : String(h));
const fmtM = (v) => `${Number(v) / 1e6} mUSD`;

class CheckError extends Error {}
function check(cond, msg) {
  if (!cond) throw new CheckError(typeof msg === 'function' ? msg() : msg);
}
function eq(actual, expected, what) {
  const a = typeof actual === 'string' && typeof expected === 'string' && /^0x/.test(expected) ? actual.toLowerCase() : actual;
  const e = typeof actual === 'string' && typeof expected === 'string' && /^0x/.test(expected) ? expected.toLowerCase() : expected;
  check(a === e, () => `${what}: expected ${String(expected)}, got ${String(actual)}`);
}

async function step(title, fn) {
  stepNo++;
  const t = Date.now();
  let facts;
  try {
    facts = (await fn()) ?? [];
  } catch (e) {
    console.log(`${String(stepNo).padStart(2)}  FAIL  ${title}`);
    console.log(`        ${e instanceof CheckError ? 'assertion' : e?.name ?? 'error'}: ${e?.message ?? e}`);
    throw e;
  }
  const secs = ((Date.now() - t) / 1000).toFixed(1).padStart(5);
  console.log(`${String(stepNo).padStart(2)}  ok  ${secs} s  ${title}`);
  for (const f of facts) console.log(`                  ${f}`);
}

// ------------------------------------------------------------------------------------------------------ the stack
check(existsSync(STACK_PATH), `no stack file at ${STACK_PATH}: start the stack first (scripts/dev-stack.sh up --detach)`);
const stack = JSON.parse(readFileSync(STACK_PATH, 'utf8'));
check(Networks.isLocalRpc(stack.rpcUrl), `refusing a non-local RPC ${stack.rpcUrl}: this script only drives a local anvil`);
const dep = P.parseDeployment(readFileSync(stack.deploymentsPath, 'utf8'), 10143);
const ORIGIN = String(stack.companionOrigins ?? 'http://127.0.0.1:5173').split(',')[0];

// the companion's settings for a local anvil fork with the anvil courier (Connect page)
const settings = {
  network: 'anvil-fork',
  rpcUrl: stack.rpcUrl,
  chainId: 10143,
  courier: 'anvil',
  anvilAccount: stack.courier,
  agentUrl: stack.agentUrl,
  agentToken: '',
  deploymentsUrl: stack.companionDeploymentsUrl ?? '',
  deploymentsJson: null,
  frameMs: 300,
  fragLen: 70,
  logChunk: 100,
  logLookback: 3000,
  theme: 'system',
};
const pc = Clients.publicClientFor(settings);
const courier = await Clients.connectCourier(settings);
const gasUsed = {};

async function write(w) {
  const r = await Chain.sendWrite(pc, courier, w);
  check(r.gasUsed <= w.gas, `${w.kind}: gas used ${r.gasUsed} above its explicit limit ${w.gas}`);
  (gasUsed[w.kind] ??= []).push(r.gasUsed);
  return { ...r, receipt: await pc.getTransactionReceipt({ hash: r.hash }) };
}
const anvil = (method, params = []) => pc.request({ method, params });
async function chainNow() {
  return Number((await pc.getBlock()).timestamp);
}
async function timeTravel(seconds) {
  await anvil('evm_increaseTime', [seconds]);
  await anvil('evm_mine', []);
}
const musd = (a) => pc.readContract({ address: dep.mockUsd, abi: erc20Abi, functionName: 'balanceOf', args: [a] });
const enforcer = (functionName, args) => pc.readContract({ address: dep.enforcer, abi: PULSE_COSIGN_ENFORCER_ABI, functionName, args });
const relay = (functionName, args) => pc.readContract({ address: dep.relay, abi: RIPAR_REPUTATION_RELAY_ABI, functionName, args });
const sentinel = (functionName, args) => pc.readContract({ address: dep.sentinel, abi: RIPAR_SENTINEL_ABI, functionName, args });
const events = (receipt) => receipt.logs.map((l) => Activity.decodeActivity(l, dep)).filter(Boolean);

/** eth_call of the redemption exactly as the agent would send it (from the agent's address): 'ok' or the revert */
async function simulateRedeem(mandate, exec, args = '0x') {
  let d = Mandate.delegationFromJson(mandate.delegation);
  if (args !== '0x') d = P.withCaveatArgs(d, dep.enforcer, args);
  const data = P.encodeRedeemDelegations([{ delegations: [d], target: exec.target, value: exec.value, callData: exec.callData }]);
  try {
    await pc.call({ account: stack.agentAddress, to: DELEGATION_MANAGER, data, gas: 3_000_000n });
    return 'ok';
  } catch (e) {
    return Chain.revertReason(e);
  }
}
const transferExec = (to, amount) => ({ target: dep.mockUsd, value: 0n, callData: P.toHex(P.erc20Transfer(to, amount)) });

// ------------------------------------------------------------------------------------------------------ the agent
const agent = new Agent.AgentClient(stack.agentUrl, (url, init = {}) => fetch(url, { ...init, headers: { ...(init.headers ?? {}), origin: ORIGIN } }));
async function api(path, body) {
  const res = await fetch(stack.agentUrl + path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { origin: ORIGIN, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const json = await res.json();
  check(res.ok, () => `agent ${path}: HTTP ${res.status} ${JSON.stringify(json)}`);
  return json;
}
/** one planner step (POST /run) and the pay_invoice result it produced */
async function runStep() {
  const r = await api('/run', {});
  const pay = r.actions.find((a) => a.tool === 'pay_invoice');
  return { summary: r.summary, result: pay?.result ?? null, raw: r };
}
const agentEscalation = (id) => api(`/escalations/${id}`);

// ------------------------------------------------------------------------------------------------------ the device
class ManualScheduler {
  timers = new Map();
  id = 0;
  now = 0;
  setInterval(fn, ms) {
    const h = ++this.id;
    this.timers.set(h, { fn, ms, next: this.now + ms });
    return h;
  }
  clearInterval(h) {
    this.timers.delete(h);
  }
  advance(ms) {
    const end = this.now + ms;
    for (;;) {
      let due = null;
      for (const t of this.timers.values()) if (t.next <= end && (!due || t.next < due.next)) due = t;
      if (!due) break;
      this.now = due.next;
      due.next += due.ms;
      due.fn();
    }
    this.now = end;
  }
}

/** the emulated device behind the companion's EmulatorTransport; the frame loop and the emulated time move together */
class Device {
  constructor(emu) {
    this.emu = emu;
    this.transport = new EmuT.EmulatorTransport(emu);
    this.sched = new ManualScheduler();
  }
  get state() {
    return this.emu.state();
  }
  run(pred, maxMs = 20_000) {
    let s = this.transport.pump();
    for (let t = 0; t < maxMs && !pred(s); t += 20) {
      this.sched.advance(20);
      s = this.transport.tick(20);
    }
    return s;
  }
  key(kind = 'press') {
    this.emu.key(kind);
    return this.transport.pump();
  }
  home() {
    let s = this.transport.pump();
    for (let i = 0; i < 4 && s.screen !== 'home'; i++) s = this.key('press');
    eq(s.screen, 'home', 'device screen');
  }
  /** HOME -> SCAN, then the exchange's frames reach the camera until the review (or a message) opens */
  scanRequest() {
    let s = this.transport.pump();
    if (s.screen !== 'scan') s = this.key('press');
    eq(s.screen, 'scan', 'device screen');
    s = this.run((x) => x.screen !== 'scan', 60_000);
    if (s.screen === 'message') throw new CheckError(`the device refused: ${s.message?.title}: ${s.message?.body}`);
    eq(s.screen, 'review', 'device screen after the scan');
    return s;
  }
  pageToEnd() {
    let s = this.transport.pump();
    for (let i = 0; i < 100 && s.screen === 'review' && !s.review.allSeen; i++) s = this.key('press');
    return s;
  }
  /** last review page -> PULSE -> thumb on the sensor -> ARMED -> SIGN -> QR */
  pulseAndSign(bpm = 72) {
    this.pageToEnd();
    let s = this.key('press');
    eq(s.screen, 'pulse', 'device screen');
    this.emu.finger({ on: true, bpm });
    s = this.run((x) => x.screen === 'armed', 20_000);
    eq(s.screen, 'armed', 'the pulse gate');
    s = this.key('press');
    this.emu.finger({ on: false });
    eq(s.screen, 'qr', 'device screen after SIGN');
    check(s.qr?.signed, 'the device QR is not signed');
    return this.transport.pump();
  }
  /** HOME: hold 2 s and release -> the keys-only pairing QR */
  holdRelease() {
    this.emu.keyDown();
    this.run((s) => s.screen === 'homeHold', 3000);
    this.emu.keyUp();
    const s = this.run((x) => x.screen === 'pairQr', 1500);
    eq(s.screen, 'pairQr', 'device screen');
  }
  /** from the pairing QR: hold 2 s -> the device menu, move to the item, hold 2 s to open it */
  menu(item) {
    let s = this.key('hold2');
    eq(s.screen, 'menu', 'device screen');
    for (let i = 0; i < 8 && !item.test(s.menu.items[s.menu.index]); i++) s = this.key('press');
    check(item.test(s.menu.items[s.menu.index]), `no ${item} in the device menu (${s.menu.items.join(', ')})`);
    return this.key('hold2');
  }
  reviewLines() {
    return this.state.review.lines.map((l) => ({ label: l.label, value: l.value, tone: l.tone }));
  }
  reviewLine(label) {
    return this.state.review.lines.find((l) => l.label === label)?.value ?? null;
  }
  reviewText() {
    return this.state.review.lines.map((l) => `${l.label}: ${l.value}`).join('\n');
  }
  /** one companion <-> device round over the DeviceExchange (the same code path the companion UI runs) */
  async exchange(parts, expect, accept, drive) {
    const ex = new Transport.DeviceExchange(this.transport, { parts, expect, frameMs: 300, ...(accept ? { accept } : {}) }, this.sched);
    const ignored = [];
    ex.on((e) => e.kind === 'ignored' && ignored.push(e.reason));
    let value;
    let error;
    ex.start().then(
      (v) => (value = v),
      (e) => (error = e),
    );
    drive();
    await new Promise((r) => setTimeout(r, 0));
    if (value === undefined) {
      ex.cancel();
      throw new CheckError(`the device gave no ${expect.join('/')} answer${error ? ` (${error.message})` : ''}${ignored.length ? `; ignored: ${ignored.join('; ')}` : ''}`);
    }
    return value;
  }
}

function sameLines(preview, device, what) {
  const a = JSON.stringify(preview);
  const b = JSON.stringify(device);
  if (a === b) return;
  const diff = [];
  for (let i = 0; i < Math.max(preview.length, device.length); i++) {
    if (JSON.stringify(preview[i]) !== JSON.stringify(device[i])) diff.push(`#${i} companion ${JSON.stringify(preview[i])} / device ${JSON.stringify(device[i])}`);
  }
  throw new CheckError(`${what}: the companion's predicted review differs from the device's:\n        ${diff.slice(0, 6).join('\n        ')}`);
}

// ------------------------------------------------------------------------------------------------------ inbox
const handedOut = new Set(); // co-sign nonces relayed to the device (the companion never relays one twice)
async function inbox(escId, mandate, device) {
  const { items, rejected } = await agent.escalations();
  check(rejected.length === 0, () => `the companion rejected agent escalations: ${rejected.map((r) => r.error).join('; ')}`);
  const e = items.find((x) => x.id === escId);
  check(e, `escalation ${escId} is not listed by the agent`);
  const chk = Cosign.checkEscalation(e, device.record, mandate);
  check(chk.errors.length === 0, () => `the companion refuses escalation ${escId}: ${chk.errors.join('; ')}`);
  const plan = Cosign.adoptAgentRequest(e, device.record, { now: await chainNow(), fragLen: settings.fragLen });
  const key = `${e.delegationHash.toLowerCase()}:${plan.nonce}`;
  check(!handedOut.has(key), `the agent reuses nonce ${plan.nonce}`);
  check(!(await Reads.nonceUsed(pc, device.record.pinned.enforcer, e.delegationHash, plan.nonce)), `nonce ${plan.nonce} is already used on chain`);
  handedOut.add(key);
  const preview = Preview.previewCosign(plan.decoded, {
    p1Key: device.record.p1Key,
    vault: device.record.pinned.vault,
    sentinel: device.record.pinned.sentinel,
    minEpoch: 0n,
    lastDelegationHash: mandate?.delegationHash ?? null,
  });
  return { e, plan, preview, warnings: chk.warnings };
}

/** shows the co-sign request to the device; 'sign' = review, pulse + SIGN; 'deny' = hold SIGN 2 s on the review */
async function deviceAnswers(device, plan, preview, action, onReview = () => {}) {
  return device.exchange(plan.request.parts, ['ripar-cosign', 'ripar-deny'], (u) => Cosign.answersCosign(u, plan.request), () => {
    const s = device.scanRequest();
    check(s.review.ok, () => `the device refused the co-sign: ${s.review.refusal}`);
    eq(s.review.title, 'CO-SIGN PAYMENT', 'review title');
    sameLines(preview.lines, device.reviewLines(), 'co-sign review');
    onReview();
    if (SHOW_REVIEW) console.log(`        --- device review\n        ${device.reviewText().split('\n').join('\n        ')}`);
    if (action === 'sign') {
      device.pulseAndSign();
    } else {
      let r = device.key('hold2');
      eq(r.screen, 'review', 'device screen after the 2 s hold');
      eq(r.review.job, 'deny', 'device job after the 2 s hold');
      device.pageToEnd();
      r = device.key('press'); // a deny is signed without the pulse: it can only restrict
      eq(r.screen, 'qr', 'device screen after signing the deny');
    }
  });
}

// ====================================================================================================== the story
const IDS = {};
let device;
let keys;
let vault;
let m1;
let m2;
let agentId;
let exitCode = 0;

console.log(`Ripar e2e: ${stack.rpcUrl} (anvil fork of Monad testnet ${stack.chainId}, forked at block ${stack.forkedAtBlock}), agent ${stack.agentUrl}`);
try {
  await step('the stack: anvil fork, the Ripar contracts, the agent (fresh)', async () => {
    const client = await anvil('web3_clientVersion');
    check(/anvil/i.test(String(client)), `not an anvil node: ${client}`);
    eq(await pc.getChainId(), 10143, 'chain id');
    const codes = await Reads.checkContracts(pc, dep);
    for (const c of codes) check(c.bytes > 0, `${c.name} ${c.address} has no code on the fork`);
    const h = await agent.health();
    const planner = (await api('/health')).planner;
    eq(h.agent?.address, stack.agentAddress, 'agent address');
    eq(h.chainId, 10143, 'agent chain id');
    check(h.mandate === null, 'the agent already holds a mandate: restart the stack (scripts/dev-stack.sh down; up) for a fresh run');
    const st = await api('/state');
    check(st.escalations.length === 0 && st.invoices.every((i) => i.status === 'open' && i.paidCount === 0), 'the agent is not fresh: restart the stack');
    check(h.agent.agentId !== null, 'the agent has no ERC-8004 agentId (see the dev-stack register-erc8004 log)');
    agentId = h.agent.agentId;
    const owner = await pc.readContract({ address: dep.erc8004Identity, abi: ERC8004_IDENTITY_ABI, functionName: 'ownerOf', args: [agentId] });
    eq(owner, stack.agentAddress, 'ERC-8004 owner of the agentId');
    if (stack.companionUrl) {
      const served = await (await fetch(new URL(stack.companionDeploymentsUrl, stack.companionUrl))).json();
      eq(served.PulseCosignEnforcer, dep.enforcer, "the companion dev server's deployments JSON");
    }
    return [
      `contracts: registry ${short(dep.registry)} enforcer ${short(dep.enforcer)} sentinel ${short(dep.sentinel)} relay ${short(dep.relay)} mUSD ${short(dep.mockUsd)}`,
      `agent ${stack.agentAddress} = ERC-8004 agentId ${agentId} (forked IdentityRegistry ${short(dep.erc8004Identity)}), ${planner} planner`,
    ];
  });

  await step('keys-only pairing (device HOME: hold 2 s, release)', async () => {
    const seed = P.toHex(P.randomBytes(32)).slice(2);
    device = new Device(await Emu.RiparEmulator.create({ test: { seed } }));
    check(device.state.emulator === true, 'not labelled EMULATOR');
    const ur = await device.exchange([], ['ripar-pair'], Pairing.isKeysOnlyPair, () => device.holdRelease());
    device.home();
    keys = Pairing.readKeysOnly(ur);
    eq(keys.k1Address, P.toChecksumAddress(device.state.k1), 'K1');
    check(keys.emulator && keys.firmwareId === P.EMULATOR_FIRMWARE_ID, 'the pairing QR does not carry the EMULATOR firmware id');
    return [`K1 ${keys.k1Address}  keyId ${short(keys.keyId)}  ${EmuT.EMULATOR_LABEL} (firmware id ${keys.firmwareId.slice(2)})`];
  });

  await step('the canonical vault derived from K1 (@ripar/protocol = smart-accounts-kit)', async () => {
    const v = await Vault.deriveVault(keys.k1Address, 10143);
    check(v.matches, `protocol ${v.address} vs kit ${v.kitAddress}: the derivations disagree`);
    eq(v.address, P.computeVaultAddress(keys.k1Address), 'vault');
    vault = v;
    check(!(await pc.getCode({ address: v.address })), 'the vault is already deployed');
    return [`vault ${v.address} (Hybrid, [K1, [], [], []], salt 0, SimpleFactory ${short(v.factory)})`];
  });

  await step('full pairing with the derived vault (multipart QR, review, pulse + SIGN)', async () => {
    const [minEpoch, reopenNonce] = await Promise.all([Reads.readMinEpoch(pc, dep.enforcer, keys.keyId), sentinel('lastReopenNonce', [vault.address])]);
    const plan = Pairing.planPairing(dep, keys.k1Address, { now: await chainNow(), minEpoch, reopenNonce, fragLen: settings.fragLen });
    eq(plan.vault, vault.address, 'pinned vault');
    check(plan.request.parts.length > 1, 'expected a multipart pairing request');
    const ur = await device.exchange(plan.request.parts, ['ripar-pair'], (u) => Pairing.answersRequest(u, plan.request), () => {
      const s = device.scanRequest();
      check(s.review.ok, () => `the device refused the pairing: ${s.review.refusal}`);
      check(device.reviewText().includes(vault.address), 'the pairing review does not show the vault');
      device.pulseAndSign();
    });
    device.home();
    device.record = Pairing.acceptPairing(ur, plan, keys);
    const ctx = device.state.context;
    check(ctx.paired, 'the device is not paired');
    eq(ctx.vault, vault.address, 'device pinned vault');
    eq(ctx.pulseCosignEnforcer, dep.enforcer, 'device pinned enforcer');
    eq(ctx.sentinel, dep.sentinel, 'device pinned sentinel');
    eq(ctx.relay, dep.relay, 'device pinned relay');
    return [`${plan.request.parts.length} QR parts; BindDevice signed by P1 and K1, VERIFIED; pinned chain 10143, enforcer, sentinel, relay, registry, vault`];
  });

  await step('registerDevice (courier = anvil dev account #0, gas limit explicit)', async () => {
    const r = await write(Chain.registerDeviceWrite(dep.registry, device.record));
    const st = await Reads.readDeviceStatus(pc, dep, device.record.keyId);
    eq(st.registeredOwner, keys.k1Address, 'registry owner of the key');
    return [`tx ${short(r.hash)}  gas ${r.gasUsed} / ${Chain.GAS_LIMITS.registerDevice}`];
  });

  await step('deploy the vault (SimpleFactory) and fund it (MockUSD faucet)', async () => {
    const d = await write(Chain.deployVaultWrite(vault.factory, vault.factoryData, vault.address));
    eq(await pc.readContract({ address: vault.address, abi: ERC173_OWNER_ABI, functionName: 'owner' }), keys.k1Address, 'vault owner()');
    const f = await write(Chain.faucetWrite(dep.mockUsd, vault.address, M(1000)));
    eq(await musd(vault.address), M(1000), 'vault mUSD');
    return [`vault deployed (gas ${d.gasUsed}), owner() = K1; 1000 mUSD minted to it (gas ${f.gasUsed})`];
  });

  const form = (epochLabel) => ({
    agent: stack.agentAddress,
    agentId: String(agentId),
    label: `Ripar treasury agent (${epochLabel})`,
    token: dep.mockUsd,
    tokenDecimals: 6,
    tokenSymbol: 'mUSD',
    perTxAutoCap: '5',
    periodAutoCap: '20',
    period: 86400,
    newPayeeNeedsHuman: true,
    redeemerOnly: true,
    validUntil: null,
  });
  async function signMandate(f, epoch) {
    const plan = Mandate.planMandate(f, device.record, epoch, { fragLen: settings.fragLen });
    const preview = Preview.previewMandate(plan.decoded, { p1Key: device.record.p1Key, vault: vault.address, sentinel: dep.sentinel, minEpoch: epoch });
    const ur = await device.exchange(plan.request.parts, ['eth-signature'], (u) => Mandate.answersMandate(u, plan.request), () => {
      const s = device.scanRequest();
      check(s.review.ok, () => `the device refused the mandate: ${s.review.refusal}`);
      eq(s.review.title, preview.title, 'mandate review title');
      sameLines(preview.lines, device.reviewLines(), 'mandate review');
      device.pulseAndSign();
    });
    device.home();
    const rec = Mandate.acceptMandate(ur, plan, f, device.record);
    eq(device.state.context.lastDelegationHash, rec.delegationHash, "the device's last mandate");
    return { rec, lines: preview.lines.length };
  }

  await step('mandate signed by the emulator (K1): 5 mUSD per tx, 20 mUSD a day, new payees need the human', async () => {
    const epoch = await Reads.readMinEpoch(pc, dep.enforcer, device.record.keyId);
    eq(epoch, 0n, 'minEpoch');
    const { rec, lines } = await signMandate(form('epoch 0'), epoch);
    m1 = rec;
    return [`delegationHash ${short(m1.delegationHash)} epoch 0, sentinel pinned, RedeemerEnforcer = the agent; companion preview = device review (${lines} lines)`];
  });

  await step('the agent takes the mandate (POST /mandate: the device request + its eth-signature)', async () => {
    await agent.postMandate(Mandate.mandateEnvelope(m1));
    const h = await agent.health();
    eq(h.mandate?.delegationHash, m1.delegationHash, 'agent mandate');
    eq(h.mandate?.status, 'active', 'agent mandate status');
    const st = await api('/state');
    eq(st.mandate.vault, vault.address, 'agent mandate vault');
    eq(st.mandate.agentId, String(agentId), 'agent mandate agentId');
    eq(st.laneOpen, true, 'lane open');
    return [`agent recovered K1 ${short(st.mandate.owner)} from the signature; vault owner() matches; budget ${st.budget.remainingFormatted} mUSD left`];
  });

  await step('INV-001 CloudNest 2.5 mUSD (on the agent list): the first AUTO attempt escalates (new payee)', async () => {
    const r = await runStep();
    eq(r.result?.outcome, 'sent_to_human', `planner step (${r.summary})`);
    eq(r.result.invoice_id, 'INV-001', 'invoice');
    IDS.inv1 = r.result.escalation_id;
    const e = await agentEscalation(IDS.inv1);
    eq(e.reason, 'new-payee', 'escalation reason');
    eq(await simulateRedeem(m1, transferExec(CLOUDNEST, M(2.5))), 'HumanRequired()', 'the enforcer on the AUTO path');
    return [`escalation ${IDS.inv1} (${e.reason}); the enforcer agrees: AUTO reverts HumanRequired()`];
  });

  let bpm;
  await step('the device co-signs INV-001 (review, finger on the sensor, SIGN) -> HUMAN redemption by the agent', async () => {
    const { e, plan, preview } = await inbox(IDS.inv1, m1, device);
    const ur = await deviceAnswers(device, plan, preview, 'sign', () => {
      eq(device.reviewLine('To'), CLOUDNEST, 'device To');
      check(/^MATCH/.test(device.reviewLine('AI claims') ?? ''), `AI claims: ${device.reviewLine('AI claims')}`);
    });
    device.home();
    const out = Cosign.acceptCosignAnswer(ur, plan, device.record, m1);
    eq(out.kind, 'cosign', 'device answer');
    bpm = out.bpm;
    const before = await musd(CLOUDNEST);
    const { txHash } = await agent.postCosign(e.id, out.answer);
    eq((await musd(CLOUDNEST)) - before, M(2.5), 'CloudNest received');
    const x = await agentEscalation(e.id);
    eq(x.status, 'executed', 'escalation status');
    check(await enforcer('isKnownPayee', [DELEGATION_MANAGER, m1.delegationHash, CLOUDNEST]), 'CloudNest is not a known payee');
    check(await enforcer('consumed', [DELEGATION_MANAGER, x.result.approvalDigest]), 'approval not consumed');
    check(!x.result.attest?.error && x.result.attest?.txHash, () => `attestApproval: ${x.result.attest?.error}`);
    check(await relay('approvalAttested', [x.result.approvalDigest]), 'approval not attested');
    return [
      `device: To ${short(CLOUDNEST)}, AI claims MATCH; pulse ${bpm} bpm; nonce ${plan.nonce}`,
      `HUMAN redemption ${short(txHash)} (gas ${x.result.gasUsed} / limit ${x.result.gasLimit}); CloudNest is now a known payee; attestApproval (ERC-8004 +1) ${short(x.result.attest.txHash)}`,
    ];
  });

  await step('+61 s: the next INV-001 goes AUTO inside the caps', async () => {
    await timeTravel(61);
    const before = await musd(CLOUDNEST);
    const r = await runStep();
    check(r.result?.outcome === 'paid' && r.result.path === 'auto', `planner step: ${r.summary}`);
    eq((await musd(CLOUDNEST)) - before, M(2.5), 'CloudNest received');
    const ms = await Reads.readMandateStatus(pc, dep.enforcer, device.record.keyId, m1.delegationHash, m1.pulseTerms);
    eq(ms.budget.spent, M(2.5), 'autoBudget spent');
    eq(ms.budget.remaining, M(17.5), 'autoBudget remaining');
    return [`AUTO ${short(r.result.tx)}; autoBudget: spent 2.5, remaining 17.5 mUSD`];
  });

  await step('INV-002 Studio Arc 45 mUSD: over the 5 mUSD per-tx cap -> escalates', async () => {
    const r = await runStep();
    eq(r.result?.outcome, 'sent_to_human', `planner step (${r.summary})`);
    eq(r.result.invoice_id, 'INV-002', 'invoice');
    IDS.inv2 = r.result.escalation_id;
    eq((await agentEscalation(IDS.inv2)).reason, 'per-tx-cap', 'escalation reason');
    eq(await simulateRedeem(m1, transferExec(STUDIO_ARC, M(45))), 'HumanRequired()', 'the enforcer on the AUTO path');
    return [`escalation ${IDS.inv2} (per-tx-cap), left pending; AUTO would revert HumanRequired()`];
  });

  await step('INV-003 LabelWorks 3 mUSD: a vendor never co-signed -> escalates (new payee), left pending', async () => {
    const r = await runStep();
    eq(r.result?.outcome, 'sent_to_human', `planner step (${r.summary})`);
    eq(r.result.invoice_id, 'INV-003', 'invoice');
    IDS.inv3 = r.result.escalation_id;
    eq((await agentEscalation(IDS.inv3)).reason, 'new-payee', 'escalation reason');
    return [`escalation ${IDS.inv3} (new-payee)`];
  });

  let deny;
  await step('INV-004 prompt injection: the device review shows AI claims MISMATCH; the user denies (hold SIGN 2 s)', async () => {
    const r = await runStep();
    eq(r.result?.outcome, 'sent_to_human', `planner step (${r.summary})`);
    eq(r.result.invoice_id, 'INV-004', 'invoice');
    IDS.inv4 = r.result.escalation_id;
    const raw = await agentEscalation(IDS.inv4);
    eq(raw.reason, 'payee-redirect', 'escalation reason');
    eq(raw.display.payee, ATTACKER, 'the redirected destination');
    eq(raw.cosign.ai.claims.to, CLOUDNEST, "the agent's claim (the invoice of record)");
    const { e, plan, preview } = await inbox(IDS.inv4, m1, device);
    const predicted = preview.lines.find((l) => l.label === 'AI claims');
    check(predicted && /^MISMATCH/.test(predicted.value) && predicted.tone === 'bad', 'the companion does not predict the MISMATCH');
    let seen;
    const ur = await deviceAnswers(device, plan, preview, 'deny', () => {
      eq(device.reviewLine('To'), ATTACKER, 'device To');
      const claim = device.state.review.lines.find((l) => l.label === 'AI claims');
      check(claim && /^MISMATCH/.test(claim.value) && claim.tone === 'bad', `device AI claims: ${claim?.value}`);
      seen = ['To', 'AI says', 'AI claims', 'Risk'].map((l) => `${l}: ${device.reviewLine(l)}`);
    });
    device.home();
    const out = Cosign.acceptCosignAnswer(ur, plan, device.record, m1);
    eq(out.kind, 'deny', 'device answer');
    eq(out.attest.requestHash, plan.denyRequestHash, 'deny requestHash');
    eq(out.attest.agentId, BigInt(agentId), 'deny agentId (the mandate agent the device pinned)');
    deny = { e, out };
    return seen.map((l) => `device: ${l.length > 110 ? `${l.slice(0, 107)}...` : l}`);
  });

  await step('the deny is relayed: attestDenial through the forked live ERC-8004 registries, then POST /deny', async () => {
    const r = await write(Chain.attestDenialWrite(dep.relay, { ...deny.out.attest, px: device.record.px, py: device.record.py }));
    const verdict = events(r.receipt).find((x) => x.kind === 'Verdict');
    check(verdict && verdict.args.approved === false && verdict.args.agentId === BigInt(agentId), 'no Verdict(approved = false) for the agent');
    const feedback = r.receipt.logs.filter((l) => l.address.toLowerCase() === dep.erc8004Reputation.toLowerCase());
    check(feedback.length > 0, 'the ERC-8004 ReputationRegistry emitted nothing (giveFeedback)');
    check(await relay('denialAttested', [device.record.keyId, deny.out.attest.requestHash]), 'denial not attested');
    await agent.postDeny(deny.e.id, { ...deny.out.answer, attestTx: r.hash });
    const x = await agentEscalation(deny.e.id);
    eq(x.status, 'denied', 'escalation status');
    eq(x.deny?.verified, true, "the agent's check of the device deny");
    eq(await musd(ATTACKER), 0n, 'attacker balance');
    return [`attestDenial ${short(r.hash)} (gas ${r.gasUsed} / ${Chain.GAS_LIMITS.attestDenial}): Verdict(agent ${agentId}, denied), ${feedback.length} ReputationRegistry log(s); the agent marks INV-004 denied; the attacker got 0`];
  });

  await step('CRE close: the fork\'s KeystoneForwarder (impersonated) delivers a close report to the sentinel', async () => {
    const fwd = dep.creForwarder;
    check((await pc.getCode({ address: fwd }))?.length > 2, `no forwarder contract at ${fwd} on the fork`);
    const block = await pc.getBlockNumber({ cacheTime: 0 });
    const metadata = `0x${'5a'.repeat(32)}${Buffer.from('ripar-risk').toString('hex')}${stack.workflowOwner.slice(2).toLowerCase()}`;
    const report = encodeAbiParameters([{ type: 'address' }, { type: 'bool' }, { type: 'uint8' }, { type: 'uint64' }], [vault.address, false, 1, block]);
    const data = encodeFunctionData({ abi: RIPAR_SENTINEL_ABI, functionName: 'onReport', args: [metadata, report] });
    // anyone but the forwarder is refused
    const notFwd = await pc.call({ account: stack.courier, to: dep.sentinel, data }).then(() => 'ok', (e) => Chain.revertReason(e));
    eq(notFwd, 'NotForwarder()', 'onReport from the courier');
    await anvil('anvil_impersonateAccount', [fwd]);
    await anvil('anvil_setBalance', [fwd, '0x56BC75E2D63100000']);
    try {
      const fw = createWalletClient({ account: fwd, chain: courier.chain, transport: http(stack.rpcUrl) });
      const hash = await fw.sendTransaction({ to: dep.sentinel, data, gas: 300_000n });
      const rc = await pc.waitForTransactionReceipt({ hash });
      eq(rc.status, 'success', 'onReport');
      const lc = events(rc).find((x) => x.kind === 'LaneChanged');
      check(lc && lc.args.open === false && lc.args.vault === vault.address, 'no LaneChanged(open = false)');
    } finally {
      await anvil('anvil_stopImpersonatingAccount', [fwd]);
    }
    eq(await sentinel('laneOpen', [vault.address]), false, 'laneOpen');
    return [`forwarder ${short(fwd)} -> onReport(metadata owner = anvil #9 ${short(stack.workflowOwner)}, report(vault, open=false, reason 1, block ${block})): LaneChanged(closed)`];
  });

  await step('+61 s: AUTO is refused while the lane is closed (LaneClosed); nothing is sent', async () => {
    await timeTravel(61);
    const payments = (await api('/state')).payments.length;
    const r = await runStep();
    eq(r.result?.outcome, 'sent_to_human', `planner step (${r.summary})`);
    eq(r.result.invoice_id, 'INV-001', 'invoice');
    IDS.inv1b = r.result.escalation_id;
    eq((await agentEscalation(IDS.inv1b)).reason, 'lane-closed', 'escalation reason');
    eq((await api('/state')).payments.length, payments, 'payments');
    eq(await simulateRedeem(m1, transferExec(CLOUDNEST, M(2.5))), 'LaneClosed()', 'the enforcer on the AUTO path');
    return [`the agent escalates INV-001 (lane-closed) instead of sending; the enforcer: AUTO reverts LaneClosed()`];
  });

  await step('the HUMAN path still pays on a closed lane: the device co-signs INV-001', async () => {
    const { e, plan, preview } = await inbox(IDS.inv1b, m1, device);
    const ur = await deviceAnswers(device, plan, preview, 'sign');
    device.home();
    const out = Cosign.acceptCosignAnswer(ur, plan, device.record, m1);
    eq(out.kind, 'cosign', 'device answer');
    const before = await musd(CLOUDNEST);
    const { txHash } = await agent.postCosign(e.id, out.answer);
    eq((await musd(CLOUDNEST)) - before, M(2.5), 'CloudNest received');
    eq(await sentinel('laneOpen', [vault.address]), false, 'laneOpen');
    return [`HUMAN redemption ${short(txHash)} with the lane still closed`];
  });

  await step('REOPEN from the device menu (hold 2 s, release; hold 2 s; REOPEN), relayed to the sentinel', async () => {
    const ur = await device.exchange([], [...Kill.KILL_TYPES], undefined, () => {
      device.holdRelease();
      const s = device.menu(/REOPEN/);
      check(/REOPEN/.test(s.review?.title ?? ''), `review ${s.review?.title}`);
      device.pulseAndSign();
    });
    device.home();
    const k = Kill.acceptKillSwitch(ur, device.record);
    eq(k.type, 'ripar-reopen', 'kill-switch type');
    const r = await write(k.write);
    const lc = events(r.receipt).find((x) => x.kind === 'LaneChanged');
    check(lc && lc.args.open === true, 'no LaneChanged(open = true)');
    eq(await sentinel('laneOpen', [vault.address]), true, 'laneOpen');
    eq(await sentinel('lastReopenNonce', [vault.address]), 1n, 'lastReopenNonce');
    return [`ripar-reopen nonce 1 VERIFIED; sentinel.reopen ${short(r.hash)} (gas ${r.gasUsed} / ${Chain.GAS_LIMITS.reopen}): lane open`];
  });

  await step('+61 s: AUTO works again', async () => {
    await timeTravel(61);
    const before = await musd(CLOUDNEST);
    const r = await runStep();
    check(r.result?.outcome === 'paid' && r.result.path === 'auto', `planner step: ${r.summary}`);
    eq((await musd(CLOUDNEST)) - before, M(2.5), 'CloudNest received');
    const ms = await Reads.readMandateStatus(pc, dep.enforcer, device.record.keyId, m1.delegationHash, m1.pulseTerms);
    eq(ms.budget.spent, M(5), 'autoBudget spent');
    return [`AUTO ${short(r.result.tx)}; autoBudget spent 5 of 20 mUSD (HUMAN payments do not count)`];
  });

  await step('PANIC on the device (HOME: hold SIGN 5 s), relayed to the enforcer', async () => {
    const ur = await device.exchange([], [...Kill.KILL_TYPES], undefined, () => {
      device.emu.keyDown();
      device.run((s) => s.screen === 'qr', 6000);
      device.emu.keyUp();
      device.run(() => false, 200);
    });
    device.home();
    const k = Kill.acceptKillSwitch(ur, device.record);
    eq(k.type, 'ripar-panic', 'kill-switch type');
    eq(k.report.fields.minEpoch, 1n, 'panic epoch');
    const r = await write(k.write);
    check(events(r.receipt).some((x) => x.kind === 'Panicked'), 'no Panicked event');
    eq(await Reads.readMinEpoch(pc, dep.enforcer, device.record.keyId), 1n, 'minEpoch');
    eq(device.state.context.minEpoch, '1', "the device's panic floor");
    return [`Panic(minEpoch 1) signed without the pulse, VERIFIED; enforcer.panic ${short(r.hash)} (gas ${r.gasUsed} / ${Chain.GAS_LIMITS.panic})`];
  });

  await step('after the PANIC every payment reverts StaleEpoch (AUTO by the agent, and a fresh device co-sign)', async () => {
    await timeTravel(61);
    const before = await musd(CLOUDNEST);
    const r = await runStep();
    eq(r.result?.outcome, 'failed', `planner step (${r.summary})`);
    check(/^StaleEpoch/.test(r.result.error), `agent AUTO: ${r.result.error}`);
    eq((await agent.health()).mandate?.status, 'dead', "the agent's mandate status");
    // the device still co-signs the pending over-cap INV-002 (a human can always sign); the chain refuses it anyway
    const { e, plan, preview } = await inbox(IDS.inv2, m1, device);
    const ur = await deviceAnswers(device, plan, preview, 'sign');
    device.home();
    const out = Cosign.acceptCosignAnswer(ur, plan, device.record, m1);
    eq(out.kind, 'cosign', 'device answer');
    const refused = await agent.postCosign(e.id, out.answer).then(() => null, (x) => x);
    check(refused && /mandate_dead/.test(refused.message), `the agent took a co-sign for a dead mandate: ${refused?.message ?? 'ok'}`);
    const matrix = {
      'AUTO CloudNest 2.5 (known payee)': await simulateRedeem(m1, transferExec(CLOUDNEST, M(2.5))),
      'AUTO LabelWorks 1 (new payee)': await simulateRedeem(m1, transferExec(LABELWORKS, M(1))),
      'HUMAN Studio Arc 45 (device co-sign)': await simulateRedeem(m1, transferExec(STUDIO_ARC, M(45)), out.answer.caveatArgs),
    };
    for (const [k, v] of Object.entries(matrix)) eq(v, 'StaleEpoch()', k);
    eq((await musd(CLOUDNEST)) - before, 0n, 'CloudNest received');
    return [
      `agent: AUTO INV-001 -> ${r.result.error.split(':')[0]} at estimation (nothing sent), mandate marked dead; POST co-sign -> 409 mandate_dead`,
      ...Object.entries(matrix).map(([k, v]) => `eth_call ${k}: ${v}`),
    ];
  });

  let preRevoke;
  await step('a new mandate at the new epoch (1), taken by the agent; its payees start empty', async () => {
    const epoch = await Reads.readMinEpoch(pc, dep.enforcer, device.record.keyId);
    eq(epoch, 1n, 'minEpoch');
    const { rec } = await signMandate(form('epoch 1'), epoch);
    m2 = rec;
    await agent.postMandate(Mandate.mandateEnvelope(m2));
    const h = await agent.health();
    eq(h.mandate?.delegationHash, m2.delegationHash, 'agent mandate');
    eq(h.mandate?.status, 'active', 'agent mandate status');
    const r = await runStep();
    eq(r.result?.outcome, 'sent_to_human', `planner step (${r.summary})`);
    eq(r.result.invoice_id, 'INV-001', 'invoice');
    IDS.inv1c = r.result.escalation_id;
    eq((await agentEscalation(IDS.inv1c)).reason, 'new-payee', 'escalation reason (known payees are per mandate)');
    // the user co-signs it on the device, but the courier holds the answer back until after the revoke
    const { plan, preview } = await inbox(IDS.inv1c, m2, device);
    const ur = await deviceAnswers(device, plan, preview, 'sign');
    device.home();
    preRevoke = Cosign.acceptCosignAnswer(ur, plan, device.record, m2);
    eq(preRevoke.kind, 'cosign', 'device answer');
    return [`mandate ${short(m2.delegationHash)} epoch 1 (= the device's panic floor); INV-001 escalates new-payee again; co-signed, held back`];
  });

  await step('REVOKE the new mandate from the device menu; even the co-sign signed before it now reverts', async () => {
    const ur = await device.exchange([], [...Kill.KILL_TYPES], undefined, () => {
      device.holdRelease();
      const s = device.menu(/REVOKE/);
      check(/REVOKE/.test(s.review?.title ?? ''), `review ${s.review?.title}`);
      device.pulseAndSign();
    });
    device.home();
    const k = Kill.acceptKillSwitch(ur, device.record);
    eq(k.type, 'ripar-revoke', 'kill-switch type');
    eq(k.report.fields.delegationHash, m2.delegationHash, 'revoked mandate');
    const r = await write(k.write);
    check(events(r.receipt).some((x) => x.kind === 'Revoked'), 'no Revoked event');
    check(await enforcer('isRevoked', [device.record.keyId, m2.delegationHash]), 'not revoked on chain');
    check(!device.state.context.lastDelegationHash, 'the device still remembers the revoked mandate');
    const before = await musd(CLOUDNEST);
    const refused = await agent.postCosign(IDS.inv1c, preRevoke.answer).then(() => null, (x) => x);
    check(refused && /DelegationRevoked/.test(refused.message), `the agent redeemed a revoked mandate: ${refused?.message ?? 'ok'}`);
    eq((await musd(CLOUDNEST)) - before, 0n, 'CloudNest received');
    eq((await agent.health()).mandate?.status, 'dead', "the agent's mandate status");
    eq(await simulateRedeem(m2, transferExec(CLOUDNEST, M(1))), 'DelegationRevoked()', 'AUTO on the revoked mandate');
    return [
      `ripar-revoke VERIFIED; enforcer.revoke ${short(r.hash)} (gas ${r.gasUsed} / ${Chain.GAS_LIMITS.revoke}); the device forgot the mandate`,
      `the held-back co-sign: agent -> 502 DelegationRevoked at estimation (nothing sent), mandate dead; AUTO eth_call -> DelegationRevoked()`,
    ];
  });

  await step('the record: balances, the agent\'s payments, the Activity feed (companion event decoder)', async () => {
    eq(await musd(CLOUDNEST), M(10), 'CloudNest total');
    eq(await musd(ATTACKER), 0n, 'attacker total');
    eq(await musd(vault.address), M(990), 'vault balance');
    const st = await api('/state');
    const paths = st.payments.map((p) => p.path).reverse();
    eq(paths.join(','), 'human,auto,human,auto', 'agent payments (oldest first)');
    // only the blocks mined on the fork (older blocks would be read from the public chain)
    const head = await pc.getBlockNumber({ cacheTime: 0 });
    const scan = await Activity.scanActivity(pc, dep, { chunk: 500, lookback: Number(head - BigInt(stack.forkedAtBlock)) });
    check(scan.errors.length === 0, () => `activity scan: ${scan.errors.join('; ')}`);
    const mine = scan.items.filter((i) => [i.args.delegator, i.args.vault].some((a) => typeof a === 'string' && a.toLowerCase() === vault.address.toLowerCase()) || ['Verdict', 'Panicked', 'Revoked'].includes(i.kind));
    const count = (k) => mine.filter((i) => i.kind === k).length;
    eq(count('HumanCosigned'), 2, 'HumanCosigned events');
    eq(count('AutoSpend'), 2, 'AutoSpend events');
    eq(count('LaneChanged'), 2, 'LaneChanged events');
    eq(count('Verdict'), 3, 'Verdict events (2 approvals, 1 denial)');
    eq(count('Panicked'), 1, 'Panicked events');
    eq(count('Revoked'), 1, 'Revoked events');
    return [
      `CloudNest received 10 mUSD (2 HUMAN + 2 AUTO), attacker 0, vault 990 mUSD; agent payments ${paths.join(' -> ')}`,
      `activity: ${['AutoSpend', 'HumanCosigned', 'Verdict', 'LaneChanged', 'Panicked', 'Revoked'].map((k) => `${k} ${count(k)}`).join(', ')}`,
      `companion gas (used / limit): ${Object.entries(gasUsed).map(([k, v]) => `${k} ${v.join('+')}/${Chain.GAS_LIMITS[k]}`).join(', ')}`,
    ];
  });

  console.log(`E2E PASSED: ${stepNo} steps in ${((Date.now() - T0) / 1000).toFixed(1)} s (device = ${EmuT.EMULATOR_LABEL})`);
} catch (e) {
  exitCode = 1;
  if (!(e instanceof CheckError)) console.error(e?.stack ?? e);
  console.log(`E2E FAILED at step ${stepNo} after ${((Date.now() - T0) / 1000).toFixed(1)} s`);
} finally {
  try {
    device?.emu.destroy();
  } catch {
    /* already gone */
  }
}
process.exit(exitCode);
