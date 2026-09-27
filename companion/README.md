# @ripar/companion

The Ripar Wallet companion web app: the **untrusted online courier** between the air-gapped Ripar device (or its
in-page EMULATOR), Monad and the AI agent. It builds requests, loops them as animated QR codes, reads the device's
single-part answer QR, verifies it with [`@ripar/protocol`](../packages/protocol), and relays it on-chain or to the
agent.

Vite + React 19 + TypeScript 5.9, viem, `@metamask/smart-accounts-kit` 2.0.0, `qrcode`, `qr-scanner`,
`@ripar/protocol` (consumed from source through its `ripar-source` export condition). Hash router, no backend: the
only servers it talks to are the RPC URL and the agent URL you configure.

## Try it (5 minutes, nothing on a public chain)

1. `bash scripts/dev-stack.sh` (repo root): an anvil fork of Monad testnet, the Ripar contracts, the agent and this app.
2. Open the URL it prints, `http://127.0.0.1:5173/?devstack`: Connect fills itself in and checks RPC, courier,
   contracts and agent. (Opened without `?devstack` on this machine, Connect offers "Use the local dev stack".)
3. Device: EMULATOR. Pair: read the keys (hold SIGN 2 s, release), then pair (page through, Place thumb, SIGN) and
   register. Vault: deploy, mint MockUSD. Mandate: prepare, sign on the emulated device.
4. Inbox: "Ask the agent to run now" (or every 30 s). Escalations appear; build the co-sign request and answer it on
   the device. The line "Next on the device" under each exchange says which key to press.

## Security model

- **The device decides.** It parses every request strictly, checks it against the contracts it pinned at pairing,
  shows every signed field and rebuilds every digest itself. The companion and the agent only carry bytes: a
  malicious companion can refuse to relay or show wrong text, but cannot make the device sign what its own screen
  did not show. The companion says so on every review: *check the device's screen, not this page*.
- **No seeds, no private keys.** The companion never asks for, stores or logs a seed or a private key. Chain writes
  are signed by the *courier*: an injected EIP-1193 wallet that only pays gas (it owns nothing), or, on a local anvil
  RPC only, an account anvil has unlocked (anvil signs; the page never sees a key).
- **The EMULATOR is always labelled `EMULATOR - DEMO KEYS`.** Its pairing carries the emulator firmware id
  `0x7bc44601d30720f1`; everything it signed is marked. Its NVS (seed + pinned context) lives in this browser's
  localStorage (`ripar.companion.emulator.nvs.v1`), so it is a demo, never a wallet.
- **Everything from the agent is validated** (`src/lib/agent.ts`): addresses, hex lengths, integers, ids. A request
  the agent prebuilt is decoded and checked against the escalation, the pinned chain / enforcer / vault, its expiry
  window and the on-chain `nonceUsed` before the device ever sees it; malformed escalations are listed as rejected.
- **Ripar contract addresses are never hard-coded**: they come from the deployments JSON that
  `contracts/script/Deploy.s.sol` writes (`deployments/<chainId>.json`), loaded by URL or pasted.

## Run

```bash
export npm_config_cache=F:/tools/npm-cache
cd F:/Projects/ripar-wallet && npm install        # npm workspaces: packages/*, agent, companion
cd companion
npm run dev          # http://127.0.0.1:5173 (binds 127.0.0.1 only)
npm run build        # tsc --noEmit (zero errors) + vite build -> dist/
npm test             # vitest: unit + emulator flows (the anvil e2e is skipped unless configured, see Tests)
```

The agent's default CORS allows `http://127.0.0.1:5173` and `http://localhost:5173`; if Vite picks another port,
add it to the agent's `COMPANION_ORIGIN`.

### Local anvil fork (no testnet gas needed)

The quickest way is the dev stack: `bash scripts/dev-stack.sh` (from the repo root) forks Monad testnet with anvil,
deploys the Ripar contracts from a private copy of `contracts/`, starts the agent and this dev server, and prints the
URL. Open it with `?devstack` (e.g. `http://127.0.0.1:5173/?devstack`) and the Connect settings (RPC, anvil courier,
deployments JSON from `/devstack/10143.json`, agent URL) are filled in from `/devstack/stack.json`
(`src/lib/devstack.ts`; local RPC and agent only). `node scripts/e2e.mjs` runs the whole story headlessly against it
with this app's own flow code and the WASM emulator. By hand:

```bash
anvil --fork-url https://testnet-rpc.monad.xyz --host 127.0.0.1 --port 8545      # chain id stays 10143
# deploy the Ripar contracts to the fork (from a checkout of contracts/):
RIPAR_WORKFLOW_OWNER=0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
  forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast --unlocked \
  --sender 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266                              # writes deployments/10143.json
```

Then on the Connect page: network *Local anvil fork*, RPC `http://127.0.0.1:8545`, courier *Anvil dev account*,
paste `deployments/10143.json`. The device pairs with chain 10143 as usual.

## Screens

| # | Screen | What it does |
|---|---|---|
| 1 | **Connect** | Network (Monad testnet RPC URL, or a local anvil fork), courier wallet, the deployments JSON (URL or paste, plus a `getCode` check of every contract on this RPC), the agent URL (and its optional `AGENT_API_TOKEN`), QR / log-scan settings. |
| 2 | **Device** | Hardware (camera + animated QR) or EMULATOR (the firmware in WASM, drawn from `state().display` at 320 x 240, SIGN key with press / hold, synthetic thumb with bpm). Emulator reset (random keys or the public demo seed). The screens-and-keys table. |
| 3 | **Pair** | Round 1: the keys-only pairing QR (Home: hold 2 s, release) gives K1 and P1. The canonical vault is derived from K1. Round 2: the full `ripar-pair-req` (chain, registry, DelegationManager, enforcer, sentinel, relay, vault, clock, and the on-chain panic-epoch / reopen-nonce floors), verified (`verifyPairing`: both BindDevice signatures, same K1 as round 1, canonical vault), then `registerDevice` through the courier. |
| 4 | **Vault** | The vault derived twice (`computeVaultAddress` and smart-accounts-kit `getCounterfactualAccountData`, Hybrid, `[K1, [], [], []]`, salt 0; must agree and equal the pinned vault), deployed through SimpleFactory with the kit's factory data, funded from the MockUSD faucet; MON / mUSD / AUSD balances and the sentinel lane. |
| 5 | **Mandate** | Agent (prefilled from the agent's `/health`), agent id, label, metered asset, caps, period, new-payee rule, optional RedeemerEnforcer / TimestampEnforcer rules. The epoch is the key's on-chain `minEpoch`. Shows **exactly what the device will show** (the firmware's review lines, predicted from the request bytes; tested line for line against the emulator), then the device signs with K1 and the request + `eth-signature` go to the agent (`POST /mandate`). |
| 6 | **Inbox** | The agent's escalations (polled every 5 s, plus its `/events` stream). For each: what the agent asks, the checks, the predicted device review (AI claims, risk, budget left from `autoBudget`), the QR round; a co-sign goes back to the agent (`POST /escalations/:id/cosign {ur}`), a deny (hold SIGN 2 s on the device's review: the device builds it) is relayed with `attestDenial` and reported to the agent. |
| 7 | **Kill switch** | Reads a `ripar-revoke` / `ripar-panic` / `ripar-reopen` QR, verifies it against the pinned context and P1, relays it (`revoke`, `panic`, `sentinel.reopen`). Shows the lane, `minEpoch`, the last reopen nonce and the state of every mandate recorded here (LIVE / REVOKED / KILLED BY PANIC). Always one click away in the header. |
| 8 | **Activity** | `AutoSpend` / `HumanCosigned` (canonical DelegationManager only), `Verdict`, `AgentShielded`, `LaneChanged`, `Revoked`, `Panicked` via `eth_getLogs`, scanned backwards in small block ranges (public RPCs cap the range), filtered to this vault and device or everything. |
| 9 | **About and proof** | Every address in use (canonical MetaMask, ERC-8004, Ripar from the deployments JSON, your device and vault), the security model, the EMULATOR disclaimer, the gas limits. |

## Device I/O: one interface

```ts
interface DeviceTransport {                       // src/device/transport.ts
  kind: 'hardware' | 'emulator';
  label: string;                                  // 'EMULATOR - DEMO KEYS' for the emulator
  present(frame: string | null): void;            // the QR frame shown now (what the device camera sees)
  onRead(listener: (text: string) => void): () => void;   // QR texts read from the device's screen
  resetReads(): void;
  dispose(): void;
}
```

- `HardwareQrTransport`: frames are drawn as an animated QR (`components/QrPlate.tsx`, ECC M, upper-case URs in
  alphanumeric mode); `qr-scanner` feeds `cameraRead()` (repeats within 1 s dropped).
- `EmulatorTransport` (`src/device/emulator.ts`): while the emulated device is on its SCAN screen it hands each new
  presented frame to `emu.scan()` (the firmware's own 1 s repeat filter applies), and reports the QR text its LCD
  shows. The same frames, the same parser, the same path as the hardware minus the camera. `EmulatorHost` owns the
  one in-page device: boot / restore from the persisted NVS, a real-time tick loop, SIGN key down / up (a release
  sooner than 120 ms after the press is held back, like a physical key), finger / bpm.
- `DeviceExchange`: one round over any transport: loops the request parts at the configured frame time (300 ms),
  accepts the first answer of an expected UR type that passes the caller's filter (req-id echo), reports ignored QRs
  (for example a stale QR still on the device's screen). A pasted response goes through the same path.

## Agent service API used

The agent (`agent/`, `npm start -w @ripar/agent`) is as untrusted as this page.

| Call | Body / result |
|---|---|
| `GET /health` | `{ ok, agent: <address>, mandate, config: { chainId, agentId } }`: prefills the Mandate form |
| `POST /mandate` | `{ request: <ripar-mandate-req UR>, signature: <eth-signature UR>, agentId?, label? }`: the agent rebuilds the delegation and recovers K1 itself |
| `GET /escalations` | `{ escalations: [...] }`, each with `cosign` fields and the agent's prebuilt `request {reqId, ur, parts}` (the agent verifies the device's answer against exactly that request, so the companion relays it after checking it; parts are re-cut from the verified CBOR) |
| `GET /events` | SSE; `event: escalation` refreshes the inbox (not used when a bearer token is configured) |
| `POST /escalations/:id/cosign` | `{ ur: <ripar-cosign> }`: the agent redeems on the HUMAN path |
| `POST /escalations/:id/deny` | `{ ur: <ripar-deny>, note }` after the companion relayed `attestDenial` |

Errors are read from `{ error: { code, message } }`. A simpler escalation shape without a prebuilt request (the
`EscalationRequest` of `@ripar/protocol`: `call`, `note`, `claims`, `risk`) is also accepted: the companion then
builds the request itself with a fresh random nonce (skipping any nonce it handed out or the chain reports used).

## Chain writes

All writes are built in `src/lib/chain.ts`, simulated first (`eth_call` from the courier with the same gas, so a
revert is decoded to its custom error before any gas is spent) and sent with an **explicit gas limit** (Monad charges
the limit). Measured on a local anvil fork of Monad testnet, where OpenZeppelin `P256.verify` falls back to Solidity
(no `0x0100` precompile; on Monad the P-256 checks are much cheaper):

| Write | Gas limit | Gas used (anvil fork) |
|---|---|---|
| `RiparDeviceRegistry.registerDevice` | 500,000 | 372,551 |
| `SimpleFactory.deploy` (vault) | 600,000 | 186,725 |
| `MockUSD.faucet` | 120,000 | 51,328 |
| `PulseCosignEnforcer.revoke` | 400,000 | 298,784 |
| `PulseCosignEnforcer.panic` | 400,000 | 294,800 to 296,903 |
| `RiparSentinel.reopen` | 450,000 | 324,831 |
| `RiparReputationRelay.attestDenial` | 800,000 | 488,470 |

(For reference, the agent's HUMAN-path `redeemDelegations` with the co-sign used 554,056 to 554,709 gas.)

## Tests

```bash
npm test                                  # test/logic.test.ts + test/device-flows.test.ts (+ e2e when configured)
RIPAR_E2E_RPC=http://127.0.0.1:8545 RIPAR_E2E_DEPLOYMENTS=<path>/deployments/10143.json npx vitest run test/e2e-anvil.test.ts
```

- `test/device-flows.test.ts` (WASM emulator in Node, test mode): keys-only + full pairing over the transport with
  multipart frames, vault derivation = smart-accounts-kit for the demo K1 (`0xc36F625D426eBa8f1e0129276B284a939CD3A57D`),
  the predicted mandate and co-sign reviews equal to the device's own review lines, the K1 mandate and the agent
  envelope, ERC-20 and native co-signs, the agent's prebuilt request relayed and answered, a deny from the review
  (hold 2 s) and its `attestDenial` call, REVOKE / REOPEN from the device menu and PANIC, a kill-switch QR from another
  device refused, and early refusals (wrong vault / chain, undecodable calldata, stale / mismatched / replayed agent
  requests, bad mandate forms).
- `test/logic.test.ts`: the agent client against untrusted JSON (and its error / token handling), every chain-write
  builder with its explicit gas limit, `sendWrite` never sending a write whose simulation reverts, custom-error
  decoding, the exchange loop over a fake transport, event decoding (foreign DelegationManagers dropped), vault
  derivation on 10143 and 143, the device's text formats.
- `test/e2e-anvil.test.ts` (optional, local RPC only): the whole flow on an anvil fork with the Ripar contracts
  deployed: pair, `registerDevice`, deploy and fund the vault, mandate, a device co-sign **redeemed on-chain** by an
  agent account (HUMAN path, `HumanCosigned`), a deny relayed (`Verdict`), the lane closed by the (impersonated) CRE
  forwarder and reopened by the device, REVOKE and PANIC; every write checked against its gas limit.

## Files

| Path | What |
|---|---|
| `src/lib/chain.ts` | the only module that writes to the chain (builders, gas limits, simulate + send) |
| `src/lib/reads.ts`, `src/lib/activity.ts` | on-chain reads, event scan |
| `src/lib/agent.ts` | agent API client and strict parsing of what it sends |
| `src/lib/flows/*.ts` | pairing, vault, mandate, co-sign / deny, kill switch: request assembly and response handling |
| `src/lib/review-preview.ts` | the device's review lines, mirrored from `firmware/src/review.cpp` |
| `src/lib/store.ts`, `storage.ts` | persisted state (settings, public device identity, pinned context, mandates, nonces handed out) |
| `src/device/transport.ts` | `DeviceTransport`, `HardwareQrTransport`, `DeviceExchange` |
| `src/device/emulator.ts`, `emulator-loader.ts`, `nvs.ts`, `lcd.ts`, `DeviceContext.tsx` | the EMULATOR: transport, host, WASM loading, NVS persistence, LCD painter, React context |
| `src/components/*` | QR plate, camera reader, emulated device, exchange panel, review / verification panels, transaction panel, manual parts |
| `src/screens/*` | the nine screens |
| `PRODUCT.md`, `DESIGN.md` | product context and the visual system (a device service manual) |

## Known limitations

- The hardware path (camera scanning with `qr-scanner`, the animated QR read by the real OV5640) has not been run
  against a physical device; the emulator path and a pasted-QR path have.
- The ERC-8004 identity registry on Monad testnet reverted `register` (even as an `eth_call`, 2026-09-27), so the
  anvil e2e files its denial against an existing agent id.
- Ripar contract addresses are not final; nothing works until a deployments JSON is loaded.
- The emulated device's seed is in localStorage (by design: it is a demo). Clearing site data erases it and its vault.
- `GET /events` cannot carry a bearer token (EventSource), so with `AGENT_API_TOKEN` the inbox polls only.
- The main bundle is about 250 KB gzipped (viem, React, the protocol); smart-accounts-kit (about 190 KB gzipped) and
  the emulator (about 190 KB gzipped WASM) load on demand.
