# Ripar companion for Android

The phone side of the Ripar Wallet: an **untrusted courier** between the air-gapped Ripar device, Monad and (optionally)
an AI agent. The device makes and keeps the keys, shows what it signs, and signs only after a live pulse and a press of
SIGN. This app never asks for, sees or stores a seed.

Expo SDK 57 · React Native 0.86 (New Architecture, Hermes) · expo-router · viem · `@ripar/protocol` from source.
Layout after the Polaris reference app (`D:/Project/polaris/mobile`), theme **signal orange on graphite**.

## Run

```bash
cd companion-mobile
npm install            # its own node_modules (not a workspace of the repo root: see "Layout")
npm test               # vitest: link helpers, BLE framing, emulator page, pairing + personal payment end to end
npm run typecheck      # tsc --noEmit
npx expo start         # Metro for a debug build (npx expo run:android builds + installs one)
```

The repo root must have its own `npm install` done too: `tsc` resolves the protocol source's `viem` / `@noble` types
from there (Metro resolves them from this app's `node_modules`, see `metro.config.js`).

## Build the APK

```bash
export GRADLE_USER_HOME=F:/tools/gradle
export JAVA_HOME="D:/Program Files/Android/Android Studio/jbr"
export ANDROID_HOME=C:/Users/<you>/AppData/Local/Android/Sdk
npx expo export --platform android          # JS bundle only (checks that everything bundles)
npx expo prebuild --platform android        # generates android/ (git-ignored); RIPAR_ABIS=arm64-v8a,x86_64 adds x86_64
cd android && ./gradlew assembleDebug       # android/app/build/outputs/apk/debug/app-debug.apk
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

`plugins/with-ripar-android.js` makes the debug APK self-contained (the JS bundle is embedded: it runs without Metro,
and still prefers Metro when one is running), allows cleartext HTTP (a LAN dev stack / agent), and builds only
`arm64-v8a` unless `RIPAR_ABIS` says otherwise. It is applied by `prebuild`, so `android/` never needs hand edits.

## Screens

| Tab / route | What it does |
|---|---|
| Onboarding | Three slides: *Keys that never touch the internet* / *It signs only what it shows* / *A real heartbeat, then SIGN*, then **Pair your Ripar** with the link choice (QR recommended, Bluetooth fallback, emulator). |
| Home | The orange balance card (vault pill, mUSD balance, MON, round Send / Receive / Scan / Device), "Finish setting up", Quick row, Insights (payments per day, by actor), recent activity. NOT AIR-GAPPED banner while Bluetooth is selected. |
| Send (sheet) | Asset chips, keypad amount, payee (paste / scan), note → Confirm sheet → `pay` (device round, then the redemption) → **Done.** receipt. |
| Receive (sheet) | Vault address QR, copy, share. |
| Activity | Payments, agent AUTO spends, co-signed spends, incoming transfers, PANIC / revoke / lane events of *this* vault and device key (the contracts are shared), with a detail screen. |
| Device | The device card, link choice, pinned context, kill switch, the SIGN key table (docs/FIRMWARE.md §5), emulator controls. |
| Agents | Agent service health, "Ask the agent to run", the escalation inbox (co-sign or DENY + report, with the AI-claims check explained), agent mandates. |
| Settings | Phone key (gas; testnet only), network / deployment / dev stack / agent, QR timing, security model. |
| `pair` | Keys-only QR → full pairing (the device pins contracts and derives its own vault) → register → deploy vault → faucet. |
| `personal` | The personal mandate (below). |
| `scan` | Kill switch: read a PANIC / revoke / reopen the device signed, verify it, relay it. |
| `link` | Link choice and Bluetooth pairing. |

## Sending from the vault: the personal mandate

The vault is a MetaMask HybridDeleGator owned by the device's **K1** alone, and K1 only signs mandates. So the phone
pays from the vault the way an agent does, under a mandate of its own: a delegation *vault → this phone's hot key*
whose one PulseCosignEnforcer caveat sets **perTxAutoCap = 0 and periodAutoCap = 0** (plus a RedeemerEnforcer caveat
naming the hot key). With both caps at 0 the enforcer's AUTO path refuses every payment (`HumanRequired`), so every
payment needs a fresh HUMAN co-sign:

1. once: the device reviews and signs the personal mandate (pulse + SIGN);
2. each Send: a `ripar-cosign-req` for that exact call (fresh single-use nonce, 15 min expiry) → the device shows it,
   pulse + SIGN → the app verifies the P-256 co-sign → the hot key sends `DelegationManager.redeemDelegations` with the
   160-byte co-sign args (and pays the gas).

The hot key alone can move nothing. The device remembers only the last mandate it signed: after signing an agent
mandate, a personal Send shows **UNKNOWN MANDATE** and a "may become an AUTO payee" line on the device; expected (the
caps are 0), and explained in the app. PANIC kills the personal mandate with every other one; the app says so and
offers to sign a new one. Code: `src/lib/flows/personal.ts`, `app/pay.tsx`; tested end to end against the emulated
device in `test/flows.test.ts`.

## The device link (`src/device/`)

One interface for every screen (`link.ts`):

```ts
interface DeviceLink {
  kind: 'qr' | 'ble' | 'emulator';
  send(req: { urType: string; cbor: Uint8Array } | string[]): Promise<void>;
  onResponse(cb: (urText: string) => void): Unsubscribe;
  status?: Observable<DeviceStatus | null>;
  close(): void;
}
sendToDevice(link, request)                          // BuiltRequest | {urType, cbor} | parts -> link.send(parts)
awaitDeviceResponse(link, expectedType, { timeoutMs, accept, signal, onIgnored })
requestAndVerify(link, request | null, verifier)     // listen, send, first acceptable answer, verify
```

`requestParts()` cuts exactly the parts `@ripar/protocol` `buildRequest().parts` cuts (tested). Every answer is
classified (complete single-part UR, CRC, expected type), filtered (`accept`: the request's req-id echo) and verified
(`parseResponse` with the request, the pinned contracts and the device keys) before the app uses it.
`components/DeviceRound.tsx` is the one UI of a round, for every link.

| Link | How |
|---|---|
| **QR** (`qr-link.ts`, default) | The request's UR parts (~70 bytes each) looped as an animated QR at ~300 ms per frame (`components/Qr.tsx`, `qrcode` core → one SVG path); the device's answer QR read with expo-camera. No radio. |
| **Bluetooth** (`ble-link.ts`, `ble-framing.ts`, `ble-plx.ts`) | `docs/BLE_LINK.md` v1: service `52495041-5200-4c49-4e4b-000000000001` (`RIPAR-XXXX`); RX `…0002` each UR part as a UTF-8 line + LF in writes of MTU-3 bytes (MTU 247 requested); TX `…0003` the answer UR + LF, reassembled across notifications; STATUS `…0004` JSON (`note` shown, unknown keys ignored, a truncated notification triggers a READ). The device takes lines only on SCAN: the app waits for STATUS `SCAN` and tells the user to press SIGN on the device, then cycles the parts until STATUS leaves SCAN. Pairing: LE Secure Connections numeric comparison, only while the device shows BLE PAIRING (menu → BLE LINK → pulse + SIGN; confirm with SIGN on the device). Android 12+ permissions via the ble-plx config plugin (`BLUETOOTH_SCAN` neverForLocation, `BLUETOOTH_CONNECT`). |
| **Emulator** (`emulator-link.ts`, `emulator/`) | `firmware/emu/dist` (the firmware's own C++ as WASM) inlined into one HTML page by `scripts/build-emu-html.mjs` (runs on `npm install`; the generated file is git-ignored), run in a hidden WebView; the app draws its LCD from the firmware's screen model, with the SIGN key (real press / hold timing) and a synthetic thumb. Demo keys, labelled everywhere. |

The UI presents QR as the default air-gapped path and Bluetooth as a fallback that turns the device's radio on
("NOT AIR-GAPPED", mirroring the device's RADIO ON badge).

## Security model

- **Keys stay on the device.** Seed, K1 (vault owner, signs mandates) and P1 (co-signs, kill switch) are made and kept
  on the Ripar. The app holds public keys, the pinned context and records (AsyncStorage). No seed, ever.
- **The app is untrusted.** The device parses every request itself, checks it against the contracts pinned at pairing
  (firmware v1.2 compiles the registry, enforcer and relay in), shows every signed field and rebuilds every digest.
  The app refuses early what the device would refuse (`checkEscalation`, `firmwareRefusal`, `tokenCheck`), and
  verifies every answer (signatures, req-id, pinned contracts) before acting on it.
- **Phone hot key** (expo-secure-store, `WHEN_UNLOCKED_THIS_DEVICE_ONLY`): pays gas for everything the app relays and
  redeems personal-mandate payments. Not the vault owner; with AUTO caps of 0 it cannot move vault funds without a
  fresh device co-sign. **Testnet only**: fund it with a little testnet MON. It is excluded from Android backups.
- **Nonces** are single-use per mandate on chain: a nonce is never reused, and one whose on-chain state cannot be read
  is never shown to the device (fail closed).
- **Agent data is untrusted**: memos, vendor names and AI claims are shown as such; the device checks AI claims
  against its own decoding of the call (AI CLAIM MISMATCH).
- **Bluetooth** is a fallback: while it runs the device is not air-gapped (it says so on every screen); it turns off
  with BLE OFF, after 5 min without traffic, on PANIC and at power-off.
- Cleartext HTTP is allowed for a LAN dev stack; public RPCs are https.

## Layout

```
app/                 expo-router routes: (tabs)/ index activity device agents settings, onboarding, send, receive,
                     pay, done, pair, personal, link, scan, network, mandate, escalation/[id], activity/[id]
src/device/          link.ts (interface + helpers), qr-link, ble-link, ble-framing, ble-plx, emulator-link,
                     emulator/ (WebView host + LCD panel), guide.ts (device steps, refusal advice), provider
src/lib/             ported from companion/src/lib (flows/pairing, mandate, cosign, killswitch; agent, reads,
                     activity, chain builders, review-preview, format, json) + personal payments, feed, store
src/components/      Surface (raised plane + edge light), Button, Screen, Sheet, Keypad, Qr, CameraScanner,
                     DeviceRound, HeroArt, Rows, Sparkline, ...
src/theme/           signal orange on graphite: colors (contrast measured), typography (tabular figures), tokens
scripts/             build-emu-html.mjs, emu-bridge.js, make-icons.mjs
plugins/             with-ripar-android.js (prebuild config plugin)
test/                vitest, with the firmware emulator as the device
```

`companion-mobile` is deliberately **not** in the root `workspaces`: Expo wants a hoisted `node_modules` with its own
React Native versions. `@ripar/protocol` is used from `../packages/protocol/src` (Metro `resolveRequest` in
`metro.config.js`, TypeScript `paths`, the vitest alias), so there is one copy of viem and noble in the bundle.

## Web preview (design checks only)

`npx expo start --web` renders the screens in a browser (react-native-web). It is a preview surface, not a target:
expo-secure-store, the camera scanner, Bluetooth and the emulator WebView do not work there, and entrance animations
are disabled on web (`components/motion.ts`), as in Polaris.

## Status and open issues

- Verified: `tsc --noEmit` clean; 33 vitest tests (link helpers, BLE framing, BleLink and QrLink against the emulated
  firmware, the personal-mandate payment end to end, the emulator WebView page in Node); `expo export --platform
  android`; `expo prebuild` + `gradlew assembleDebug` (a debug APK with the JS bundle embedded). The screens were
  checked in the web preview.
- **Not yet run on Android hardware or an Android emulator.** The local AVD crashed at boot (exit 139) in the build
  environment, so the APK was built but not launched; native-only behaviour (camera, BLE, WebView emulator, secure
  store, shadows) is untested on a device.
- **Bluetooth** is written to docs/BLE_LINK.md and tested against a fake transport whose far end is the emulated
  firmware; never against a real Ripar (the firmware's radio side is itself untested on hardware, BLE_LINK.md §7).
  Android's automatic bonding on the first protected read is relied on; if a phone does not start bonding by itself,
  an explicit `createBond` (native) would be needed.
- The vault address is derived with `@ripar/protocol` only (the web companion also cross-checks with
  `@metamask/smart-accounts-kit`, which is not bundled here).
- No Server-Sent Events in React Native: the Agents tab polls the agent every 5 s while open.
- Monad testnet needs a deployments JSON (the sentinel address is deployment-specific); none ships with the app.
