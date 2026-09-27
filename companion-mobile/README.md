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
npm test               # vitest: link helpers, BLE framing, Wi-Fi link + provisioning, emulator page, pairing + payment e2e
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
| `link` | Link choice and Bluetooth pairing; the Wi-Fi link (testing) status. |
| `wifi` | **TEMPORARY, testing:** Wi-Fi link setup (send the network over Bluetooth, WI-FI ON on the device, code + IP, test). |

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
  kind: 'qr' | 'ble' | 'emulator' | 'wifi';
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
| **Wi-Fi (testing)** (`wifi-link.ts`, `wifi-prov.ts`) | TEMPORARY, see [below](#the-wi-fi-link-temporary-for-testing-only). The same UR parts POSTed to the device over plain HTTP on the LAN, STATUS and the answer polled back. Not air-gapped. |
| **Emulator** (`emulator-link.ts`, `emulator/`) | `firmware/emu/dist` (the firmware's own C++ as WASM) inlined into one HTML page by `scripts/build-emu-html.mjs` (runs on `npm install`; the generated file is git-ignored), run in a hidden WebView; the app draws its LCD from the firmware's screen model, with the SIGN key (real press / hold timing) and a synthetic thumb. Demo keys, labelled everywhere. |

The UI presents QR as the default air-gapped path and Bluetooth as a fallback that turns the device's radio on
("NOT AIR-GAPPED", mirroring the device's RADIO ON badge).

## The Wi-Fi link (TEMPORARY, for testing only)

> **Temporary test feature.** It turns the device's Wi-Fi on: **Ripar is NOT air-gapped while it is on.** It exists to
> test the phone and the device together over a LAN and is meant to go away with the firmware's `RIPAR_WIFI` build flag
> (env:ripar only; env:ripar-ble / env:ripar-airgap have no Wi-Fi). QR stays the default and the recommended link;
> the app says "NOT AIR-GAPPED · WI-FI ON · TESTING" on Home and on the Device tab while Wi-Fi is the chosen link.
> Firmware contract: `docs/WIFI_LINK.md` (firmware/src/wifi_proto.cpp, flows.cpp).

**Setting it up** (Device tab > *Wi-Fi link (testing)*, or Link > *Wi-Fi (testing)* > *Set up*; `app/wifi.tsx`):

1. Connect over Bluetooth (the usual BLE LINK pairing, `components/BleConnect.tsx`), only to hand over the network.
2. Enter the SSID and password (hidden field) while the Ripar shows Home, and send: one write of the UTF-8 JSON
   `{"v":1,"ssid":"...","pass":"..."}` to the PROV characteristic `52495041-5200-4c49-4e4b-000000000005` (bonded link
   only). SSID 1..32 bytes without control characters, password empty (open network) or 8..63 printable ASCII: the
   firmware's `parse_prov` rules, checked before anything is written (`wifi-prov.ts`). The value is at most 217 bytes
   and is **never split into separate writes** (the firmware takes one write as one value; a value longer than MTU-3
   goes out as a GATT long write, which Android does by itself). The password is not logged, stored or put in an error
   message; the screen clears it after sending. The device takes it only on HOME or BLE PAIRING (no code waiting): the
   screen warns when STATUS shows another screen, and shows the STATUS note of a refusal (`wifi setup ignored: the
   device must show HOME ...` / `wifi setup refused: ...`) with "go back to Home".
3. On the device: **JOIN WI-FI &lt;ssid&gt;?** review, SIGN on the last page (no pulse; hold 2 s refuses) → WI-FI SAVED.
   Then menu (Home: hold 2 s + release, hold 2 s) → **WI-FI ON** → review → SIGN. Home shows NOT AIR-GAPPED, the IP
   address and `CODE 1234 5678` (per boot). Wi-Fi stays on, also across restarts, until WI-FI OFF, FORGET WI-FI or PANIC.
4. In the app: the address is prefilled from STATUS `"ip"` (the last known one is kept: the device drops `ip` from a
   STATUS whose note needs the room; typed otherwise; `ripar-xxxx.local` may not resolve on Android), type the code,
   **Test the link** (GET /status), then **Use Wi-Fi for requests**.

**The link** (`src/device/wifi-link.ts`, same `DeviceLink` interface, same round UI as Bluetooth):

| | |
|---|---|
| `GET /status` | STATUS JSON (the BLE document + `"wifi"`: off / connecting / on, `"ip"`), polled every ~700 ms. `"radio"` is the Bluetooth link: `"off"` over HTTP is normal |
| `POST /rx` | `text/plain`, up to 4 UR lines (at most 1 KB) per request, each + LF; only while the device is on SCAN, else 409 + STATUS whose note says why |
| `GET /tx` | the UR text of the QR on the device's screen (204: none), polled with STATUS |
| every request | `X-Ripar-Code: <8 digits>`; 401 = wrong code (polling stops, the code is forgotten); 429 + Retry-After = locked after repeated wrong codes (3 free, then 1 s doubling up to 300 s): the app says "Locked ... wait N s" and polls again only when the lock ends |

`send()` waits for STATUS SCAN ("press SIGN on the Ripar"), POSTs the parts and repeats them until the device leaves
SCAN; a 409 in between (the device left SCAN between two polls) sends it back to waiting for SCAN. Requests are
serialised (the device serves one connection at a time), time out after 4 s and are retried twice on network errors;
three failed polls in a row mark the link unreachable. Errors say what to do: wrong code, locked, unreachable (same
Wi-Fi? WIFI ON? use the IP), not a Ripar at that address, not scanning.

**Web preview:** the device's HTTP server sends no CORS headers, so a browser cannot call it (and Bluetooth does not
run there): the link and setup screens say so on web. The Android app is not affected.

**Stored:** the last working address and the SSID (AsyncStorage settings: `wifiHost`, `wifiSsid`); the 8-digit code
only in memory and expo-secure-store (`lib/wifi-secret.ts`, cleared on disconnect or a refused code); the password
nowhere. Android: cleartext HTTP to the LAN address works because `plugins/with-ripar-android.js` sets
`usesCleartextTraffic` (checked in the generated manifest), and `INTERNET` is in the manifest.

Tested (`test/wifi.test.ts`) against a real HTTP server on 127.0.0.1 whose far end is the emulated firmware
(`test/helpers.ts` FakeWifiRipar, answering as `wifi_proto.cpp` does): keys-only QR and a full pairing round trip over
the link, wrong code, lock-out (429 on open, back-off while connected), code changed mid-session, radio "off" and a
missing ip in STATUS, 409 off SCAN (note, guidance, retry after a mid-send 409),
unreachable address, a web server that is not a Ripar; the PROV value (JSON, length / charset rules, one write at
every MTU, password never in an error). **Not run against the real firmware or on a phone yet.**

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
- Cleartext HTTP is allowed for a LAN dev stack (and the Wi-Fi test link); public RPCs are https.
- **Wi-Fi link (TEMPORARY, testing)**: not air-gapped while the device's Wi-Fi is on (the app says so on every screen
  that shows the link). The phone is as untrusted over Wi-Fi as over QR: the device still parses, shows and checks
  every request and needs pulse + SIGN. The link code travels in clear on the LAN (plain HTTP): anyone on that network
  can read it. Wi-Fi goes off with WI-FI OFF, FORGET WI-FI or PANIC; it does not time out by itself.

## Layout

```
app/                 expo-router routes: (tabs)/ index activity device agents settings, onboarding, send, receive,
                     pay, done, pair, personal, link, wifi, scan, network, mandate, escalation/[id], activity/[id]
src/device/          link.ts (interface + helpers), qr-link, ble-link, ble-framing, ble-plx, emulator-link,
                     emulator/ (WebView host + LCD panel), guide.ts (device steps, refusal advice), provider,
                     wifi-link + wifi-prov (TEMPORARY Wi-Fi test link and its BLE provisioning)
src/lib/             ported from companion/src/lib (flows/pairing, mandate, cosign, killswitch; agent, reads,
                     activity, chain builders, review-preview, format, json) + personal payments, feed, store,
                     wifi-secret (the Wi-Fi link code in expo-secure-store)
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

- Verified: `tsc --noEmit` clean; 55 vitest tests (link helpers, BLE framing, BleLink, QrLink and WifiLink against the
  emulated firmware, Wi-Fi provisioning, the personal-mandate payment end to end, the emulator WebView page in Node);
  `expo export --platform android`; `expo prebuild` + `gradlew assembleDebug` (a debug APK with the JS bundle embedded). The screens were
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
- **Wi-Fi link (TEMPORARY):** written against docs/WIFI_LINK.md and the firmware sources as they stood on 2026-09-28
  and tested against a fake device; never run against a real Ripar or on a phone. The Wi-Fi screens were checked in
  the web preview only. Remove it (and the `wifi` link choice) together with the firmware's `RIPAR_WIFI` flag.
- Monad testnet needs a deployments JSON (the sentinel address is deployment-specific); none ships with the app.
