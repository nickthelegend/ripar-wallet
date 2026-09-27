# Ripar Wallet: Bluetooth LE fallback link (v1)

Ripar is an **air-gapped** signer. Requests arrive as QR codes through the camera and every answer leaves as a QR code on the screen ([PROTOCOL.md](PROTOCOL.md) §1). That stays the primary path.

The firmware builds `env:ripar` (default, for testing) and `env:ripar-ble` (`RIPAR_BLE=1`) add **Bluetooth LE as a fallback courier** for the case where the camera cannot read the phone's QR codes (glare, a cracked screen, a bad camera module). The radio is dead until the user wakes it **on the device**, and the device says so on every screen while it is alive. The link carries exactly the text a QR code would carry, so nothing about parsing, review, policy, pulse or SIGN changes.

`env:ripar-airgap` (`RIPAR_BLE=0`, `RIPAR_WIFI=0`) is the radio-free firmware: no Bluetooth or Wi-Fi code is linked at all. The linked binary can be checked for this (§6).

> **Wi-Fi (temporary test feature).** The default `env:ripar` also contains a Wi-Fi test link (`RIPAR_WIFI=1`, [WIFI_LINK.md](WIFI_LINK.md)). Its network is provisioned over this Bluetooth link through a fifth characteristic, **PROV** (§4.6), and STATUS gains the keys `wifi` and `ip` (§4.5). `env:ripar-ble` is the same Bluetooth firmware without any of it.

This document is the contract for the mobile app. **Status (2026-09-27; PROV and the STATUS Wi-Fi keys 2026-09-28):** the firmware builds and the portable link logic is host-tested (`firmware/test/host/test_ble_link.cpp`). **Nothing on the radio side has run on hardware yet**: advertising, pairing, GATT access, notifications, throughput and power-off/on cycles are all untested (§7).

## Contents

1. [Why this does not weaken the pitch](#1-why-this-does-not-weaken-the-pitch)
2. [Turning the radio on and off](#2-turning-the-radio-on-and-off)
3. [Pairing and security model](#3-pairing-and-security-model)
4. [GATT protocol](#4-gatt-protocol)
5. [Phone app flow](#5-phone-app-flow)
6. [Builds and the radio check](#6-builds-and-the-radio-check)
7. [Limits and what is untested](#7-limits-and-what-is-untested)

## 1. Why this does not weaken the pitch

- **Air-gapped by default.** The Bluetooth controller is never initialised at boot. Every power-on (and every reset) starts with the Bluetooth radio off. This link never starts Wi-Fi; in `env:ripar` the separate Wi-Fi test link only runs after the user chose WI-FI ON in the device menu ([WIFI_LINK.md](WIFI_LINK.md) §4), and `ripar-ble` / `ripar-airgap` contain no Wi-Fi code.
- **Dead until woken on the device.** Only the device can turn the radio on: device menu → **BLE LINK** → a review that says *"Turns the radio ON. Ripar is not air-gapped while it is on."* → pulse + SIGN, the same gesture as a signature. Nothing a phone, a companion or a QR code sends can turn it on.
- **Always visible.** While the controller is alive, a red **RADIO ON** badge is drawn on every screen (by the display flush itself, so no screen can appear without it), and Home says **NOT AIR-GAPPED** instead of AIR-GAPPED. The badge follows the controller state, not a flag: if turning the radio off ever failed, the badge would stay.
- **Goes off by itself.** After 5 minutes without link traffic, on **BLE OFF** in the device menu, on **PANIC**, and at power-off. Off means the controller is disabled and de-initialised.
- **Same review, pulse and SIGN.** A line from the phone enters the same intake as a camera-decoded QR part (UR decoder → parser → review → policy → pulse → SIGN), and only while the device is on SCAN because the user pressed SIGN on Home. The phone is exactly as untrusted as the companion that shows QR codes: it can deliver request parts, read the device's screen state and receive the response QR. It cannot press keys, skip or shorten a review, sign, pair itself, or turn the radio on.
- **Provable radio-free use.** Users who never want a radio flash `env:ripar-airgap`, which contains no Bluetooth or Wi-Fi code; a symbol check on the linked binary shows it (§6). `env:ripar-ble` contains Bluetooth but no Wi-Fi code.

What the link does cost, honestly: while the radio is on, the Bluetooth stack (Bluedroid + the controller, running on the same chip as the keys) is reachable over the air, the device's presence and its random advertising name are visible, and its Bluetooth address is the chip's public address (not randomised). Keep the radio on only as long as needed, or use `ripar-airgap`.

## 2. Turning the radio on and off

| Step | On the device |
|---|---|
| 1 | Home: hold SIGN 2 s and release → pairing QR; hold 2 s there → **DEVICE ACTIONS** |
| 2 | Press to move to **BLE LINK (radio on: phone courier)**, hold 2 s to select |
| 3 | Review **BLE LINK: TURN THE RADIO ON?** - it names the new random advertising name `RIPAR-XXXX` |
| 4 | Pulse, then SIGN (nothing is signed: this is a confirmation) |
| 5 | **BLE PAIRING RIPAR-XXXX** screen: the pairing window is open while it is shown |

Menu items in the `ripar-ble` build: `REVOKE the last mandate`, `REOPEN the agent lane`, `BLE LINK` (radio off) / `BLE OFF` (radio on), `FORGET PHONE`, `BACK`. The `ripar` build adds `WI-FI ON` / `WI-FI OFF` and `FORGET WI-FI` before `BACK` ([WIFI_LINK.md](WIFI_LINK.md) §4).

The radio turns off:

| Trigger | Notes |
|---|---|
| **BLE OFF** (menu) | at once |
| hold 2 s on the pairing screen (no code shown) | at once |
| **PANIC** | before the panic is signed (in `ripar` builds Wi-Fi goes off too) |
| 5 min without link traffic | "traffic" = any request from the authenticated phone (read, write, subscription) and pairing activity. The device's own notifications do not count. |
| power-off / reset | the controller is never started at boot |

Off = stop advertising, drop the link, `esp_bluedroid_disable/deinit`, `esp_bt_controller_disable/deinit`. The controller memory is kept reserved (not `esp_bt_controller_mem_release`d) so the radio can be turned on again without a reboot.

## 3. Pairing and security model

- **LE Secure Connections only, with MITM and bonding** (`ESP_LE_AUTH_REQ_SC_MITM_BOND`, "only accept the specified authentication"). The device's IO capability is DisplayYesNo, so a phone pairs by **numeric comparison**: the device shows the 6-digit value large on the pairing screen, the phone shows its own. The user compares them and presses **SIGN** on the device to confirm (**hold 2 s = reject**), and confirms on the phone.
- A SIGN press only confirms a code that was already on screen when the press began (the screen is re-entered when a code appears, so an earlier press is dropped).
- **Legacy pairing, Just Works and passkey entry are refused.** A passkey-entry attempt (a phone that can only type a number) is aborted by disconnecting; a bond that completed without the user's confirmation on the device would be deleted at once.
- **Pairing only while BLE PAIRING is shown.** On any other screen every pairing request and comparison is refused. Leaving the screen (key, 120 s timeout, radio off) closes the window and rejects a pending comparison.
- **One phone.** A confirmed new pairing deletes every other bond; **FORGET PHONE** (menu) deletes the bond at once when the radio is on (and disconnects), or, when it is off, before advertising starts the next time the radio is turned on (flag in NVS namespace `riparble`). A bonded phone reconnects without pairing; the link is re-encrypted with its key.
- **No GATT access without an authenticated link.** Every characteristic value and descriptor requires an encrypted, MITM-authenticated link at the ATT layer; in addition the firmware answers every read and write itself and refuses it (`Insufficient Authentication`, 0x05) unless this connection completed an authenticated (MITM) security procedure. Only service discovery (the service / characteristic declarations) is open, as BLE requires.
- **One connection at a time.** A second central is disconnected at once. A connection that has not authenticated after 30 s is dropped (not while a code is waiting for the user).
- The bond keys are stored by Bluedroid in NVS, unencrypted, like the seed (see FIRMWARE.md "Known limitations").

## 4. GATT protocol

### 4.1 Advertising

| | |
|---|---|
| Advertising data | flags (LE General Discoverable, BR/EDR not supported) + complete list of 128-bit service UUIDs: the RIPAR LINK service |
| Scan response | complete local name `RIPAR-` + 4 upper-case hex digits, random per enable (e.g. `RIPAR-3F9A`); the same name is shown on the device |
| Type | connectable undirected (ADV_IND), 60-100 ms interval, public device address |
| Connections | one at a time; advertising restarts after a disconnect while the radio is on |

### 4.2 Service and characteristics

Service **RIPAR LINK** `52495041-5200-4c49-4e4b-000000000001` (the first bytes spell `RIPAR`, `LINK`).

| Characteristic | UUID | Properties | Direction |
|---|---|---|---|
| RX | `52495041-5200-4c49-4e4b-000000000002` | Write, Write Without Response | phone → device |
| TX | `52495041-5200-4c49-4e4b-000000000003` | Notify | device → phone |
| STATUS | `52495041-5200-4c49-4e4b-000000000004` | Read, Notify | device → phone |
| PROV (`ripar` builds only) | `52495041-5200-4c49-4e4b-000000000005` | Write | phone → device |

All values and the two Client Characteristic Configuration descriptors need the authenticated link (§3). PROV exists only in firmware built with `RIPAR_WIFI=1` (`env:ripar`); an app can offer Wi-Fi setup exactly when the service has it (§4.6).

**MTU.** The device's local ATT MTU is **247**. A peripheral cannot start the MTU exchange: the phone should request 247 (Android `requestMtu(247)`; iOS negotiates by itself). With the default MTU 23 everything still works, only slower.

### 4.3 RX: phone → device

- A stream of UTF-8 bytes. Write boundaries do not matter: the device reassembles **lines ending in `\n`** (a trailing `\r` is dropped, empty lines are ignored).
- Each line is **one UR part**, exactly the text a QR code would carry: upper-case UR, single part `UR:<TYPE>/<BYTEWORDS>` or one multipart part `UR:<TYPE>/<SEQ>-<LEN>/<BYTEWORDS>` ([PROTOCOL.md](PROTOCOL.md) §1).
- A line longer than **4096 bytes** (without the `\n`) is dropped whole; the stream recovers at the next `\n`.
- Each line is fed into the **same intake** as a camera-decoded QR (`intake_part()` in `flows.cpp`: UR decoder → `on_request` → review → policy → pulse → SIGN). Nothing else is different.
- Lines are **only accepted while the device is on SCAN** (the user pressed SIGN on Home). Otherwise they are ignored and STATUS says so in `note`.
- Both write types work. Write Without Response is faster; pace it (Android: wait for `onCharacteristicWrite`; iOS: `canSendWriteWithoutResponse`). Keep each write at most MTU - 3 bytes. Long (prepared) writes up to 4160 bytes are accepted too.
- The device queues at most 32 lines / 64 KB; a line that does not fit is dropped. Multipart URs are fountain codes, so a lost part only costs time: **keep cycling the parts** (as the QR animation does) until STATUS leaves SCAN.

### 4.4 TX: device → phone

When the device shows a QR (a signed response, or the unsigned keys-only pairing QR `ripar-pair`), it also sends that **UR text + `\n`**, exactly the text the QR encodes (upper case), in notifications of at most **MTU - 3** bytes. Concatenate notifications until `\n`.

It is sent once per QR, and again whenever the phone subscribes to TX while the QR is on screen. Nothing is sent while no QR is on screen.

### 4.5 STATUS: device → phone

UTF-8 JSON, at most **180 bytes**. Readable at any time over the authenticated link, and notified on **every change**: screen change, scan progress, note.

```json
{"v":1,"screen":"SCAN","paired":true,"k1":"0xAbCd...1234","scan":{"got":2,"of":5},"radio":"on","fw":"0123456789abcdef"}
```

`ripar` builds (Wi-Fi test link) add `wifi` and, while connected, `ip` between `radio` and `fw`:

```json
{"v":1,"screen":"HOME","paired":true,"k1":"0xAbCd...1234","radio":"on","wifi":"on","ip":"192.168.1.23","fw":"0123456789abcdef"}
```

| Key | Meaning |
|---|---|
| `v` | `1` (this document) |
| `screen` | `HOME`, `SCAN`, `REVIEW`, `PULSE`, `ARMED`, `QR`, `MESSAGE`, `MENU`, `BLE_PAIR` |
| `paired` | the device holds a companion pairing (pinned context, PROTOCOL.md §6). This is **not** the Bluetooth bond |
| `k1` | short K1 address: `0x` + first 4 + `...` + last 4 hex digits, EIP-55 case |
| `scan` | only on `SCAN`: `got` = parts received so far, `of` = parts in the sequence (0 before the first multipart part) |
| `radio` | the Bluetooth link: always `"on"` here (the same JSON read over Wi-Fi says `"off"` when Bluetooth is off) |
| `wifi` | `ripar` builds only: `"off"`, `"connecting"` or `"on"` ([WIFI_LINK.md](WIFI_LINK.md) §5.4) |
| `ip` | `ripar` builds only, while `wifi` is `"on"`: the device's IPv4 address |
| `fw` | firmware id: 16 hex digits, the first 8 bytes of the running image's SHA-256 (the same id as key 6 of the `ripar-pair` response) |
| `note` | optional, short: why the last line was not used, e.g. `ignored: not on SCAN (press SIGN on the device first)` or `part not used: bad QR part: ...` |

Clients must ignore unknown keys. To stay within 180 bytes the optional keys give way first: a `note` that does not fit next to `ip` drops `ip` for that status, and a note that still does not fit is cut. A notification carries the whole JSON when it fits into MTU - 3 bytes; otherwise it carries the first MTU - 3 bytes, and the phone must read the characteristic (a long read) for the whole value.

Screen codes and a suggested "Next on the device" text for the app:

| `screen` | Device shows | Next on the device |
|---|---|---|
| `HOME` | Home (also the "release = pairing QR" hold screen) | Press SIGN to start scanning |
| `SCAN` | viewfinder, parts received | (sending) keep the app open |
| `REVIEW` | the request, paged (in `ripar` builds also JOIN WI-FI / WI-FI ON: SIGN without pulse) | Read every page, then press SIGN |
| `PULSE` | pulse measurement | Hold your thumb on the sensor |
| `ARMED` | pulse OK | Press SIGN to sign |
| `QR` | the response (or keys-only pairing) QR; its text also arrives on TX | Press SIGN when done |
| `MESSAGE` | a refusal / information (or the self-test failure) | Read it, press SIGN |
| `MENU` | device actions menu | - |
| `BLE_PAIR` | the pairing screen (and the 6-digit code) | Compare the code, press SIGN to confirm |

### 4.6 PROV: phone → device (Wi-Fi test link, `ripar` builds only)

TEMPORARY TEST FEATURE; the full contract is [WIFI_LINK.md](WIFI_LINK.md) §3.

- **One write = one JSON document**, UTF-8, at most **512 bytes**: a plain Write (up to MTU - 3 bytes) or a long (prepared) write; an empty or longer value is refused (`Invalid Attribute Value Length`). Same authenticated-link rule as every other characteristic. Write Without Response is not offered.
- Payload `{"v":1,"ssid":"...","pass":"..."}`: strict JSON, exactly these members, `v` = 1, `ssid` 1..32 bytes without control characters, `pass` `""` (open network) or 8..63 printable ASCII characters.
- Taken only while the device shows **HOME** or **BLE PAIRING** (no code waiting); otherwise STATUS `note` says `wifi setup ignored: ...`. A malformed value gives `note` `wifi setup refused: <reason>` (never containing the password).
- The device then shows the review **JOIN WI-FI &lt;ssid&gt;?** (STATUS `screen` = `REVIEW`; the password is never displayed) and stores the network (NVS namespace `ripar-wifi`) only after the user presses **SIGN** on it (no pulse; hold 2 s rejects). Storing a network does not turn Wi-Fi on: that is **WI-FI ON** in the device menu.
- Long writes to PROV and RX cannot be interleaved (one prepared-write queue at a time; a mixed queue is refused with `Request Not Supported`).

## 5. Phone app flow

1. Scan for the service UUID `52495041-5200-4c49-4e4b-000000000001`. Show the name (`RIPAR-XXXX`) so the user can match it with the device screen.
2. Connect. Request MTU 247.
3. **First time:** the device asks for an encrypted link at once, so the OS starts pairing (or does so on the first protected access). The OS shows a 6-digit code; the user compares it with the device's pairing screen and confirms on both. Pairing only works while the device shows **BLE PAIRING**.
4. After **every** connection: enable notifications on STATUS and TX (CCCD writes), then read STATUS.
5. Tell the user what to do from `screen` (table above). To send a request: wait for `SCAN`, then write each UR part + `\n`, cycling multipart parts, until `screen` is no longer `SCAN`.
6. On `QR`: collect TX notifications up to `\n`; that is the response UR (the same text the QR shows).
7. `ripar` builds: optional Wi-Fi setup through PROV (§4.6, [WIFI_LINK.md](WIFI_LINK.md) §7).
8. Errors: an ATT error "Insufficient Authentication / Encryption" means the link is not paired: go back to step 3. A disconnect after about 30 s without pairing is the device dropping an unauthenticated link. If the device stops advertising, the radio is off (5 min idle, BLE OFF, PANIC or power): the user must turn it on again on the device. An idle app should not poll just to keep the radio on.

## 6. Builds and the radio check

```bash
cd firmware
pio run -e ripar           # QR + BLE fallback + the Wi-Fi test link (default, testing only)
pio run -e ripar-ble       # QR + BLE fallback
pio run -e ripar-airgap    # radio-free
xtensa-esp32s3-elf-nm -C .pio/build/ripar-airgap/firmware.elf | grep -E "esp_wifi_init|esp_bt_controller_init|esp_phy_enable|lwip"
```

| Build (2026-09-28) | RAM (static) | Flash | Radio symbols |
|---|---|---|---|
| `ripar-airgap` | 39 572 B (12.1 %) | 738 921 B (11.3 %) | `esp_wifi_init`, `esp_bt_controller_init`, `esp_phy_enable`, `lwip`: **0 matches** |
| `ripar-ble` | 66 568 B (20.3 %) | 1 345 909 B (20.5 %) | `esp_bt_controller_init`, `esp_bluedroid_init`, `esp_phy_enable` present (Bluetooth); `esp_wifi_init`, `esp_wifi_start`, `esp_netif`, `lwip`: 0 |
| `ripar` (test build) | 90 024 B (27.5 %) | 1 759 157 B (26.8 %) | Bluetooth as above, plus the Wi-Fi test link (`esp_wifi_init`, `lwip`, `mdns_init`, ...; [WIFI_LINK.md](WIFI_LINK.md) §2) |

Bluedroid also allocates heap while the radio is on (not measured on hardware).

## 7. Limits and what is untested

- **Untested on hardware:** everything radio-side - controller start / stop and repeated on-off cycles, advertising, pairing with real Android and iOS phones (numeric comparison dialogs, identity-address handling for "one bond"), the MITM flag the stack reports when a bonded phone re-encrypts (the firmware requires it; if a stack version did not report it, a bonded phone would be refused until it pairs again), GATT reads / writes / long writes, notifications, pacing under congestion, throughput, the 5-minute auto-off and power use; in `ripar` builds also the PROV characteristic (single and long writes, the JOIN WI-FI review it opens) and Bluetooth running next to Wi-Fi (coexistence). The portable parts (line reassembly, chunking, STATUS JSON incl. the Wi-Fi keys, idle timer, the pairing-outcome rule, the PROV JSON rules and the state-machine changes) are host-tested (`test_ble_link.cpp`, `test_wifi_link.cpp`).
- The stack is the Bluedroid host + controller bundled with Arduino-ESP32 2.0.17 (ESP-IDF 4.4), used through its ESP-IDF API; the framework's Arduino BLE C++ wrapper is not used because it cannot be torn down and started again at run time.
- The device address is the public one (no privacy / RPA); the advertising name changes per enable.
- The bond keys sit in NVS unencrypted (like the seed).
