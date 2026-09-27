# Ripar Wallet: Wi-Fi test link (v1)

> **TEMPORARY TEST FEATURE - NOT PART OF THE PRODUCT.** Ripar is an **air-gapped** signer: requests arrive as QR codes through the camera and every answer leaves as a QR code on the screen ([PROTOCOL.md](PROTOCOL.md) §1). The Wi-Fi link described here exists **only so the device can be tested** from a phone or a PC on the same network, and it will be removed. It lives entirely behind the build flag `RIPAR_WIFI`, which only the default test build `env:ripar` sets.
>
> **For a demo, a pitch or real funds, flash a build without it:**
>
> ```bash
> cd firmware
> pio run -e ripar-airgap -t upload   # the air-gapped pitch firmware: no Bluetooth, no Wi-Fi code at all
> pio run -e ripar-ble -t upload      # QR + the Bluetooth LE fallback only (docs/BLE_LINK.md), no Wi-Fi code
> ```
>
> Neither build contains a single Wi-Fi or lwIP symbol (checked on the linked binary, [§2](#2-builds-and-the-radio-check)). Flashing one of them over a `ripar` build leaves the stored Wi-Fi network in NVS (namespace `ripar-wifi`) but nothing reads it; use **FORGET WI-FI** first, or erase the flash, if the network's password matters.

The link carries exactly the text a QR code would carry, like the Bluetooth fallback ([BLE_LINK.md](BLE_LINK.md)): nothing about parsing, review, policy, pulse or SIGN changes.

**Status (2026-09-28):** the three builds compile and link; the portable logic (credential JSON, link code and lock-out, HTTP parsing and routes, STATUS JSON, state-machine changes) is host-tested in `firmware/test/host/test_wifi_link.cpp`. **Nothing radio-side has run on hardware yet**: provisioning over a real BLE link, association, DHCP, mDNS, HTTP over a real network, coexistence with BLE, reconnection and power use are all untested ([§8](#8-limits-and-what-is-untested)).

## Contents

1. [What it is](#1-what-it-is)
2. [Builds and the radio check](#2-builds-and-the-radio-check)
3. [Provisioning over Bluetooth (PROV)](#3-provisioning-over-bluetooth-prov)
4. [Turning Wi-Fi on and off](#4-turning-wi-fi-on-and-off)
5. [HTTP protocol](#5-http-protocol)
6. [Security model](#6-security-model)
7. [Phone / PC flow](#7-phone--pc-flow)
8. [Limits and what is untested](#8-limits-and-what-is-untested)

## 1. What it is

- A **third courier** for the same UR text, next to the camera (primary) and Bluetooth LE (fallback): `POST /rx` delivers UR parts into the same intake as a camera-decoded QR, only while the device is on SCAN; `GET /tx` returns the QR on screen; `GET /status` returns the same STATUS JSON as the BLE STATUS characteristic.
- **Provisioned over Bluetooth only.** The network (SSID + password) comes from the paired phone through the BLE `PROV` characteristic and is stored only after the user confirms it on the device.
- **Off unless chosen.** Wi-Fi starts only when a network is stored **and** the user chose **WI-FI ON** in the device menu. That choice is persisted, so a developer can keep Wi-Fi on across restarts.
- **Always visible.** While the Wi-Fi driver is alive, every screen shows a red **WIFI ON** badge (**BLE+WIFI** when Bluetooth is on too), Home says **NOT AIR-GAPPED** and shows the device's address and the link code.
- **Authenticated by the screen.** Every request needs the per-boot 8-digit **link code**, which is only ever shown on the device's own Home screen (never sent over any link).
- The device, its keys, the review and the SIGN key are exactly as untrusted-courier-proof as before: a Wi-Fi client can deliver request parts, read the screen state and the response QR. It cannot press keys, skip or shorten a review, sign, or read keys, the seed or the pinned context.

## 2. Builds and the radio check

| Env | Flags | Radios | Use |
|---|---|---|---|
| `ripar` (default) | `RIPAR_BLE=1`, `RIPAR_WIFI=1` | QR + Bluetooth LE fallback + **Wi-Fi test link** | development and testing only |
| `ripar-ble` | `RIPAR_BLE=1`, `RIPAR_WIFI=0` | QR + Bluetooth LE fallback | the previous default build |
| `ripar-airgap` | `RIPAR_BLE=0`, `RIPAR_WIFI=0` | none: QR only | **the air-gapped firmware (pitch, demos, funds)** |

`RIPAR_WIFI=1` requires `RIPAR_BLE=1` (the network is provisioned over Bluetooth; `include/device.h` refuses the combination at compile time). `ripar-ble` and `ripar-airgap` do not build `src/wifi_link.cpp` / `src/wifi_proto.cpp` and ignore the framework's `WiFi`, `WebServer` and `ESPmDNS` libraries (`lib_ignore`).

```bash
cd firmware
pio run -e ripar           # QR + BLE + Wi-Fi (test)
pio run -e ripar-ble       # QR + BLE
pio run -e ripar-airgap    # radio-free
xtensa-esp32s3-elf-nm -C .pio/build/<env>/firmware.elf | grep -cE "esp_wifi_init|esp_bt_controller_init|esp_phy_enable|lwip"
```

| Build (2026-09-28), of 327 680 B RAM / 6 553 600 B flash | RAM (static) | Flash | Radio symbols in the linked `firmware.elf` |
|---|---|---|---|
| `ripar` | 90 024 B (27.5 %) | 1 759 157 B (26.8 %) | Bluetooth (`esp_bt_controller_init`, `esp_bluedroid_init`), Wi-Fi (`esp_wifi_init`, `esp_wifi_start`, `esp_netif`, `lwip`, `mdns_init`) and the coexistence code (`coex_*`) |
| `ripar-ble` | 66 568 B (20.3 %) | 1 345 909 B (20.5 %) | Bluetooth only (`esp_bt_controller_init`, `esp_bluedroid_init`, `esp_phy_enable`); `esp_wifi_init`, `esp_wifi_start`, `esp_netif`, `lwip`, `mdns_init`: **0** |
| `ripar-airgap` | 39 572 B (12.1 %) | 738 921 B (11.3 %) | `esp_wifi_init`, `esp_bt_controller_init`, `esp_phy_enable`, `lwip`: **0 matches** |
| `chk_device` (bring-up check) | 35 828 B (10.9 %) | 598 609 B (9.1 %) | **0 matches** |

The Wi-Fi test link costs about 23 KB of static RAM and 413 KB of flash; at run time the Wi-Fi driver and lwIP also allocate heap while Wi-Fi is on (not measured on hardware).

**Removing the feature for good:** delete `src/wifi_link.cpp`, `src/wifi_proto.cpp`, `include/wifi_link.h`, `include/wifi_proto.h`, `test/host/test_wifi_link.cpp`, the `#if RIPAR_WIFI` blocks (`flows.cpp`, `ble_link.cpp`, `keys.cpp`, `device.h`), the `Job::WifiJoin` / `Job::WifiOn` / `Act::Confirm` / `MENU_WIFI*` values in `fsm.h` and the `wifi` / `ip` STATUS keys; or simply make `ripar-ble` the default env.

## 3. Provisioning over Bluetooth (PROV)

### 3.1 The characteristic

`ripar` builds add a fifth characteristic to the RIPAR LINK service ([BLE_LINK.md](BLE_LINK.md) §4.2):

| Characteristic | UUID | Properties | Direction |
|---|---|---|---|
| PROV | `52495041-5200-4c49-4e4b-000000000005` | Write | phone → device |

- Same rules as RX: the value needs the encrypted, MITM-authenticated link of the bonded phone at the ATT layer, and the firmware refuses every write from a link that did not complete an authenticated pairing / re-encryption (`Insufficient Authentication`, 0x05). `ripar-ble` does not have this characteristic: a phone can detect Wi-Fi support by looking for it.
- **One write = one JSON document**, at most **512 bytes**: a plain Write (up to MTU - 3 bytes, 244 with MTU 247) or a long (prepared) write. An empty value is refused with `Invalid Attribute Value Length` (0x0D), a long write beyond 512 bytes with `Prepare Queue Full` (0x09). A write succeeds as soon as the value is taken; the result shows in STATUS (below).

### 3.2 Payload

UTF-8, strict JSON (RFC 8259; no duplicate or unknown members, no trailing data):

```json
{"v":1,"ssid":"HomeNet","pass":"correct horse battery"}
```

| Member | Rule |
|---|---|
| `v` | the number `1` |
| `ssid` | 1..32 bytes (after JSON unescaping, UTF-8), no control characters |
| `pass` | `""` for an open network, or 8..63 printable ASCII characters (WPA2/WPA3-Personal passphrase) |

### 3.3 What the device does

1. The value is parsed at once. If it is refused, STATUS `note` says why (`wifi setup refused: pass must be empty (open network) or 8..63 characters`, cut if it does not fit the 180 bytes); the text never contains the password.
2. It is only taken while the device shows **HOME** or **BLE PAIRING** (without a pairing code waiting). On any other screen (a scan, a review, a QR, the menu, ...) it is dropped with the note `wifi setup ignored: the device must show HOME (or BLE PAIRING)`: a phone can never push a review on top of a request.
3. The device opens the review **JOIN WI-FI &lt;ssid&gt;?**: the network name (bytes that are not printable ASCII shown as `?`), `Password: set (never shown)` or `NONE: open network`, the network it replaces (if another one is stored), whether Wi-Fi is on, and that signing is unchanged. **The password is never displayed.** STATUS `screen` is `REVIEW`.
4. The user reads every page and presses **SIGN** to store it (**no pulse**: this is a device setting, nothing is signed). **Hold 2 s = reject**; the 120 s timeout also rejects. Nothing is stored before the press; a rejected network is wiped from RAM.
5. Stored: NVS namespace **`ripar-wifi`** (keys `ssid`, `pass`), separate from the wallet's `ripar` namespace (seed) and its context. Written, read back and compared. The screen says **WI-FI SAVED**. If Wi-Fi was on, it reconnects to the new network at once; otherwise Wi-Fi stays **off**.

Only one network is stored; a new one replaces it.

## 4. Turning Wi-Fi on and off

| Action | On the device | Pulse? |
|---|---|---|
| Wi-Fi on | Home: hold 2 s and release → pairing QR; hold 2 s → **DEVICE ACTIONS** → **WI-FI ON** → review **WI-FI ON: TURN WI-FI ON?** ("Ripar is not air-gapped while it is on", the network, "stays on also after a restart") → press SIGN | no |
| Wi-Fi off | menu **WI-FI OFF** | no |
| Forget the network | menu **FORGET WI-FI**: Wi-Fi off, the network and the WI-FI ON choice erased (`ripar-wifi` namespace cleared) | no |
| PANIC | turns Wi-Fi off (and Bluetooth) before the panic is signed, and clears the WI-FI ON choice | no |

- **WI-FI ON is persisted** (NVS `ripar-wifi` key `on`). At every boot, after the self-test and the keys (never on a failed self-test), a device with a stored network and the choice set starts Wi-Fi by itself; Home then shows NOT AIR-GAPPED and the badge from the first screen on. WI-FI OFF, FORGET WI-FI and PANIC clear the choice. If the start fails at boot, the device says **WI-FI NOT STARTED** and the choice stays set.
- WI-FI ON without a stored network shows **NO WI-FI NETWORK** (provision one first, §3).
- **Off** = HTTP server closed, mDNS stopped, network dropped, the driver's RAM copy of the password erased, `esp_wifi_stop` + `esp_wifi_deinit`. The badge follows the driver (`esp_wifi_get_mode()` succeeds only while it is initialised), not a flag: if turning it off ever failed, the badge would stay.
- **No idle auto-off** (unlike Bluetooth): a developer may keep it on. It is not tied to the Bluetooth radio either: Bluetooth may be off (after its 5-minute idle timeout, or BLE OFF) while Wi-Fi stays on, and both may be on together.
- **Coexistence.** The framework's prebuilt ESP-IDF 4.4 for the ESP32-S3 is built with Wi-Fi / Bluetooth software coexistence (`CONFIG_ESP32_WIFI_SW_COEXIST_ENABLE=1`), so both links are allowed at the same time; Wi-Fi then stays in modem sleep (the Arduino default, required by coexistence). Not measured on hardware.
- **Entropy.** While Wi-Fi (or Bluetooth) is up, `trng_fill()` never toggles the SAR-ADC entropy source (`keys.cpp`): the RF subsystem feeds the RNG. The link code is drawn before the radio starts.

**Home while Wi-Fi is on** (one amber line above the key hints):

| State | Home line |
|---|---|
| connecting / reconnecting | `WI-FI connecting...  CODE 1234 5678` (or `network not found`, `connection refused (password?)`, `connection lost`) |
| connected | `192.168.1.23  CODE 1234 5678` |

The device retries a failed connection every 20 s. On SCAN the hint says the request can also come from the phone (`BLE / Wi-Fi`).

## 5. HTTP protocol

### 5.1 Connection

| | |
|---|---|
| Address | `http://ripar-xxxx.local/` (mDNS; `xxxx` = the last two bytes of the Wi-Fi MAC, lower-case hex, stable per device) or `http://<IP>/` (Home; STATUS `ip`) |
| Port | 80, plain HTTP/1.1 or 1.0 (no TLS) |
| mDNS | host `ripar-xxxx.local`, service `_http._tcp` port 80, announced once connected |
| Connections | one request per connection (`Connection: close`), one connection served at a time; the whole request must arrive within **5 s** of the connection (else `408`) |
| Limits | request line + headers at most **2048 bytes** (`431`); body at most **16384 bytes** (`413`), only with `Content-Length` (`411` without; `Transfer-Encoding` → `501`) |
| Caching | every response has `Cache-Control: no-store` |
| CORS | none: browsers cannot call it from a web page (the custom header needs a preflight that is never approved). Use the app, `curl` or a script. |

### 5.2 Authentication: the link code

- Every request needs the header **`X-Ripar-Code: <8 digits>`**: the link code shown on the device's Home screen (`CODE 1234 5678` → `12345678`).
- The code is drawn from the TRNG once per boot, when Wi-Fi is first turned on, and stays the same until the device restarts (WI-FI OFF / ON keeps it). It is **only shown on the device screen**: never in STATUS, never over Bluetooth or HTTP, never in the serial log.
- It is checked **before** the route is looked at and before any body byte is used, in constant time. A missing or wrong code is `401` (the routes are not revealed: `/anything` without the code is `401`, not `404`).
- **Lock-out:** 3 wrong codes are free; each further wrong code locks the link for 1 s, 2 s, 4 s, ... up to **300 s**. While locked every request gets `429` with `Retry-After` and no code is compared at all. A correct code resets the count. The count lives for the whole boot (WI-FI OFF / ON does not reset it).

### 5.3 Routes

| Request | Answer |
|---|---|
| `GET /status` | `200`, `application/json`: the STATUS JSON (§5.4) |
| `POST /rx`, body `text/plain`: one or more UR lines | on SCAN: `200` + STATUS JSON after the lines were taken. Not on SCAN: **`409`** + STATUS JSON with `note` (`ignored: not on SCAN (press SIGN on the device first)`), nothing taken |
| `GET /tx` | `200`, `text/plain`: the UR text of the QR on screen + `\n` (a signed response or the keys-only `ripar-pair`; single part, upper case, exactly what the QR encodes). **`204`** (no body) when no QR is on screen |
| other paths | `404`; wrong method `405` with `Allow` |

Errors other than `409` carry `{"error":"<text>"}`. The query string is ignored.

**`POST /rx` body:** lines separated by `\n` (a trailing `\r` is dropped, empty lines are skipped, the last line needs no `\n`). Each line is one UR part (`UR:<TYPE>/<BYTEWORDS>` or `UR:<TYPE>/<SEQ>-<LEN>/<BYTEWORDS>`, at most 4096 bytes; longer lines are skipped) and goes into `intake_part()` in order, exactly like a camera-decoded QR part ([BLE_LINK.md](BLE_LINK.md) §4.3). A body with no usable line is `400`. Once the request is complete (or the scan ends) the remaining lines are not used, and the answer shows the new `screen` (e.g. `REVIEW`). Sending all parts of a multipart request in one POST is fine; resending them is harmless (fountain code).

### 5.4 STATUS JSON

The same document as the BLE STATUS characteristic ([BLE_LINK.md](BLE_LINK.md) §4.5), at most **180 bytes**; `ripar` builds add two keys:

```json
{"v":1,"screen":"SCAN","paired":true,"k1":"0xAbCd...1234","scan":{"got":2,"of":5},"radio":"off","wifi":"on","ip":"192.168.1.23","fw":"0123456789abcdef"}
```

| Key | Meaning |
|---|---|
| `radio` | the **Bluetooth** link: `"on"` / `"off"` (always `"on"` when read over Bluetooth) |
| `wifi` | `"off"`, `"connecting"` (no address yet, or reconnecting) or `"on"` (connected). Only in `ripar` builds |
| `ip` | the device's IPv4 address while `wifi` is `"on"` |

The other keys (`v`, `screen`, `paired`, `k1`, `scan`, `fw`, `note`) are unchanged. To stay within 180 bytes the optional keys give way first: a `note` that does not fit next to `ip` drops `ip` for that one status (the address is in the next one again); a note that still does not fit is cut. Clients must ignore unknown keys.

### 5.5 Examples

```bash
CODE=12345678   # from the device's Home screen
curl -s -H "X-Ripar-Code: $CODE" http://ripar-3f9a.local/status
# press SIGN on the device (SCAN), then send the parts (one per line):
curl -s -H "X-Ripar-Code: $CODE" -H "Content-Type: text/plain" --data-binary @request_parts.txt http://ripar-3f9a.local/rx
# review, pulse and SIGN on the device, then:
curl -s -H "X-Ripar-Code: $CODE" http://ripar-3f9a.local/tx
```

`curl -d` would send `application/x-www-form-urlencoded`; the device ignores the content type, but keep `--data-binary` so the newlines survive.

## 6. Security model

What the link adds, honestly:

- **Not air-gapped while it is on.** The Wi-Fi stack (driver + lwIP + mDNS + the small HTTP server) runs on the same chip as the keys and is reachable from the local network. The code that parses network input before authentication is the portable `wifi_proto.cpp` HTTP reader (bounded, host-tested); lwIP and the Wi-Fi driver below it are the framework's.
- **What a client with the code can do:** exactly what a companion showing QR codes can do. Deliver request parts (only while the user has the device on SCAN; every request still needs the full review, the pulse and SIGN on the device), read STATUS (screen, scan progress, short K1, pairing flag, firmware id, address) and read the response QR on screen. **No route exposes keys, the seed, the pinned context or the stored network**, and nothing can press a key, turn a radio on, or change a setting.
- **Plain HTTP, no TLS.** Anyone who can read the network traffic (an open network, or someone else holding the WPA2-Personal passphrase who captured this device's handshake) can read the link code, the UR requests and the response URs. Responses are public by design (they are relayed on-chain), but co-sign and deny responses include the raw 12-byte pulse evidence ([PROTOCOL.md](PROTOCOL.md) §5). With the sniffed code such a listener can only do what a courier can do (above). Use a network you control.
- **Without the code:** `401`, then the lock-out (§5.2): 3 free guesses, then at most one guess per 300 s after 13 failures. An 8-digit code (10^8) cannot be brute-forced that way; the lock-out can, however, be used by someone on the network to keep the device locked for the developer (restart = new count and new code).
- **Denial of service.** One connection at a time with a 5 s limit: a local attacker can keep the link busy. The device UI and signing are unaffected (the server is polled without blocking; the camera and BLE paths work as before).
- **No browser access** (no CORS, custom header): a web page in someone's browser on the network cannot call the link cross-origin. A DNS-rebinding page could send same-origin requests, but still needs the code (and meets the lock-out).
- **Credentials at rest.** The network name and password sit in NVS namespace `ripar-wifi`, unencrypted, like the seed ([FIRMWARE.md](FIRMWARE.md) "Known limitations"). FORGET WI-FI erases the keys, but NVS keeps old copies until its pages are recycled; erase the flash to be sure. The Wi-Fi driver itself is started with `WiFi.persistent(false)`: it never writes the network to its own NVS namespace, and its RAM copy is erased when Wi-Fi goes off.
- **Presence.** While on, the device answers mDNS as `ripar-xxxx.local` (a stable name derived from its MAC, which the network sees anyway) and announces `_http._tcp`.
- **Provisioning** only comes from the bonded, authenticated Bluetooth phone and is only stored after SIGN on the device; the phone cannot turn Wi-Fi on (only the menu can).
- **The serial log** prints status lines only (`wifi ON as ripar-xxxx.local (network "...")`, connected / address, `wifi http GET /status -> 200`, wrong-code counts). Never the password, the link code or request contents.

## 7. Phone / PC flow

1. Bluetooth first ([BLE_LINK.md](BLE_LINK.md) §5): BLE LINK on the device, pair the phone, connect.
2. If the service has the PROV characteristic, offer "Wi-Fi setup": ask for the network, write `{"v":1,"ssid":...,"pass":...}` to PROV while the device shows HOME or BLE PAIRING. Watch STATUS: `screen` becomes `REVIEW` (tell the user to read it and press SIGN on the device) or `note` explains a refusal.
3. Tell the user to choose **WI-FI ON** in the device menu and confirm with SIGN.
4. Wait for STATUS `wifi` = `"on"` and read `ip` (over BLE), or resolve `ripar-xxxx.local`. Ask the user for the **8-digit code on the device's Home screen** (it is never sent over any link).
5. From then on the phone (or a PC) can use HTTP: poll `GET /status` (e.g. every 0.5-1 s while a request is in flight), send parts with `POST /rx` once `screen` is `SCAN`, fetch the response with `GET /tx` once `screen` is `QR`.
6. `401`: wrong code (the device restarted? read it again). `429`: wait `Retry-After`. `409`: the device is not on SCAN (the user must press SIGN on Home first). No answer: Wi-Fi is off (WI-FI OFF, PANIC, restart without the persisted choice) or the device is on another network.

## 8. Limits and what is untested

- **Untested on hardware:** everything radio-side - the PROV write over a real BLE link, association (WPA2 / WPA3 / open), DHCP, the 20 s retry, mDNS resolution from Android / iOS / desktop, HTTP from real clients, coexistence with an active BLE link (throughput, BLE connection stability while Wi-Fi scans), repeated WI-FI ON / OFF cycles (driver init / deinit, the server socket, mDNS start / stop), the start at boot, heap use of lwIP + the Wi-Fi driver next to Bluedroid, and power use. The portable parts (PROV JSON, link code, lock-out, HTTP reader and routes, STATUS JSON, state machine) are host-tested.
- IPv4 only; one network; no enterprise (802.1X) networks; no static IP; the passphrase must be 8..63 printable ASCII characters (no 64-hex-digit PSK).
- Android apps do not resolve `.local` names everywhere: use the address from STATUS `ip` / Home.
- The link code changes at every restart; the lock-out count too.
- Stack: Arduino-ESP32 2.0.17 `WiFi` (station), `ESPmDNS` and a `WiFiServer` socket; the framework's `WebServer` class is not used, because it reads a POST body of any length, before any handler and so before authentication, with blocking waits on the caller's task.
