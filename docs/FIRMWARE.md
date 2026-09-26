# Ripar Wallet: firmware guide

The firmware turns a Waveshare ESP32-S3-LCD-2 into an air-gapped signer. It has no radio. Requests arrive as QR codes through the camera, and every answer leaves as one QR code on the screen. Nothing is signed until the user has seen every line of the review, held a thumb on the pulse sensor until a live pulse is measured, and then pressed SIGN.

- **Protocol:** byte-exact contract in [`PROTOCOL.md`](PROTOCOL.md).
- **Wiring:** full pin list in [`WIRING.md`](WIRING.md).
- **Source:** `firmware/` (PlatformIO, Arduino-ESP32 2.0.17 / ESP-IDF 4.4).

> **Status (2026-09-27).** The full firmware builds and links. The host tests cover the portable code, including the screen state machine, the signing gate and the SIGN step (byte-equal to the Python reference), and they pass. The findings of the second security and conformance review (panic epoch, re-pairing, key presses across screens, device-time ratchet, sentinel, revoke display) are fixed in code and tests; what stays open is listed under [Known limitations](#known-limitations). The QR frames drawn by `companion_lite.html` decode with the firmware's own quirc + UR decoder + parser on the PC. **Nothing in this guide has been checked on a real board yet**: the display rotation, the camera orientation, the pulse-sensor tuning and the key timings are all untested. See [Known limitations](#known-limitations).

## Contents

1. [Hardware and wiring](#1-hardware-and-wiring)
2. [Build and test](#2-build-and-test)
3. [Flash over USB-C](#3-flash-over-usb-c)
4. [First boot](#4-first-boot)
5. [Screens and keys](#5-screens-and-keys)
6. [Walkthrough](#6-walkthrough)
7. [Security model](#7-security-model)
8. [Known limitations](#known-limitations)
9. [Source map](#9-source-map)

## 1. Hardware and wiring

| Part | Connection | Notes |
|---|---|---|
| Waveshare ESP32-S3-LCD-2 | - | ESP32-S3R8 (8 MB octal PSRAM), 16 MB flash, 2" ST7789 LCD used landscape at 320×240 |
| OV5640 camera | 24-pin FPC on the back | grayscale QVGA, powered down between scans |
| MAX30102 pulse sensor | VIN → 3V3 (P2-1), GND → P2-2, SDA → **GPIO48** (P2-6), SCL → **GPIO47** (P2-5), INT open | shares the I2C bus with the on-board IMU (0x6B). **Move its pull-up jumper to 3.3 V.** |
| Buzzer (active, 3.3 V) | + → **GPIO18** (P1-6), − → GND | use an S8050 + 1 k base resistor for a 5 V buzzer or one drawing more than 20 mA |
| SIGN key | the board's **BOOT key (GPIO0)**, pressed by the printed Sign_Pin | a strapping pin: **never hold it while powering on** |
| Battery | 18650 → TP4056 → latching switch → board BAT connector | the gauge reads GPIO5 through the board's 200 k / 100 k divider |

With the camera attached, the only free signals are GPIO18, GPIO43 and GPIO44, plus the shared I2C bus. `firmware/include/board.h` holds every pin.

## 2. Build and test

Requirements: PlatformIO Core and Python 3 (standard library only). `lib_deps` fetches LovyanGFX once. The quirc QR decoder is vendored in `firmware/lib/quirc`.

```bash
cd firmware
pio run -e ripar            # full firmware -> .pio/build/ripar/firmware.bin
pio run -e chk_device       # device bring-up check (no signing code), see test/device/check_main.cpp
python test/host/run_host_tests.py          # portable modules, MinGW / any g++ as C++14
python tools/make_request.py selftest       # companion tool: build -> simulate -> verify, tamper tests
python tools/make_request.py check-vectors  # test/host/vectors_protocol.h matches the Python reference
```

- Last full build (clean, 2026-09-27): `RAM 11.7 % (38 180 of 327 680 bytes)`, `Flash 11.0 % (719 593 of 6 553 600 bytes)` in the default 16 MB partition table.
- `pio run -t compiledb` without the same `PLATFORMIO_BUILD_FLAGS` as the last build changes the configuration hash, and PlatformIO then empties `.pio/build/<env>`: build again afterwards.
- A low-disk PC can add `PLATFORMIO_BUILD_FLAGS=-pipe` so that GCC keeps its temporary files in memory. Run one `pio` build at a time.
- Optional build flags (add them to `build_flags`):

| Flag | Default | Meaning |
|---|---|---|
| `RIPAR_LCD_ROTATION` | 1 | Use 3 if the screen is upside down. |
| `RIPAR_CAM_VFLIP` / `RIPAR_CAM_HMIRROR` | 1 / 0 | Viewfinder orientation. QR decoding works either way. |
| `RIPAR_CAM_AE_LEVEL` | -2 | Camera exposure. Go darker (down to -4) if phone screens wash out. |
| `RIPAR_LED_CHALLENGE` | 0 | 1 also requires the MAX30102 LED-drive liveness challenge before SIGN is armed. Not tested on hardware. |
| `RIPAR_TIME_FLOOR` | 2026-09-26 00:00 UTC | The earliest "now" the device assumes (see [co-sign expiry](#co-sign)). |

## 3. Flash over USB-C

Use the board's own USB-C port, not the charge-only TP4056 port. Never plug both at once.

```bash
cd firmware
pio run -e ripar -t upload          # builds if needed, then flashes over the native USB (USB-Serial/JTAG)
pio device monitor -b 115200        # optional: status lines (self-test, K1 address, "output <type>")
```

**If the upload cannot connect** (a crashed app, or a USB port that no longer enumerates), use ROM download mode:

1. Hold **BOOT**.
2. Press and release **RST**.
3. Release **BOOT**. The chip now waits in ROM download mode, and the screen stays dark.
4. Run `pio run -e ripar -t upload` again.
5. Press **RST** to start the new firmware.

A normal upload does not touch the NVS partition, so the seed and the pairing survive re-flashing.

> **`pio run -t erase` erases the whole flash, including the seed.** The device then creates new keys, which means a new K1 address and a new vault owner. There is no seed backup yet (see [Known limitations](#known-limitations)). Only erase a unit that holds no funds.

## 4. First boot

| Step | What you see | What happens |
|---|---|---|
| 1 | RIPAR logo, "starting..." | The display, key, buzzer, pulse sensor (I2C 0x57) and camera are probed. |
| 2 | "self-test: crypto vectors..." | `keys_selftest()` checks the on-device crypto against published vectors (RFC 6979 P-256, the secp256k1 "Satoshi" vector, BIP-32 and SLIP-10 test vector 1) and cross-checks it with mbedTLS. |
| 3 | First run only: "NEW DEVICE: creating keys..." | 64 TRNG bytes, 1.5 s of raw MAX30102 samples, camera frames and timing jitter are hashed into the seed input. `keys_create()` adds 64 more TRNG bytes. The seed goes to NVS, and the self-test runs again, now signing and verifying with the new device keys. |
| 4 | Home screen | Shows the short K1 address, battery level and **NOT PAIRED**. |

If the self-test fails, the screen shows **SELFTEST FAIL**, the failed checks and "SIGNING IS DISABLED". This state is final until the next reset: no key does anything and nothing is ever signed. The serial log lists the same lines.

The pulse sensor and the camera are optional at boot:
- Without the camera the device cannot scan anything.
- Without the pulse sensor it can still answer deny requests and PANIC, but it can sign nothing that needs the pulse.

## 5. Screens and keys

There is one key, SIGN (BOOT). It produces three events:
- **press**: released within 1 s.
- **hold 2 s**: fires while the key is held, at 2 s.
- **hold 5 s**: fires at 5 s. A 5 s hold also fires "hold 2 s" first.

A release between 1 s and 2 s does nothing.

**A press or hold belongs to the screen on which it began.** After any screen change the key does nothing until it has been released: queued events are dropped, a press that is still held is swallowed until release (`io_flush`), and the state machine also ignores key events until it has seen the key up on the new screen. The only exception is the Hold screen on Home, which exists for the hold that opened it. So a hold that cancels a screen never turns into a PANIC on Home, a hold carried into a co-sign review never files a deny, and a SIGN press that began while the pulse was being measured does not sign when ARMED appears: press again.

Every screen except Home returns to Home after 120 s without a key press. The buzzer gives:
- a short tick for each new QR part and each heartbeat;
- a rising two-tone for OK;
- a falling two-tone for refused or error.

| Screen | Shows | press | hold 2 s | hold 5 s |
|---|---|---|---|---|
| **Home** | K1 (short), battery, PAIRED / NOT PAIRED | scan a request | opens the Hold screen | (only through the Hold screen) |
| Hold (on Home) | "RELEASE = PAIRING QR", keep holding = PANIC | - | (release before 5 s = **pairing QR**, keys only) | **PANIC**, signed at once |
| **Scan** | camera viewfinder, multipart progress bar, hint | - | cancel → Home | - |
| **Review** | every line of the request, paged by display row; arrows and a scrollbar whenever rows are hidden | next page; on the last page: continue (→ Pulse), or sign a deny; refused → Home | co-sign review: **DENY**; other reviews: cancel → Home | - |
| **Pulse** | heart, bpm, beats n/5, progress ring | ignored (error beep) | cancel → Home | - |
| **Armed** | "PULSE OK - press SIGN" | **SIGN**, only while the pulse still counts as live | cancel → Home | - |
| **QR** | the signed response | done → Home | done → Home | - |
| Message | refusal or error, with the exact reason | → Home | → Home | - |
| Pairing QR | `ripar-pair` with K1 + P1 + firmware id (nothing signed, nothing pinned) | → Home | device menu | - |
| Device menu | REVOKE the last mandate / REOPEN the agent lane / BACK | next item | select | - |

The review shows at most 9 rows at a time. Each press moves the page by 8 rows, overlapping one row, so every row appears on screen. The last-page footer (for example "press = PULSE + SIGN") appears only once the last row has been drawn. Until then the footer reads "press = more", and SIGN cannot be armed.

A refused request still opens its review. Its first line is **REFUSED** in red, with the policy's exact reason: wrong chain, a contract that is not pinned, an expiry too far ahead, UNKNOWN CALLDATA, MANDATE WITHOUT PULSE CO-SIGN, and so on. A request that cannot even be parsed goes straight to a message screen with the parser's reason.

## 6. Walkthrough

Two tools run on the online computer, which is untrusted:
- `firmware/tools/make_request.py` builds requests and verifies responses.
- `firmware/tools/companion_lite.html` shows the request QR codes and prepares the verify command.

The commands below use bash syntax (Git Bash on Windows works) and are run from `firmware/`. Addresses in `<...>` are your deployed contracts.

**companion_lite.html:**
1. Open the file in a browser. It needs cdnjs for its QR encoder.
2. Paste the output of `make_request.py build` (or load the saved file) and press **Show QR**. Multipart requests loop at about 300 ms per frame; the slider changes the speed.
3. Point the device at it after pressing SIGN on the Home screen.
4. Read the device's answer with any QR reader (a phone camera works), paste it in section 3, and run the command the page prints.

Before using real hardware, `python tools/make_request.py simulate @req.txt` plays a demo device (fixed demo seed, **no pulse check and no pinned-context policy**). Use it to check a request file and your verify command.

### Pairing

Pairing pins the chain and contracts that every later request is checked against.

```bash
python tools/make_request.py build pair chainId=10143 registry=<REGISTRY> enforcer=<PULSE_COSIGN_ENFORCER> \
    sentinel=<SENTINEL> relay=<RELAY> vault=<VAULT> > req_pair.txt
```

- `manager` defaults to the MetaMask v1.3.0 DelegationManager.
- `now` (the companion clock) is added automatically.

On the device:
1. Scan the request.
2. Review every contract to pin. Anything missing is shown as a warning, for example "not set - no reopen, mandates without a sentinel lane".
3. Press on the last page, hold your thumb on the sensor, and press SIGN when the screen says so.

P1 and K1 both sign `BindDevice(K1, P1)`. The device stores the new context and only then shows the QR. If NVS fails, the signature is withheld.

**Pairing again** shows "REPLACES the current pairing" and one red **CHANGES** line per pinned value that changes (old → new). While the device remembers a mandate it signed, a pairing that changes the chain, DelegationManager, PulseCosignEnforcer or vault is refused with **REVOKE FIRST**: revoke that mandate (device menu), then pair again. Sentinel, relay and registry may change.

**Counter floors** (`minEpoch=<n> reopenNonce=<n>`, pair-req keys 10 and 11) can only raise the device's panic epoch and reopen nonce. The review shows both counters and marks a raise in amber. Use them when the device lost its context (the boot screen then says **PAIRING LOST**), see [Known limitations](#known-limitations).

Save the answer (`UR:RIPAR-PAIR/...`) as `pair.txt`, then verify it:

```bash
python tools/make_request.py parse @pair.txt --req @req_pair.txt      # exit 0 = VERIFIED
```

`pair.txt` now holds the device's K1 address and P1 key. Every later `parse` uses it through `--pair @pair.txt`.

The **pairing QR** from the Home screen (hold 2 s, release) contains the same keys **without** signatures, and it pins nothing.

### Mandate (K1 signs a delegation)

```bash
P1=$(python tools/make_request.py parse @pair.txt | python -c "import json,sys; print(json.load(sys.stdin)['p1Key'])")
python tools/make_request.py build mandate chainId=10143 manager=0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3 \
    delegate=<AGENT_REDEEMER> delegator=<VAULT> salt=1 agentId=42 label="demo agent" \
    "caveats=[{\"kind\":\"pulse\",\"enforcer\":\"<PULSE_COSIGN_ENFORCER>\",\"p1Key\":\"$P1\",
      \"token\":\"0xa9012a055bd4e0eDfF8Ce09f960291C09D5322dC\",\"perTxAutoCap\":5000000,
      \"periodAutoCap\":20000000,\"period\":86400,\"epoch\":0,\"newPayeeNeedsHuman\":true,\"sentinel\":\"<SENTINEL>\"}]" \
    > req_mandate.txt
```

The device signs a mandate only if:
- it has **exactly one** caveat on the pinned PulseCosignEnforcer, naming **this** device's P1 key, an epoch **exactly equal** to the device's panic floor, and exactly the pinned sentinel (the zero address when none is pinned);
  - the panic floor is 0 on a new device and N after the device signed `Panic(N)` (or after a pairing floor of N). The review shows it as "(= panic floor)"; any other epoch is refused, because the device's next PANIC (floor + 1) could not kill a higher one;
- every other caveat is one it can decode and show;
- the delegator is the pinned vault;
- the delegate is not ANY_DELEGATE.

The review shows every decoded caveat field.

After pulse + SIGN, the device stores `lastDelegationHash` (what REVOKE revokes) and the agent id (what a deny is filed against), then shows an `eth-signature`.

```bash
python tools/make_request.py parse @mandate.txt --req @req_mandate.txt --pair @pair.txt   # prints delegationHash
```

### Co-sign

A co-sign is a payment the agent cannot make alone.

```bash
EXP=$(( $(date +%s) + 3600 ))      # must be at most 7 days after the device's "not before" time
python tools/make_request.py build cosign chainId=10143 enforcer=<PULSE_COSIGN_ENFORCER> \
    delegationHash=0x<delegationHash from the mandate> delegator=<VAULT> redeemer=<AGENT_REDEEMER> \
    target=0xa9012a055bd4e0eDfF8Ce09f960291C09D5322dC value=0 nonce=1 expiry=$EXP \
    'transfer={"to":"<PAYEE>","amount":25000000}' \
    'ai={"text":"pay invoice 17","claims":{"to":"<PAYEE>","token":"0xa9012a055bd4e0eDfF8Ce09f960291C09D5322dC","amount":25000000}}' \
    > req_cosign.txt
```

The review shows:
- the action;
- the amount, using the firmware token table (AUSD has 6 decimals, so 25000000 is shown as "25 AUSD");
- the full payee address, chain, vault, redeemer and mandate hash;
- expiry in UTC, and the nonce;
- the AI claim check (MATCH or MISMATCH);
- anything the companion added, marked "(companion)".

After pulse + SIGN, P1 signs `HumanApproval`, with `presenceHash = sha256(evidence12 ‖ salt16)` and a fresh salt.

```bash
python tools/make_request.py parse @cosign.txt --req @req_cosign.txt --pair @pair.txt   # prints caveatArgs
```

<a id="co-sign"></a>**Expiry and device time.** The device has no clock. Its "not before" time is the later of:
- the build floor;
- the pairing time (key 9);
- the expiry of each co-sign it signed, but each co-sign moves the time forward by **at most 1 day**, so approved co-signs cannot push the device time (and with it the 7-day expiry window) far ahead of real time.

A device whose time has fallen more than a week behind (no co-signs for a while, or fewer than about one a day) refuses every co-sign until it is paired again, because pairing updates the time. A pairing time more than 30 days after the device time is shown in red.

### Deny (report the agent)

On a co-sign review, **hold 2 s**. The device builds the deny itself:
- the pinned chain and relay;
- the agent of the pinned mandate;
- `requestHash = hashStruct(HumanApproval)` of the request it just reviewed.

It shows that deny. A press signs it, **without the pulse**, because a deny can only restrict.

```bash
python tools/make_request.py parse @deny.txt --req @req_cosign.txt --pair @pair.txt --contract <RELAY>
```

A deny request from the companion (`build deny chainId=... relay=... agentId=... requestHash=...`) is refused unless its agent is the pinned one. It is reviewed and signed the same way.

### Privy authorization

```bash
python tools/make_request.py build privy 'json={"body":{"policy_ids":["pol9x2k4m8"]},"headers":{"privy-app-id":"cm0appid1234"},"method":"PATCH","url":"https://api.privy.io/v1/wallets/wl8yz4c2rq0q1cdz2q8a4","version":1}' > req_privy.txt
python tools/make_request.py parse @privy.txt --req @req_privy.txt --pair @pair.txt
```

- Only the two allow-listed request shapes are accepted: a wallet's signers or policies, and a key quorum. Everything else is refused.
- Every value is shown in full. Key-quorum keys are marked THIS DEVICE or OTHER P-256 KEY.
- After pulse + SIGN, P1 signs `sha256` of the exact JSON bytes and returns a DER signature.

### PANIC, revoke, reopen

These are started on the device and use the **pinned** contracts only.

| Action | How | Pulse? | Verify |
|---|---|---|---|
| PANIC | Home: hold SIGN. At 2 s the Hold screen appears; keep holding to 5 s. Signs `Panic(minEpoch + 1)` at once; refused if not paired. A hold that began on another screen never panics | no | `parse @panic.txt --pair @pair.txt --chain 10143 --contract <PULSE_COSIGN_ENFORCER>` |
| Revoke | Home: hold 2 s and release, then hold 2 s on the pairing QR → **REVOKE**. Revokes the last mandate this device signed, then forgets it: scan the QR before leaving the screen | yes | `parse @revoke.txt --pair @pair.txt --chain 10143 --contract <PULSE_COSIGN_ENFORCER>` |
| Reopen | same menu → **REOPEN**. Nonce = last + 1, never reused; needs a pinned sentinel and vault | yes | `parse @reopen.txt --pair @pair.txt --chain 10143 --contract <SENTINEL>` |

Relay a PANIC QR at once. The device never lowers its epoch: every later mandate needs `epoch =` the new minimum. If the new epoch cannot be stored in NVS, the QR is still shown with a warning, and the device keeps using the new epoch until it restarts.

## 7. Security model

**What is trusted.** Only the device: its firmware, its keys, and the contracts pinned at a pairing the user confirmed. Everything else is an untrusted courier: the companion, the agent, Privy, and this guide's tools. A courier can refuse to relay, but it cannot get the device to sign anything the user did not see.

**What the device enforces** (portable code, host-tested):

- **Strict parsing:**
  - CBOR is bounded and canonical;
  - strict JSON is used for Privy;
  - unknown keys are refused;
  - request ids are 16 bytes, and the authority must be ROOT.
- **Digests are rebuilt on the device.** Every digest comes from the same parsed struct that produced the review lines (`review.h`). The device never signs a hash it was handed.
  - The SIGN step (`respond.h`) repeats the policy check, rebuilds the digest and builds the response. Its output is tested byte for byte against the independent Python reference for every request type.
- **Pinned context** (`context.h`, `policy.h`):
  - Chain, DelegationManager, PulseCosignEnforcer, sentinel, relay, registry and vault are pinned only at pairing. A re-pairing lists every changed value in red and is refused while it would abandon a mandate the device signed (REVOKE FIRST).
  - A request naming anything else is refused.
  - Co-sign, deny and Privy requests never change the pinned contracts or the mandate. A co-sign only advances the device time, by at most 1 day.
  - The panic epoch and the reopen nonce only ever increase. Every mandate carries exactly the current panic floor, so the next PANIC kills every mandate the device signed.
- **What gets refused:**
  - calldata the device cannot decode;
  - an ERC-20 call that also carries native value;
  - a token whose decimals or symbol claim disagrees with the firmware table;
  - a mandate without exactly one pulse co-sign caveat for this device;
  - any caveat without a strict terms decoder;
  - an expiry beyond the 7-day window;
  - any Privy request outside the allow-list.
- **The signing gate** (`fsm.h`, `test_fsm.cpp`, security review B1):
  - SIGN is armed only after every review row has been drawn, the policy check has passed, and a live pulse has been measured.
  - The signature is made only for a press read in the **same** loop pass in which the pulse sensor still reports a live pulse.
  - Nothing is remembered between passes. A press or hold only acts on the screen on which it began (see [Screens and keys](#5-screens-and-keys)).
  - Deny and PANIC skip the pulse, because they can only restrict.
- **Pulse evidence:**
  - a live pulse means at least 5 beats in 8 s at 40–180 bpm, with a finger present and samples still arriving;
  - `evidence12` and a fresh TRNG salt go into `presenceHash`, which is what the contract checks;
  - the evidence, salt, signature and CBOR buffers are wiped once the QR text is built, and the QR text is wiped when the screen is left.
- **Keys:**
  - K1 (secp256k1, `m/44'/60'/0'/0/0`) signs only mandates and BindDevice. P1 (P-256, `m/7951'/0'`) signs everything else.
  - Each private key is derived for one signature, the signature is verified (K1 is also recovered) before release, and the key is then wiped.
  - Signatures are RFC 6979 and low-s.
- **No radio.** No source file includes Wi-Fi or Bluetooth headers, and nothing starts either radio. Radio check on the linked `firmware.elf` (2026-09-27): `xtensa-esp32s3-elf-nm -C firmware.elf | grep -E "esp_wifi_init|esp_bt_controller_init|esp_phy_enable|lwip"` gives **0 matches**.
  - What remains is code the SDK links unconditionally, not radio code: `esp_bt_controller_mem_release` (Arduino frees the Bluetooth memory at start-up), the coexistence pre-init stubs from IDF start-up, a Wi-Fi log-level constructor and an empty PHY hook.
  - ROM function addresses from the ROM linker scripts also appear, but they are not linked code.
- **Only one port.** The data USB-C port is the only way in besides the camera. The serial log prints status lines only: self-test results, the K1 address, the pairing chain and "output <type>". It never prints keys or request contents.

## Known limitations

- **Hardware not tested.** The display rotation, the camera orientation and exposure, QR decoding at real distances, MAX30102 detection on real thumbs, the key timings, the buzzer, the battery gauge and the NVS behaviour have not been checked on a board. Everything above comes from the build and the host tests.
- **Crypto is not constant-time.** The ECDSA arithmetic in `crypto.cpp` leaks timing, and the stack used by the point arithmetic is not wiped. This is accepted for an air-gapped prototype that signs only after a physical confirmation. The ESP32-S3 hardware accelerators are not used for private-key operations.
- **The seed is not encrypted.**
  - It sits in NVS as a plain blob. `keys_wipe` cannot erase old NVS copies until the page is recycled.
  - USB-Serial/JTAG and ROM download mode stay enabled, so anyone with the device and a cable can dump the flash with `esptool read_flash`.
  - Flash and NVS encryption, secure download mode and the DIS_USB_JTAG eFuse are planned. **Never burn eFuses on the demo unit**, because it cannot be undone.
- **No seed backup.** Losing or erasing the device loses K1, the vault owner. There is no BIP-39 export yet.
- **Placeholders (security review N2, still open in data).**
  - The PulseCosignEnforcer addresses in `src/enforcers.cpp` are `""`. Until the deployed addresses are compiled in, the device trusts the address confirmed at the **first** pairing (trust on first use): a malicious first pairing could pin a contract that enforces nothing. Later pairings show every changed contract in red and cannot abandon a live mandate. Paste the deployed addresses in and rebuild: from then on a pairing with any other enforcer is refused.
  - MockUSD and AUSD on chain 143 in `src/tokens.cpp` are also placeholders.
  - An unlisted token is shown in base units with an UNKNOWN TOKEN warning.
- **Device time.**
  - There is no real-time clock. Co-sign expiry is checked against the device's "not before" time (pairing clock, or signed co-sign expiries at most 1 day per co-sign, and never earlier than the build floor).
  - The companion supplies the pairing clock, and the user confirms it on screen (red when it jumps more than 30 days).
  - Each approved co-sign can still move the device time up to 1 day ahead of real time. The review shows every expiry in UTC.
  - A device that falls more than a week behind real time must be paired again.
- **One mandate is tracked.**
  - Revoke covers only the last mandate this device signed, and the device forgets it after signing the revoke, so that QR cannot be shown again. PANIC covers every mandate the device signed.
  - A co-sign for any other mandate shows **UNKNOWN MANDATE** as a warning, not a refusal.
  - A deny needs a mandate with an agent id.
- **Sentinel contract.** Reopen assumes the sentinel accepts any nonce greater than the last one it saw.
- **Privy keys.** The key-quorum `public_keys` format is assumed to be base64 DER SPKI (uncompressed P-256). This has not been checked against Privy's live API.
- **Liveness.**
  - The pulse check shows that a finger is on the sensor. It does not prove that the finger belongs to the owner.
  - The LED-drive challenge is compiled out by default (`RIPAR_LED_CHALLENGE`).
  - Co-sign and deny responses return the raw 12-byte evidence (bpm, DC levels, jitter) to the companion. The contract only sees `presenceHash`.
- **Review paging only moves forward.** To read a review again from the top, cancel (hold 2 s) and scan again.
- **Deny from a co-sign review** needs a relay pinned at pairing and a mandate with an agent id. Otherwise the device explains why and signs nothing.
- **Lost context (old layout v1, corrupt NVS).** The device counts as unpaired and its panic epoch and reopen nonce restart at 0. It says so at boot (**PAIRING LOST**). A PANIC or REOPEN signed now would be refused on chain (the enforcer needs a `minEpoch` above its current one, the sentinel a nonce above the last one), so **pair again with the floors**: `make_request.py build pair ... minEpoch=<the enforcer's current minEpoch for this device key, from its latest Panic event> reopenNonce=<the sentinel's last nonce for the vault>`. The floors come from the untrusted companion but can only raise the counters (restrict-only), and both are shown on the pairing review.
- **Key handling on hardware.** The rule that a press only acts on the screen where it began is host-tested in the state machine; the matching `io_flush` swallow in `io.cpp` (timer task + critical section) is not tested on a board.

## 9. Source map

| File | Role |
|---|---|
| `src/main.cpp` | Arduino entry. 32 KB loop-task stack; calls `app_setup` / `app_loop` |
| `src/flows.cpp` | device driver of the state machine: boot, self-test, key creation, scan, parse, review, pulse, sign, QR, NVS |
| `include/fsm.h`, `src/fsm.cpp` | portable screen state machine and signing gate (host-tested: `test/host/test_fsm.cpp`) |
| `include/respond.h`, `src/respond.cpp` | the SIGN step: policy re-check, digest from the parsed request, signature, response, new context (`test_respond.cpp`, byte-equal to the Python reference) |
| `src/protocol.cpp`, `src/json_strict.cpp` | request parsers, digests, response builders (`test_protocol.cpp`) |
| `src/policy.cpp`, `src/review.cpp`, `src/context.cpp`, `src/enforcers.cpp`, `src/tokens.cpp` | pinned-context policy, review lines, caveat decoders, NVS blob layout, contract and token tables (`test_policy.cpp`) |
| `src/crypto.cpp`, `src/hashes.cpp`, `src/eip712.cpp`, `src/abi.cpp`, `src/cbor.cpp`, `src/ur.cpp` | portable crypto and encodings (`test_crypto`, `test_hashes`, `test_eip712_abi`, `test_cbor_ur`) |
| `src/pulse_algo.cpp` | beat detection (`test_pulse.cpp`) |
| `src/keys.cpp`, `src/store.cpp` | seed, K1 / P1, self-test (mbedTLS cross-check), context in NVS |
| `src/io.cpp`, `src/pulse.cpp`, `src/qrscan.cpp`, `src/ui.cpp` | BOOT key and buzzer, MAX30102, camera + quirc, LovyanGFX screens |
| `tools/make_request.py`, `tools/ref_*.py` | companion-side builder and verifier; independent Python references |
| `tools/companion_lite.html` | static page: request QR animation, response → verify command |
| `test/device/check_main.cpp` | `chk_device` bring-up program (screens, sensors, self-test; no signing flows) |
