# Ripar Wallet: device protocol v1

This is the contract between the **air-gapped device firmware**, the **companion app** and the **smart contracts**. Everything travels as QR codes. The radio is off: Bluetooth only runs when the user turns on the optional BLE fallback courier on the device (§1.1), and Wi-Fi only in the `ripar` test build, as a temporary test courier the user turns on in the device menu (§1.2). The `ripar-airgap` build has no radio code at all.

The companion app is **untrusted**. It only carries data. The device parses every request strictly, checks it against the contracts it **pinned at pairing** (§6), shows every field that is signed, and rebuilds every digest itself.

This document describes **firmware v1.2** (contracts v1.2). The wire format is unchanged from v1.1; what the device accepts is stricter. The differences are summarised in [§7](#7-changes-in-firmware-v12).

## 1. Transport: BC-UR over QR

- Encoding follows BC-UR (BCR-2020-005): `ur:<type>/<bytewords>`, with a CBOR payload in *minimal* bytewords and a CRC-32 at the end.
- QR codes carry the UR **upper-cased**, so they fit QR alphanumeric mode.
- **Companion → device:** a single part `ur:<type>/<bw>`, or a multipart `ur:<type>/<seq>-<len>/<bw>`.
  - Each multipart fragment is the standard CBOR array `[seqNum, seqLen, messageLen, checksum(crc32 of message), fragment]`.
  - The device accepts **pure** fragments (`seqNum ≤ seqLen`). It also accepts mixed fountain fragments (Xoshiro256** part selection per BC-UR) when they complete the set.
  - The companion should loop the pure fragments, each 60–80 bytes, at about 300 ms per frame.
- **Device → companion:** always one single-part QR.

Every request map carries key `1` = request id. The id is a byte string of 16 bytes, which may be a UUID (CBOR tag 37). The response echoes it back as a plain byte string.

### 1.1 Optional courier: Bluetooth LE (firmware `env:ripar`, `env:ripar-ble`)

QR stays the primary, air-gapped path. When the camera cannot read the companion's QR codes, the user can turn on a Bluetooth LE link **on the device** (device menu → BLE LINK → review → pulse + SIGN). The link is only a second courier for the **same UR text**, specified in [BLE_LINK.md](BLE_LINK.md):

- **Companion → device:** each QR part is written to the RX characteristic as one line: the upper-case UR part text + `\n` (at most 4096 bytes). The device feeds it into the same intake as a camera-decoded QR, and only while it is on SCAN. Parsing, review, policy, pulse and SIGN are identical.
- **Device → companion:** the UR of the QR on screen + `\n`, as TX notifications of at most MTU - 3 bytes.
- **STATUS:** a small JSON (screen, scan progress, short K1, firmware id) so the companion can say what the device expects next.
- Security: LE Secure Connections with numeric comparison confirmed on the device, one bonded phone, no GATT access without the authenticated link. The radio is dead until woken on the device, shows **RADIO ON** on every screen while alive, and goes off after 5 min without link traffic, on BLE OFF, PANIC and power-off.

### 1.2 Optional courier: Wi-Fi (TEMPORARY TEST FEATURE, firmware `env:ripar` only)

For testing only, the default test build `env:ripar` (`RIPAR_WIFI=1`) can also carry the **same UR text over the local network**; it will be removed, and `env:ripar-ble` / `env:ripar-airgap` contain no Wi-Fi code at all. Specified in [WIFI_LINK.md](WIFI_LINK.md):

- **Setup:** the bonded phone sends the network (`{"v":1,"ssid":...,"pass":...}`) over the Bluetooth PROV characteristic; the device stores it only after the user confirms the JOIN WI-FI review with SIGN, and Wi-Fi only runs after **WI-FI ON** in the device menu (persisted across restarts until WI-FI OFF, FORGET WI-FI or PANIC). While it is on, every screen shows **WIFI ON** and Home says NOT AIR-GAPPED.
- **Companion → device:** `POST http://ripar-xxxx.local/rx` with one UR part per line (the text a QR would carry), fed into the same intake as a camera-decoded QR, only while the device is on SCAN (otherwise `409`).
- **Device → companion:** `GET /tx` returns the UR of the QR on screen (`204` when none); `GET /status` returns the same STATUS JSON as Bluetooth (plus `wifi` and `ip`).
- Security: every request carries `X-Ripar-Code`, the per-boot 8-digit code shown only on the device screen (constant-time check, lock-out after wrong codes). Plain HTTP: the local network can read the traffic. Parsing, review, policy, pulse and SIGN are identical.

Nothing in the message formats below depends on the courier.

## 2. Keys

- **Seed:** a 256-bit master seed.
  - It comes from SHA-256 of an entropy pool, built on the first run: `esp_fill_random()` with the SAR-ADC entropy source switched on (`bootloader_random_enable()`, since no radio runs then: keys are created at the first boot, and the optional Bluetooth link of §1.1 can only be turned on later; while it is on, later TRNG draws such as the co-sign salt use the RF noise source instead), plus camera frames, raw MAX30102 samples and timing jitter mixed in by the firmware (`flows.cpp` `create_keys()`), plus a second TRNG draw and a timer value in `keys_create()`.
  - It is stored in NVS. Encryption comes in P1.
- **K1 (secp256k1):** BIP-32 from the seed (`HMAC-SHA512("Bitcoin seed", seed)`), path `m/44'/60'/0'/0/0`.
  - K1 owns the vault and signs **only** `Delegation` mandates (and `BindDevice`).
  - Its address is `keccak256(pubX‖pubY)[12:]`.
  - The vault address is **derived from K1** on the device ([§2.1](#21-the-vault-derived-from-k1)).
- **P1 (P-256 / secp256r1):** SLIP-10 from the seed (`HMAC-SHA512("Nist256p1 seed", seed)`), path `m/7951'/0'`.
  - P1 signs co-signatures, revoke, panic, reopen, deny, `BindDevice` and Privy requests.
  - Its public key travels as `px‖py`, 64 bytes uncompressed, without the 0x04 prefix.
- **All ECDSA signatures:** RFC 6979 deterministic nonces with SHA-256, and **low-s**, i.e. `s ≤ n/2`. OpenZeppelin `P256.verify` and `ECDSA.recover` reject high-s.
- **The device never signs a digest it was handed.** Every digest is rebuilt on the device from the same parsed request that produced the review screen (`firmware/include/review.h`).

### 2.1 The vault (derived from K1)

The vault is the MetaMask HybridDeleGator (delegation-framework v1.3.0) owned by K1, behind an ERC1967Proxy that the canonical SimpleFactory deploys with CREATE2. Since firmware v1.2 the device computes its address from K1 alone (`firmware/src/vault.cpp`) and pins **no other vault**: the companion can no longer choose it.

```
initcode = abi.encodeWithSignature("initialize(address,string[],uint256[],uint256[])", K1, [], [], [])   228 bytes, selector 0x8ebf9533
args     = abi.encode(address HybridDeleGatorImpl, bytes initcode)                                     352 bytes
creation = ERC1967Proxy creation code (1008 bytes) ‖ args
vault    = address(keccak256(0xff ‖ SimpleFactory ‖ bytes32(0) ‖ keccak256(creation))[12:])
```

| Constant (same on 10143 and 143) | Value |
|---|---|
| SimpleFactory | `0x69Aa2f9fe1572F1B640E1bbc512f5c3a734fc77c` |
| HybridDeleGator implementation | `0x48dBe696A4D990079e039489bA2053B36E8FFEC4` |
| ERC1967Proxy creation code | 1008 bytes, `@metamask/delegation-abis@2.0.0` `dist/bytecode/ERC1967Proxy` (keccak256 `0xc8fb9314…a8e0`), embedded in the firmware |
| salt | `bytes32(0)` |

- This is what `@metamask/smart-accounts-kit` 2.0.0 computes for the owner K1 and deploy salt `0x` (`getCounterfactualAccountData`). The companion must deploy and fund exactly this account.
- Known answer: K1 `0x753454832754c071704be47915d4DeC6339624Eb` (the demo seed) → initCodeHash `0x9694a6959734c65d55361f8f8d333c8534d1e808dbfbb2694fab6c7c8cbd60ce` → vault `0xc36F625D426eBa8f1e0129276B284a939CD3A57D`. Checked on Monad testnet with `SimpleFactory.computeAddress` and an `eth_call` of `SimpleFactory.deploy`; host-tested in `test_vault.cpp` against this answer and an independent Python implementation (`make_request.py vault_address`).
- `make_request.py vault <K1>` prints it, `demo-keys` prints the demo device's, and `parse` of a `ripar-pair` response adds it as `vault`.
- Pair-req key 8 may only confirm it; every mandate and co-sign delegator must equal it; a reopen names it (§4).

## 3. EIP-712

Every digest is `keccak256(0x19 0x01 ‖ domainSeparator ‖ structHash)`.

The domain is always `EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)`:

| name | verifyingContract | used for |
|---|---|---|
| `DelegationManager` v`1` | MetaMask DelegationManager | `Delegation` (K1) |
| `RiparPulseCosign` v`1` | PulseCosignEnforcer | `HumanApproval`, `Revoke`, `Panic` (P1) |
| `RiparSentinel` v`1` | RiparSentinel | `Reopen` (P1) |
| `RiparReputationRelay` v`1` | RiparReputationRelay | `Deny` (P1) |
| `RiparDeviceRegistry` v`1` | RiparDeviceRegistry | `BindDevice` (P1 **and** K1) |

The verifyingContract and chainId of every domain are the ones **pinned at pairing** (§6), never the ones a request names (a request that names others is refused). Since firmware v1.2 the PulseCosignEnforcer, the RiparDeviceRegistry and the RiparReputationRelay are compiled into the firmware, and a pairing can only pin those (§4 `ripar-pair-req`).

The struct types, exactly as hashed:

```
Delegation(address delegate,address delegator,bytes32 authority,Caveat[] caveats,uint256 salt)Caveat(address enforcer,bytes terms)
Caveat(address enforcer,bytes terms)
HumanApproval(bytes32 delegationHash,address delegator,address redeemer,address target,uint256 value,bytes32 callDataHash,uint256 nonce,uint64 expiry,bytes32 presenceHash)
Revoke(bytes32 delegationHash)
Panic(uint64 minEpoch)
Reopen(address vault,uint256 nonce)
Deny(uint256 agentId,bytes32 requestHash,bytes32 presenceHash)
BindDevice(address owner,bytes32 px,bytes32 py)
```

Hashing rules:
- `bytes` members are hashed as `keccak256(bytes)`.
- `Caveat[]` is `keccak256(concat(hashStruct(caveat_i)))`.
- `callDataHash = keccak256(calldata)`.
- `presenceHash = sha256(evidence12 ‖ salt16)`. Note this one is **SHA-256**, not keccak.
- `requestHash` (a deny from a co-sign review) = `hashStruct(HumanApproval)` of the reviewed request with `presenceHash = 0x00…00`, computed by the device.
- `ROOT_AUTHORITY = 0xfff…fff` (32 bytes of 0xff). The device refuses any other authority.

## 4. Messages (CBOR maps with unsigned-integer keys)

Types used in the tables below:
- `bstr` is a byte string.
- `addr` is a 20-byte `bstr`. Every address in a request must be non-zero (AI claims may use the zero address for "native").
- `u256` is a big-endian `bstr` of at most 32 bytes (leading zeros optional).
- `uint` is a CBOR unsigned integer.

General parser rules: only the keys listed for a request type are allowed (an unknown key is refused), required keys must be present, and display text must not contain control characters.

### `ripar-pair-req` (in, optional) → `ripar-pair` (out)

Pairing pins the chain and the contracts every later request is checked against (§6). The device shows every value in full and signs only after pulse + SIGN.

| key | request | response |
|---|---|---|
| 1 | req-id | req-id |
| 2 | chainId `uint` (must be in the firmware chain table: 10143 or 143) | K1 address `addr` |
| 3 | registry `addr` (RiparDeviceRegistry; must equal the firmware's) | P1 key `bstr(64)` = px‖py |
| 4 | DelegationManager `addr` (optional; must equal the firmware's) | P1 signature `bstr(64)` r‖s over `BindDevice(owner=K1, px, py)` |
| 5 | PulseCosignEnforcer `addr` (optional; must equal the firmware's) | K1 signature `bstr(65)` r‖s‖v over the same digest |
| 6 | RiparSentinel `addr` (optional; pinned as given) | firmware id `bstr(8)` (first 8 bytes of SHA-256 of the app image) |
| 7 | RiparReputationRelay `addr` (optional; must equal the firmware's) | |
| 8 | vault `addr` (optional; must equal the vault derived from K1, §2.1) | |
| 9 | now `uint` (companion clock, unix s, < 2^40, optional) | |
| 10 | minEpoch floor `uint` (< 2^63, optional) | |
| 11 | reopenNonce floor `uint` (< 2^63, optional) | |

- **Contracts compiled into the firmware** (`firmware/src/enforcers.cpp`; the Ripar contracts are CREATE2 addresses of the bytecode frozen for contracts v1.2):

  | Contract | Key | 10143 | 143 |
  |---|---|---|---|
  | MetaMask DelegationManager v1.3.0 | 4 | `0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3` | same |
  | Ripar PulseCosignEnforcer | 5 | `0x64d61fe5438981DC803ED61250FEf024617ae7eE` | same |
  | RiparDeviceRegistry | 3 | `0xA08a47c9d645926615CF04D69b7a048133F68c9f` | same |
  | RiparReputationRelay | 7 | `0xE433dCA75CA6cd730b1006F51A26208B000eA9E2` | `0x108BA102F7D0915f51c93F128b96Bd24F647f06d` (other constructor arguments - the chain's ERC-8004 registries - but all public constants of the deploy config, so known before deployment; `contracts/test/FirmwarePins.t.sol` recomputes both) |
  | RiparSentinel | 6 | not compiled in (its address depends on the CRE workflow owner): key 6 is pinned as given | same |

  A key 3, 4, 5 or 7 that names another address than the one compiled in for the chain is **refused**, e.g. `WRONG REGISTRY: key 3 = 0x… is not the RiparDeviceRegistry this firmware pins on Monad testnet (10143): 0xA08a…8c9f` (likewise `WRONG DELEGATION MANAGER`, `WRONG PULSE CO-SIGN ENFORCER`, `WRONG REPUTATION RELAY`). An absent key 4, 5 or 7 pins the compiled-in address. Key 3 stays required: it is the `BindDevice` domain. The review marks each compiled-in address "(firmware table)".
- **Vault (key 8):** when present it must equal the vault derived from K1 (§2.1), otherwise the pairing is **refused**: `VAULT IS NOT THIS DEVICE'S VAULT: key 8 = …, but this device's K1 … owns the vault … (MetaMask SimpleFactory CREATE2, salt 0; leave key 8 out to pin it)`. When absent, the derived vault is pinned. The review shows `Vault <address> (derived from this device)`, and a wrong key 8 in red as `Key 8 vault`. `make_request.py build pair` leaves key 8 out unless it is given.
- A missing sentinel is shown as a warning: without a sentinel there is no reopen (and mandates must name no sentinel). The relay is always the compiled-in one. (Until the firmware v1.2 review the relay on 143 was whatever key 7 named, so a companion could send every deny the user filed on 143 to a contract of its choice.)
- Key 9 advances the device's "not before" time (§6), shown as UTC. The companion should always send it (`make_request.py build pair` adds the current time). A time more than 30 days after the device's current time is shown in red.
- Keys 10 and 11 are **floors** for the device's panic epoch and reopen nonce: the device keeps `max(its own value, the floor)`, so they can only raise the counters, never lower them. Use them after the device lost its context (the counters then restart at 0): send the on-chain `minEpoch` of the device key and the last reopen nonce the sentinel saw. Both counters, and any raise, are shown on the review.
- Pairing again replaces the pinned set. The panic epoch and the reopen nonce never go back. The review lists every pinned value that changes, old → new, in red.
- **PANIC FIRST.** While mandates the device signed may be live and uncovered by its last panic (context flag `unpanickedMandates`, §6: set when the device signs a mandate, cleared when it signs a panic), a pairing that would change the chain, the DelegationManager, the PulseCosignEnforcer or the vault is **refused**: `PANIC FIRST: mandates signed on <chain> (PulseCosignEnforcer <address>, vault <address>) would not be covered by PANIC after re-pairing. Sign a PANIC (home: hold 5 s) and relay it, then pair again`. After such a pairing the device's panic and revoke would be signed for the new chain / enforcer and would no longer reach those mandates. With the contracts compiled in and the vault derived, in practice this blocks a change of chain (10143 ↔ 143). The sentinel, the clock and the counter floors may change (and a relay pinned by an older context moves to the compiled-in one).
  - PANIC FIRST replaces v1.1's REVOKE FIRST (refused while `lastDelegationHash` was set). A revoke only covers the last mandate, while earlier mandates signed since the last panic may still be live, so a revoke no longer unlocks the change. A mandate the device still remembers after a panic is already dead on chain once that panic is relayed (its epoch is below the new `minEpoch`), so no revoke is needed either.
  - The review lists a mandate the pairing would forget as `FORGETS mandate 0x… (killed once this device's last PANIC is relayed)`, or `(still live: PANIC first)` on a refused review.
  - PANIC FIRST clears when the device **signs** a panic, but the chain kills the mandates only once that panic is **relayed**, which the device cannot see (a companion that withholds it could otherwise move the device off the chain unnoticed). So a pairing that moves the chain, manager, enforcer or vault after a panic (flag clear, `minEpoch > 0`) shows, in red: `PANIC mandates signed on <chain> die only once this device's PANIC (min epoch N) is relayed there - this device cannot check that. Confirm only if the on-chain min epoch of this device key is >= N`. If it was not relayed, pair back to that chain (allowed: the flag is clear) and panic again.

Without a request (home screen → PAIR), the device outputs keys 2, 3 and 6 only and pins nothing. The companion derives the vault from key 2 (§2.1).

### `ripar-cosign-req` (in) → `ripar-cosign` (out)

| key | request | notes |
|---|---|---|
| 1 | req-id | |
| 2 | chainId `uint` | must equal the pinned chain |
| 3 | enforcer `addr` | must equal the pinned PulseCosignEnforcer (the domain verifyingContract; the firmware's on 10143 and 143) |
| 4 | delegationHash `bstr(32)` | flagged **UNKNOWN MANDATE** unless it is the last mandate this device signed |
| 5 | delegator (vault) `addr` | must equal the pinned vault, i.e. the vault derived from K1 (§2.1), else **NOT THIS DEVICE'S VAULT** |
| 6 | redeemer `addr` | |
| 7 | target `addr` | ERC-20 token or native payee |
| 8 | value `u256` | native value |
| 9 | calldata `bstr` | the device decodes ERC-20 `transfer`, `approve` and `transferFrom` |
| 10 | nonce `u256` | **single-use per mandate** on chain (PulseCosignEnforcer v1.2): use a fresh nonce for every co-sign, including a retry of the same request |
| 11 | expiry `uint` (unix s) | must be < 2^40 and at most 7 days after the device's "not before" time (§6); shown as UTC |
| 12 | risk `{1: src text, 2: category text, 3: label text, 4: ageDays uint}` | optional, shown as "(companion)" |
| 13 | ai `{1: text ≤100, 2: {1: to addr, 2: token addr, 3: amount u256}}` | optional; the device checks the claims against its own decode |
| 14 | budgetLeft `u256` | optional, for display, "(companion)" |
| 15 | token decimals `uint` | optional **claim**, see below |
| 16 | token symbol `text` | optional **claim**, see below |

Checks and display:
- Refused: calldata that is not empty and not exactly one of the three ERC-20 calls (**UNKNOWN CALLDATA**), and an ERC-20 call with a non-zero native value.
- **Token table** (`firmware/src/tokens.cpp`): the asset of the amount is the native coin for empty calldata, otherwise the call target. For a listed asset (AUSD `0xa9012a055bd4e0eDfF8Ce09f960291C09D5322dC`, 6 decimals, on 10143; MockUSD `mUSD` `0xB5b7eaffbF9bf68cbcC1Ce8B5850b2ea9d6f9a2a`, 6 decimals, on 10143; MON, 18 decimals, on 10143 and 143) the table's decimals and symbol are used, and a request whose key 15 or 16 disagrees with the table is **refused**. An unlisted token is shown as the raw integer in base units, the full token address and **UNKNOWN TOKEN - decimals unverified**; a companion symbol is shown as "(companion)".
- **AI claims** match only a plain native send (to = target, token = zero, amount = value) or an ERC-20 `transfer` (to, token = target, amount; no native value). `approve` and `transferFrom` never match.
- Every address is shown as the full 42-character EIP-55 form. The vault line reads `<address> (derived from this device)`.
- **AUTO payee line** (PulseCosignEnforcer v1.2 known-payee predicate, contracts/SPEC.md "Changes in v1.2"). On a co-sign for the mandate the device remembers (key 4 = `lastDelegationHash`) whose terms set `newPayeeNeedsHuman`, the review shows, in amber, `<payee> becomes an AUTO payee of this mandate: the agent can then pay it without a pulse, up to <perTxAutoCap> per payment and <periodAutoCap> per <period> window (fixed windows from the first AUTO spend)` (for period 0: `… and <periodAutoCap> in total (lifetime cap)`). It appears **exactly** when the enforcer will record the payee:
  - the call is meterable for the mandate's asset: native terms (`token = 0`) need empty calldata with `value > 0` (payee = target); token terms need a `transfer` on that token with `value = 0` and `amount > 0` (payee = the recipient);
  - the payee is not the zero address.

  So never for `approve`, `transferFrom`, another asset, or a 0 amount. The caps are formatted with the firmware token table for the mandate's asset. The device takes the terms from its context (§6), stored when it signed the mandate.
  A **refused** co-sign (wrong vault, enforcer or chain, expiry too far, ...) never shows it: nothing is signed, so nothing is whitelisted.
- **Unknown mandate** (key 4 is not the remembered mandate: an older one, one revoked since - perhaps never relayed -, one from before a re-pairing). The enforcer records the payee for any co-signed mandate whose terms make the call meterable, and the device does not know those terms. The review shows `UNKNOWN MANDATE - not the last mandate this device signed` and, when the call could be meterable under some terms (a native send with `value > 0`, or an ERC-20 `transfer` with no native value and `amount > 0`) to a non-zero payee, in amber: `<payee> may become an AUTO payee of mandate 0x…: the agent could then pay it without a pulse, up to caps this device does not know`.
- A co-sign for the remembered mandate after the device signed a panic shows `this device signed a PANIC after this mandate: once that PANIC is relayed, the chain refuses it`.

The response is `{1: req-id, 2: r‖s bstr(64), 3: evidence12 bstr(12), 4: salt16 bstr(16)}`. The companion recomputes `presenceHash` and relays `abi.encode(nonce, expiry, presenceHash, r, s)` as the caveat args.

### `ripar-mandate-req` (in) → `eth-signature` (out, ERC-4527 shape)

| key | request |
|---|---|
| 1 | req-id |
| 2 | chainId `uint` (must equal the pinned chain) |
| 3 | DelegationManager `addr` (must equal the pinned one) |
| 4 | delegate `addr` (not ANY_DELEGATE `0x…0a11`) |
| 5 | delegator `addr` (must equal the pinned vault = the vault derived from K1, §2.1) |
| 6 | authority `bstr(32)` (must be ROOT) |
| 7 | caveats `[[enforcer addr, terms bstr], …]`, 1 to 16 entries |
| 8 | salt `u256` |
| 9 | label `text` (optional, ≤ 64 bytes, shown as "(companion)") |
| 10 | agentId `uint` (optional; the agent a deny is filed against; shown as "(companion)") |

The response is `{1: req-id, 2: r‖s‖v bstr(65)}`, with v = 27 or 28.

**Mandate policy** (`firmware/src/policy.cpp` `check_mandate`):
- **Exactly one** caveat must use the pinned PulseCosignEnforcer, otherwise the device refuses with **MANDATE WITHOUT PULSE CO-SIGN**.
- Its terms must name **this device's** P1 key and an epoch **exactly equal** to the device's panic floor `minEpoch` (the last panic epoch it signed, or the pairing floor; 0 on a new device). The enforcer kills a mandate when `terms.epoch < minEpoch`, and the device's next panic is `minEpoch + 1`, so a higher epoch would survive every panic the device can sign. A lower epoch is stale.
- Its sentinel must be exactly the pinned one, or the zero address when no sentinel is pinned (a mandate cannot name a sentinel lane the user never confirmed at pairing).
- **Every** caveat must have a strict terms decoder. The device shows every decoded field. Any other enforcer, known or not, is refused (UNKNOWN ENFORCER, or e.g. "NonceEnforcer is not supported").
- The delegator must be the device's own vault (§2.1), otherwise **NOT THIS DEVICE'S VAULT** (v1.1 accepted any delegator when no vault was pinned).
- The pulse caveat's AUTO period is shown as `never resets (lifetime cap)` for 0, otherwise as the duration followed by `(fixed windows from the first AUTO spend)` (contracts/SPEC.md v1.2 "AUTO windows"). The agent id is shown as `<id> (companion)`.

Terms layouts the device decodes, with exact lengths (MetaMask delegation-framework v1.3.0 `getTermsInfo`, same addresses on 10143 and 143):

| enforcer | terms | bytes |
|---|---|---|
| Ripar PulseCosignEnforcer `0x64d6…7eE` | `abi.encode(bytes32 px, bytes32 py, address token, uint128 perTxAutoCap, uint128 periodAutoCap, uint32 period, uint64 epoch, bool newPayeeNeedsHuman, address sentinel)`; every word canonical | 288 |
| ERC20TransferAmountEnforcer `0xf100…D2Fc` | token (20) ‖ maxAmount uint256 | 52 |
| NativeTokenTransferAmountEnforcer `0xF71a…0320` | allowance uint256 | 32 |
| ValueLteEnforcer `0x92Bf…6A8F` | max value uint256 | 32 |
| LimitedCallsEnforcer `0x0465…5416` | max calls uint256 | 32 |
| ERC20PeriodTransferEnforcer `0x474e…39aB` | token (20) ‖ periodAmount ‖ periodDuration (> 0) ‖ startDate | 116 |
| TimestampEnforcer `0x1046…c069` | afterThreshold uint128 ‖ beforeThreshold uint128 (0 = no bound) | 32 |
| AllowedTargetsEnforcer `0x7F20…4EeB` | 1 to 16 packed addresses | 20·n |
| RedeemerEnforcer `0xE144…65c5` | 1 to 16 packed addresses | 20·n |

After signing, the device remembers the mandate: `lastDelegationHash = hashStruct(Delegation)` (what `ripar-revoke` revokes), its agentId, and its pulse terms `token`, `perTxAutoCap`, `periodAutoCap`, `period` and `newPayeeNeedsHuman` (for the co-sign review's AUTO payee line). It also sets `unpanickedMandates` (PANIC FIRST, §4 `ripar-pair-req`). Only the last mandate is remembered; every mandate the device signed is killed by its next panic.

### `ripar-deny-req` (in) → `ripar-deny` (out)

- Request: `{1: req-id, 2: chainId, 3: relay addr, 4: agentId uint, 5: requestHash bstr(32)}`.
  - The chain and relay must be the pinned ones (the relay compiled into the firmware for the chain).
  - The agentId must be the agent of the last mandate this device signed; the companion cannot choose another agent.
  - The request hash is shown as "from the companion (not checked)".
- **Deny from a co-sign review:** hold SIGN for 2 s on the co-sign review. The device builds the deny itself:
  - req-id: the co-sign request's;
  - chain and relay: the pinned ones;
  - agentId: from the pinned mandate;
  - `requestHash = hashStruct(HumanApproval)` of the reviewed request with `presenceHash = 0` (§3).
  - It then shows the deny it built (agent, request hash, relay, chain). A short press signs it, without the pulse; holding 2 s cancels. A deny request from the companion is reviewed and signed the same way.
- Response: `{1: req-id, 2: r‖s, 3: evidence12, 4: salt16, 5: agentId uint, 6: requestHash bstr(32)}`. Keys 5 and 6 echo exactly what was signed, so the companion can relay a deny it did not build.
- A deny is always allowed (it can only restrict). The pulse evidence stays optional (all-zero).

### Device-initiated: `ripar-revoke`, `ripar-panic`, `ripar-reopen` (out)

These use the chain and contracts **pinned at pairing** (§6), never values from a request.

- Panic starts from the home screen (hold the key: at 2 s the "RELEASE = PAIRING QR / keep holding = PANIC" screen appears, at 5 s panic) and is signed at once. A hold that began on another screen never panics.
- Revoke and reopen start from the device menu (home: hold 2 s and release → pairing QR; hold 2 s → menu). Each shows its review and needs pulse + SIGN. The screens and keys are in `docs/FIRMWARE.md`.

| Type | Payload | Domain contract |
|---|---|---|
| `ripar-revoke` | `{1: delegationHash, 2: r‖s}` (the last mandate this device signed; the device then forgets it) | PulseCosignEnforcer |
| `ripar-panic` | `{1: minEpoch uint, 2: r‖s}` | PulseCosignEnforcer |
| `ripar-reopen` | `{1: vault addr, 2: nonce u256, 3: r‖s}` (the vault derived from K1) | RiparSentinel |

- **Panic:** hold SIGN for 5 s on the home screen. No pulse check is needed, because panic can only tighten. `minEpoch` is the device's panic floor + 1. Every mandate the device signed carries an epoch equal to the floor at that time (§4 mandate policy), so a relayed panic kills all of them, even if an earlier panic QR was never relayed. The enforcer only accepts a new `minEpoch` above its current one: after a lost context, pair with the on-chain floor (key 10) first. If the new epoch cannot be stored, the device still uses it until it restarts and says so on the QR screen. A signed panic clears `unpanickedMandates`: a pairing may then move the chain again (PANIC FIRST).
- **Revoke:** signs `Revoke(lastDelegationHash)` for the pinned enforcer (the one shown on the review), then the device forgets that mandate and its terms (a co-sign for it then shows UNKNOWN MANDATE). Scan the QR before leaving the screen: it cannot be shown again. The panic still covers it. A revoke does **not** clear `unpanickedMandates`: earlier mandates signed since the last panic may still be live.
- **Reopen:** `nonce` is the device's last reopen nonce + 1 and is never reused. The sentinel contract must accept any nonce greater than the last one it saw. After a lost context, pair with the sentinel's last nonce as key 11 first.

### `ripar-privy-req` (in) → `ripar-der-sig` (out)

- Request: `{1: req-id, 2: canonical JSON bstr}`. The JSON is the Privy authorization-signature payload `{"body":…,"headers":{…},"method":…,"url":…,"version":1}`, parsed with a strict RFC 8259 parser (no duplicate keys, no trailing data, valid UTF-8, depth ≤ 16).
- The device signs **only** these two request shapes. Everything else is refused, including `/rpc`, other methods, other hosts, query strings, other body members (e.g. `owner_id`) and other headers.
  - `PATCH https://api.privy.io/v1/wallets/<id>`, with body members from `policy_ids` (array of ids) and `additional_signers` (array of `{signer_id, override_policy_ids?}`).
  - `PATCH https://api.privy.io/v1/key_quorums/<id>`, with body members from:
    - `public_keys`: 1 to 8 base64 DER SubjectPublicKeyInfo P-256 keys, uncompressed;
    - `authorization_threshold`: an integer from 1 to 99;
    - `display_name`: printable ASCII, at most 64 bytes;
    - `user_ids`, `key_quorum_ids`: arrays of ids.
- Headers: `privy-app-id` is required and `privy-idempotency-key` is optional. Both are shown.
- Limits: ids are 1 to 64 characters of `[A-Za-z0-9_:.-]`, and arrays have at most 8 entries.
- **Every value is shown in full.** A request with anything that could not be shown in full is refused, never truncated. Each key-quorum key is marked **THIS DEVICE** or **OTHER P-256 KEY**.
- The device signs `sha256(json)` of the exact bytes with P1.
- Response: `{1: req-id, 2: DER signature bstr}`. The companion base64-encodes it for the `privy-authorization-signature` header.

## 5. Pulse gate (presence evidence)

Signing (except Deny and Panic) requires both:
1. a **live pulse**: finger present (IR DC > 50 000), at least 5 beats in 8 s, 40–180 bpm, and the thumb still on the pad;
2. then a **short press on SIGN** (the BOOT key, GPIO0).

The pulse gate (`src/pulse_algo.cpp`, host-tested in `test_pulse.cpp`) also refuses what does not look like a heart: flat, constant, saturated or uncorrelated red / IR channels, rhythms with jitter > 0.35, edge-like (square-wave) or slow symmetric (sine, triangle) upstrokes in more than 1/4 of the beats, and beat trains that are **too regular**. The regularity statistics run once 4 post-landing beats span 3 s (4 s above 80 bpm), on beat timing points that do not depend on the foot of the upstroke:
- robust successive differences of the beat intervals above a fixed floor and above 1.5× the timing noise predicted from the measured sensor noise; no more repeated interval values than random heart-rate variability produces;
- **cross-channel test** (since the firmware v1.2 review): white sensor noise shifts the timing points of a perfectly periodic source from beat to beat, and the gate read that as heart-rate variability (a 66 bpm square wave with noise 120 passed 10/10, some sines even at the nominal noise 8). The noise is independent in the IR and red channels; a heart's variability is common to both. The device finds each beat's upstroke separately in both channels (slope centroid, one wide window per beat) and compares a = (dI + dR) / 2 with b = (dI − dR) / 2 over the successive interval differences dI, dR of clean beats (steepest step ≥ 0.6× the median one, both intervals within ±25 % of the median). Without a heart a and b are identically distributed, so the timing noise is measured rather than predicted. The ratio (the largest third of a² left out, against all of b²) must exceed its 99.9 % null quantile for the number of differences; a pulse that has passed keeps a lower bar (0.6×);
- the edge test also runs noise-aware (largest fall less 2.5 σ of the fall noise, against the sum of falls less the noise's share), so a square wave with sensor noise is still recognised.

Limits: a source with random beat-to-beat timing common to both channels (a replayed PPG with variability, or common-mode amplitude noise from the source) passes. Per evaluation a periodic source with Gaussian timing noise passes the cross-channel test with probability ~0.1 %, and very noisy periodic sources (noise at or above the pulse amplitude) still pass now and then (host sweep: 1 of 480 runs at noise 250 / 500, 0 of 960 at noise 8–120, all shapes at 50–130 bpm and 0.5–4 %). A weak real pulse whose beat-to-beat variability is close to the red channel's timing noise (weak signal, high rate, low HRV) passes late (10–30 s) or not at all.

`evidence12` layout (big-endian):

| bytes | field |
|---|---|
| [0] | version = 1 |
| [1] | bpm |
| [2] | beats counted |
| [3..5] | mean IR DC (24 bit) |
| [6..8] | mean red DC (24 bit) |
| [9] | mean beat-interval jitter ×1000, capped at 255 |
| [10..11] | measurement duration in ms / 10 |

`salt16` is fresh from the TRNG for every signature.

## 6. Pinned context and signing policy

The device keeps one pinned **context** in NVS (`firmware/include/context.h`, layout version 3, 256 bytes, CRC-protected). A blob with another version (v1, or v2 written by firmware v1.1) or a bad CRC is ignored, and the device then counts as unpaired: the boot screen says **PAIRING LOST**, and it must be paired again with the counter floors (keys 10 / 11). A loaded context whose vault is not the vault derived from this device's K1 is treated the same way.

| field | set by |
|---|---|
| chainId, DelegationManager, PulseCosignEnforcer, sentinel, relay, registry | a pairing the user confirmed with pulse + SIGN (the compiled-in addresses where the firmware has them) |
| vault | the same pairing: always the vault derived from K1 (§2.1), never the request's key 8 |
| lastDelegationHash, agentId, and the pulse terms of that mandate (token, perTxAutoCap, periodAutoCap, period, newPayeeNeedsHuman) | a mandate the device signed; a revoke the device signed clears lastDelegationHash and the terms |
| unpanickedMandates (PANIC FIRST) | set by a mandate the device signed, cleared by a panic it signed (a revoke leaves it set) |
| minEpoch | a panic the device signed, or the pairing floor (key 10) (only ever increases) |
| reopenNonce | a reopen the device signed, or the pairing floor (key 11) (only ever increases) |
| notBefore | the pairing clock (key 9) and the expiry of each co-sign the device signed, by at most 1 day per co-sign (only ever increases) |

- A co-sign, deny or Privy request never changes the pinned chain, contracts or mandate. A signed co-sign only advances `notBefore` towards its expiry (at most 1 day per co-sign, so approved co-signs cannot push the device time, and with it the expiry window, far ahead of real time).
- A request is refused when its chain, DelegationManager, PulseCosignEnforcer, relay or delegator differs from the pinned set, or when the device is not paired. A pinned PulseCosignEnforcer, DelegationManager or relay that differs from the address compiled in for the chain is refused too ("PINNED … DIFFERS FROM FIRMWARE TABLE").
- Layout v3 (big-endian, no padding): `version 3 | chainId u64 | DelegationManager 20 | PulseCosignEnforcer 20 | sentinel 20 | relay 20 | registry 20 | vault 20 | lastDelegationHash 32 | hasAgentId u8 | agentId u64 | minEpoch u64 | reopenNonce u64 | notBefore u64 | pulse token 20 | perTxAutoCap u128 | periodAutoCap u128 | period u32 | newPayeeNeedsHuman u8 | unpanickedMandates u8 | crc32`. Flag bytes other than 0 / 1 are refused.
- **Time:** the device has no clock. Its "not before" time is the later of `notBefore` and a build-time floor (`RIPAR_TIME_FLOOR`, currently 2026-09-26 00:00 UTC). A co-sign expiry more than 7 days after that time, or ≥ 2^40, is refused. A device whose time has fallen more than a week behind (no co-sign for a while, or fewer than about one co-sign per day) needs a pairing with key 9 to update its time.
- The checks live in `firmware/src/policy.cpp`, the review lines in `firmware/src/review.cpp`, and both are host-tested in `firmware/test/host/test_policy.cpp` (the vault derivation in `test_vault.cpp`).

## 7. Changes in firmware v1.2

These follow the contracts v1.2 review (contracts/SPEC.md "Changes in v1.2" and its limitation lists). The wire format is unchanged; every change makes the device refuse more or show more.

| # | v1.1 behaviour | v1.2 behaviour |
|---|---|---|
| 1 | The PulseCosignEnforcer was a placeholder: the address confirmed at the first pairing was trusted (trust on first use). | PulseCosignEnforcer, RiparDeviceRegistry and RiparReputationRelay are compiled in for 10143 and 143 (the 143 relay since the v1.2 review); pair keys 3 / 5 / 7 must equal them (§4). MockUSD (`mUSD`, 6 decimals) is in the token table on 10143. |
| 2 | The vault was pair-req key 8 as sent by the companion; without key 8 any delegator was accepted. | The device derives its vault from K1 (§2.1); key 8 can only confirm it; every mandate / co-sign delegator must equal it. |
| 3 | Context layout v2. | Layout v3: the last mandate's pulse terms and the `unpanickedMandates` flag (§6). v2 blobs load as unpaired. |
| 4 | REVOKE FIRST: a scope-changing re-pairing was refused only while the last mandate was remembered. | PANIC FIRST: refused while any mandate signed since the last panic may be live (§4 `ripar-pair-req`). |
| 5 | The mandate review showed the AUTO period as a plain duration and the agent id without a source; a co-sign did not say that it whitelists its payee. | Period 0 reads `never resets (lifetime cap)`, otherwise `<duration> (fixed windows from the first AUTO spend)`; the agent id is marked `(companion)`; a co-sign for the remembered mandate shows `<payee> becomes an AUTO payee of this mandate` with the caps, exactly when the enforcer's v1.2 predicate holds and the co-sign is not refused; a co-sign for another mandate shows `<payee> may become an AUTO payee of mandate 0x…` (§4 `ripar-cosign-req`). |
| 6 | The pulse gate read the timing jitter that sensor noise puts on a perfectly periodic source as heart-rate variability (firmware v1.2 review). | Cross-channel test and noise-aware edge test (§5). Weak, noisy real pulses with low variability pass later or not at all. |
| 7 | A pairing that moved the chain right after a panic said the forgotten mandate was killed by that panic. | `FORGETS mandate … (killed once this device's last PANIC is relayed)` and a red `PANIC` line asking to check the on-chain min epoch (§4 `ripar-pair-req`). |
