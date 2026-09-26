# Ripar Wallet: device protocol v1

This is the contract between the **air-gapped device firmware**, the **companion app** and the **smart contracts**. Everything travels as QR codes. The device has no radio: Wi-Fi and Bluetooth are never initialised.

The companion app is **untrusted**. It only carries data. The device parses every request strictly, checks it against the contracts it **pinned at pairing** (§6), shows every field that is signed, and rebuilds every digest itself.

## 1. Transport: BC-UR over QR

- Encoding follows BC-UR (BCR-2020-005): `ur:<type>/<bytewords>`, with a CBOR payload in *minimal* bytewords and a CRC-32 at the end.
- QR codes carry the UR **upper-cased**, so they fit QR alphanumeric mode.
- **Companion → device:** a single part `ur:<type>/<bw>`, or a multipart `ur:<type>/<seq>-<len>/<bw>`.
  - Each multipart fragment is the standard CBOR array `[seqNum, seqLen, messageLen, checksum(crc32 of message), fragment]`.
  - The device accepts **pure** fragments (`seqNum ≤ seqLen`). It also accepts mixed fountain fragments (Xoshiro256** part selection per BC-UR) when they complete the set.
  - The companion should loop the pure fragments, each 60–80 bytes, at about 300 ms per frame.
- **Device → companion:** always one single-part QR.

Every request map carries key `1` = request id. The id is a byte string of 16 bytes, which may be a UUID (CBOR tag 37). The response echoes it back as a plain byte string.

## 2. Keys

- **Seed:** a 256-bit master seed.
  - It comes from SHA-256 of an entropy pool, built on the first run: `esp_fill_random()` with the SAR-ADC entropy source switched on (`bootloader_random_enable()`, since the radios never run), plus camera frames, raw MAX30102 samples and timing jitter mixed in by the firmware (`flows.cpp` `create_keys()`), plus a second TRNG draw and a timer value in `keys_create()`.
  - It is stored in NVS. Encryption comes in P1.
- **K1 (secp256k1):** BIP-32 from the seed (`HMAC-SHA512("Bitcoin seed", seed)`), path `m/44'/60'/0'/0/0`.
  - K1 owns the vault and signs **only** `Delegation` mandates (and `BindDevice`).
  - Its address is `keccak256(pubX‖pubY)[12:]`.
- **P1 (P-256 / secp256r1):** SLIP-10 from the seed (`HMAC-SHA512("Nist256p1 seed", seed)`), path `m/7951'/0'`.
  - P1 signs co-signatures, revoke, panic, reopen, deny, `BindDevice` and Privy requests.
  - Its public key travels as `px‖py`, 64 bytes uncompressed, without the 0x04 prefix.
- **All ECDSA signatures:** RFC 6979 deterministic nonces with SHA-256, and **low-s**, i.e. `s ≤ n/2`. OpenZeppelin `P256.verify` and `ECDSA.recover` reject high-s.
- **The device never signs a digest it was handed.** Every digest is rebuilt on the device from the same parsed request that produced the review screen (`firmware/include/review.h`).

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

The verifyingContract and chainId of every domain are the ones **pinned at pairing** (§6), never the ones a request names (a request that names others is refused).

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
| 3 | registry `addr` (RiparDeviceRegistry) | P1 key `bstr(64)` = px‖py |
| 4 | DelegationManager `addr` (optional) | P1 signature `bstr(64)` r‖s over `BindDevice(owner=K1, px, py)` |
| 5 | PulseCosignEnforcer `addr` (optional) | K1 signature `bstr(65)` r‖s‖v over the same digest |
| 6 | RiparSentinel `addr` (optional) | firmware id `bstr(8)` (first 8 bytes of SHA-256 of the app image) |
| 7 | RiparReputationRelay `addr` (optional) | |
| 8 | vault `addr` (HybridDeleGator owned by K1, optional) | |
| 9 | now `uint` (companion clock, unix s, < 2^40, optional) | |
| 10 | minEpoch floor `uint` (< 2^63, optional) | |
| 11 | reopenNonce floor `uint` (< 2^63, optional) | |

- The DelegationManager must equal the firmware's MetaMask v1.3.0 address `0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3`; when key 4 is absent, that address is pinned.
- Once the PulseCosignEnforcer address is compiled into the firmware (`firmware/src/enforcers.cpp`, **TODO after deployment**), key 5 must equal it. Until then key 5 is what gets pinned.
- A missing sentinel, relay or vault is shown as a warning: without a sentinel there is no reopen, without a relay no deny, and without a vault any delegator is accepted (and shown in full).
- Key 9 advances the device's "not before" time (§6), shown as UTC. The companion should always send it (`make_request.py build pair` adds the current time). A time more than 30 days after the device's current time is shown in red.
- Keys 10 and 11 are **floors** for the device's panic epoch and reopen nonce: the device keeps `max(its own value, the floor)`, so they can only raise the counters, never lower them. Use them after the device lost its context (the counters then restart at 0): send the on-chain `minEpoch` of the device key and the last reopen nonce the sentinel saw. Both counters, and any raise, are shown on the review.
- Pairing again replaces the pinned set. The panic epoch and the reopen nonce never go back. The review lists every pinned value that changes, old → new, in red.
- While the device remembers a mandate it signed (`lastDelegationHash`, §6), a pairing that would change the chain, the DelegationManager, the PulseCosignEnforcer or the vault is **refused** ("REVOKE FIRST"): the device would forget that mandate while it stays live, and its revoke and panic would then target the new contract. Revoke the mandate first (the device then forgets it), then pair again. Sentinel, relay and registry may change.

Without a request (home screen → PAIR), the device outputs keys 2, 3 and 6 only and pins nothing.

### `ripar-cosign-req` (in) → `ripar-cosign` (out)

| key | request | notes |
|---|---|---|
| 1 | req-id | |
| 2 | chainId `uint` | must equal the pinned chain |
| 3 | enforcer `addr` | must equal the pinned PulseCosignEnforcer (the domain verifyingContract) |
| 4 | delegationHash `bstr(32)` | flagged **UNKNOWN MANDATE** unless it is the last mandate this device signed |
| 5 | delegator (vault) `addr` | must equal the pinned vault (when one is pinned) |
| 6 | redeemer `addr` | |
| 7 | target `addr` | ERC-20 token or native payee |
| 8 | value `u256` | native value |
| 9 | calldata `bstr` | the device decodes ERC-20 `transfer`, `approve` and `transferFrom` |
| 10 | nonce `u256` | |
| 11 | expiry `uint` (unix s) | must be < 2^40 and at most 7 days after the device's "not before" time (§6); shown as UTC |
| 12 | risk `{1: src text, 2: category text, 3: label text, 4: ageDays uint}` | optional, shown as "(companion)" |
| 13 | ai `{1: text ≤100, 2: {1: to addr, 2: token addr, 3: amount u256}}` | optional; the device checks the claims against its own decode |
| 14 | budgetLeft `u256` | optional, for display, "(companion)" |
| 15 | token decimals `uint` | optional **claim**, see below |
| 16 | token symbol `text` | optional **claim**, see below |

Checks and display:
- Refused: calldata that is not empty and not exactly one of the three ERC-20 calls (**UNKNOWN CALLDATA**), and an ERC-20 call with a non-zero native value.
- **Token table** (`firmware/src/tokens.cpp`): the asset of the amount is the native coin for empty calldata, otherwise the call target. For a listed asset (AUSD `0xa9012a055bd4e0eDfF8Ce09f960291C09D5322dC`, 6 decimals, on 10143; MON, 18 decimals, on 10143 and 143) the table's decimals and symbol are used, and a request whose key 15 or 16 disagrees with the table is **refused**. An unlisted token is shown as the raw integer in base units, the full token address and **UNKNOWN TOKEN - decimals unverified**; a companion symbol is shown as "(companion)". MockUSD is a placeholder until it is deployed.
- **AI claims** match only a plain native send (to = target, token = zero, amount = value) or an ERC-20 `transfer` (to, token = target, amount; no native value). `approve` and `transferFrom` never match.
- Every address is shown as the full 42-character EIP-55 form.

The response is `{1: req-id, 2: r‖s bstr(64), 3: evidence12 bstr(12), 4: salt16 bstr(16)}`. The companion recomputes `presenceHash` and relays `abi.encode(nonce, expiry, presenceHash, r, s)` as the caveat args.

### `ripar-mandate-req` (in) → `eth-signature` (out, ERC-4527 shape)

| key | request |
|---|---|
| 1 | req-id |
| 2 | chainId `uint` (must equal the pinned chain) |
| 3 | DelegationManager `addr` (must equal the pinned one) |
| 4 | delegate `addr` (not ANY_DELEGATE `0x…0a11`) |
| 5 | delegator `addr` (must equal the pinned vault, when one is pinned) |
| 6 | authority `bstr(32)` (must be ROOT) |
| 7 | caveats `[[enforcer addr, terms bstr], …]`, 1 to 16 entries |
| 8 | salt `u256` |
| 9 | label `text` (optional, ≤ 64 bytes, shown as "(companion)") |
| 10 | agentId `uint` (optional; the agent a deny is filed against) |

The response is `{1: req-id, 2: r‖s‖v bstr(65)}`, with v = 27 or 28.

**Mandate policy** (`firmware/src/policy.cpp` `check_mandate`):
- **Exactly one** caveat must use the pinned PulseCosignEnforcer, otherwise the device refuses with **MANDATE WITHOUT PULSE CO-SIGN**.
- Its terms must name **this device's** P1 key and an epoch **exactly equal** to the device's panic floor `minEpoch` (the last panic epoch it signed, or the pairing floor; 0 on a new device). The enforcer kills a mandate when `terms.epoch < minEpoch`, and the device's next panic is `minEpoch + 1`, so a higher epoch would survive every panic the device can sign. A lower epoch is stale.
- Its sentinel must be exactly the pinned one, or the zero address when no sentinel is pinned (a mandate cannot name a sentinel lane the user never confirmed at pairing).
- **Every** caveat must have a strict terms decoder. The device shows every decoded field. Any other enforcer, known or not, is refused (UNKNOWN ENFORCER, or e.g. "NonceEnforcer is not supported").

Terms layouts the device decodes, with exact lengths (MetaMask delegation-framework v1.3.0 `getTermsInfo`, same addresses on 10143 and 143):

| enforcer | terms | bytes |
|---|---|---|
| Ripar PulseCosignEnforcer | `abi.encode(bytes32 px, bytes32 py, address token, uint128 perTxAutoCap, uint128 periodAutoCap, uint32 period, uint64 epoch, bool newPayeeNeedsHuman, address sentinel)`; every word canonical | 288 |
| ERC20TransferAmountEnforcer `0xf100…D2Fc` | token (20) ‖ maxAmount uint256 | 52 |
| NativeTokenTransferAmountEnforcer `0xF71a…0320` | allowance uint256 | 32 |
| ValueLteEnforcer `0x92Bf…6A8F` | max value uint256 | 32 |
| LimitedCallsEnforcer `0x0465…5416` | max calls uint256 | 32 |
| ERC20PeriodTransferEnforcer `0x474e…39aB` | token (20) ‖ periodAmount ‖ periodDuration (> 0) ‖ startDate | 116 |
| TimestampEnforcer `0x1046…c069` | afterThreshold uint128 ‖ beforeThreshold uint128 (0 = no bound) | 32 |
| AllowedTargetsEnforcer `0x7F20…4EeB` | 1 to 16 packed addresses | 20·n |
| RedeemerEnforcer `0xE144…65c5` | 1 to 16 packed addresses | 20·n |

After signing, the device remembers the mandate: `lastDelegationHash = hashStruct(Delegation)` (what `ripar-revoke` revokes) and its agentId. Only the last mandate is remembered; every mandate the device signed is killed by its next panic.

### `ripar-deny-req` (in) → `ripar-deny` (out)

- Request: `{1: req-id, 2: chainId, 3: relay addr, 4: agentId uint, 5: requestHash bstr(32)}`.
  - The chain and relay must be the pinned ones.
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
| `ripar-reopen` | `{1: vault addr, 2: nonce u256, 3: r‖s}` | RiparSentinel |

- **Panic:** hold SIGN for 5 s on the home screen. No pulse check is needed, because panic can only tighten. `minEpoch` is the device's panic floor + 1. Every mandate the device signed carries an epoch equal to the floor at that time (§4 mandate policy), so a relayed panic kills all of them, even if an earlier panic QR was never relayed. The enforcer only accepts a new `minEpoch` above its current one: after a lost context, pair with the on-chain floor (key 10) first. If the new epoch cannot be stored, the device still uses it until it restarts and says so on the QR screen.
- **Revoke:** signs `Revoke(lastDelegationHash)` for the pinned enforcer (the one shown on the review), then the device forgets that mandate (a co-sign for it then shows UNKNOWN MANDATE). Scan the QR before leaving the screen: it cannot be shown again. The panic still covers it.
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

The device keeps one pinned **context** in NVS (`firmware/include/context.h`, layout version 2, CRC-protected). A blob with another version or a bad CRC is ignored, and the device then counts as unpaired.

| field | set by |
|---|---|
| chainId, DelegationManager, PulseCosignEnforcer, sentinel, relay, registry, vault | a pairing the user confirmed with pulse + SIGN |
| lastDelegationHash, agentId | a mandate the device signed; a revoke the device signed clears lastDelegationHash |
| minEpoch | a panic the device signed, or the pairing floor (key 10) (only ever increases) |
| reopenNonce | a reopen the device signed, or the pairing floor (key 11) (only ever increases) |
| notBefore | the pairing clock (key 9) and the expiry of each co-sign the device signed, by at most 1 day per co-sign (only ever increases) |

- A co-sign, deny or Privy request never changes the pinned chain, contracts or mandate. A signed co-sign only advances `notBefore` towards its expiry (at most 1 day per co-sign, so approved co-signs cannot push the device time, and with it the expiry window, far ahead of real time).
- A request is refused when its chain, DelegationManager, PulseCosignEnforcer, relay or delegator differs from the pinned set, or when the device is not paired.
- **Time:** the device has no clock. Its "not before" time is the later of `notBefore` and a build-time floor (`RIPAR_TIME_FLOOR`, currently 2026-09-26 00:00 UTC). A co-sign expiry more than 7 days after that time, or ≥ 2^40, is refused. A device whose time has fallen more than a week behind (no co-sign for a while, or fewer than about one co-sign per day) needs a pairing with key 9 to update its time.
- The checks live in `firmware/src/policy.cpp`, the review lines in `firmware/src/review.cpp`, and both are host-tested in `firmware/test/host/test_policy.cpp`.
