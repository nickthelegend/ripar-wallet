# @ripar/protocol

The companion-side Ripar Wallet device protocol ([docs/PROTOCOL.md](../../docs/PROTOCOL.md)) in TypeScript: CBOR,
BC-UR QR transport, request builders, response parsers and verifiers, and the on-chain helpers the companion and the
agent need (vault address, `redeemDelegations` encoding, AUTO budget, co-sign nonces, ABIs, deployments).

It is a faithful port of [`firmware/tools/make_request.py`](../../firmware/tools/make_request.py), the reference
companion tool the firmware is host-tested against. **For identical inputs (fixed req-id) the requests are
byte-identical**, and every response is verified the same way, down to the check names.

ESM, TypeScript, runtime dependencies: `@noble/curves`, `@noble/hashes`, `viem`. Works in browsers and Node 20+.

## Security model

- The companion and the agent are **untrusted couriers**. The device (or its emulator) decides: it parses every
  request strictly, checks it against the contracts pinned at pairing, shows every signed field and rebuilds every
  digest. This library helps a companion refuse early and verify what comes back; it never decides for the device.
- **This library never asks for, stores or logs a seed or a private key.** There is no signing code in `src/` (the
  test suite has a software demo device with the *public* demo seed, `test/helpers/demo-device.ts`, never exported).
- Every digest is rebuilt from the request and the pinned context, never taken from the device. P-256 signatures
  must be **low-s** (OpenZeppelin `P256.verify` rejects high-s); K1 signatures must be low-s with v = 27/28 and
  recover the paired K1.
- **The emulator is always labelled EMULATOR**: its `ripar-pair` firmware id (key 6) is
  `sha256("ripar-emulator v1")[:8]` = `EMULATOR_FIRMWARE_ID` (`0x7bc44601d30720f1`); `parseResponse` sets
  `fields.emulator` and `verifyPairing` returns `identity.emulator`. Show it, and never put real funds behind it.
- Ripar contract addresses are not final: read them from `contracts/deployments/<chainId>.json` with
  `parseDeployment`, never hard-code them.

## Quick start

```ts
import {
  buildRequest, parseResponse, verifyPairing, expectVerified, computeVaultAddress, randomCosignNonce,
  parseDeployment, pairFieldsFromDeployment, signedDelegation, withCaveatArgs, encodeRedeemDelegations,
  erc20Transfer, UrDecoder,
} from '@ripar/protocol';

// 1. pairing: the contracts to pin come from the deployment JSON; the vault is derived from K1, which the companion
//    learns from the device's keys-only pairing QR (HOME: hold 2 s and release; parseResponse(qr).fields.k1Address)
const dep = parseDeployment(await (await fetch('/deployments/10143.json')).text(), 10143);
const vault = computeVaultAddress(k1);
const pair = buildRequest('pair', pairFieldsFromDeployment(dep, { vault }));
showQrLoop(pair.parts);                     // upper-case multipart UR parts, ~300 ms per frame
const device = verifyPairing(scannedPairUr, pair); // throws unless both BindDevice signatures verify
if (device.emulator) showEmulatorBadge();
if (computeVaultAddress(device.k1Address) !== vault) throw new Error('not the canonical vault of this device');

// 2. a co-sign (HUMAN path)
const req = buildRequest('cosign', {
  chainId: 10143, enforcer: dep.enforcer, delegationHash, delegator: vault, redeemer: agent,
  target: token, nonce: randomCosignNonce(), expiry: now + 3600,
  transfer: { to: payee, amount: 25_000_000n }, ai: { text: 'pay invoice 17', claims: { to: payee, token, amount: 25_000_000n } },
});
const rep = expectVerified(parseResponse(scannedUr, { request: req, p1Key: device.p1Key }));
if (rep.type === 'ripar-cosign') {
  const d = withCaveatArgs(signedDelegation(mandate, mandateRsv), dep.enforcer, rep.fields.caveatArgs!);
  const calldata = encodeRedeemDelegations([{ delegations: [d], target: token, value: 0n, callData: erc20Transfer(payee, 25_000_000n) }]);
}

// 3. device-initiated messages: verify against the pinned context
parseResponse(revokeOrPanicOrReopenUr, { pinned: { chainId: 10143, enforcer: dep.enforcer, sentinel: dep.sentinel, relay: dep.relay }, p1Key: device.p1Key });
```

Scanning the device's answer (always one single-part QR) or a multipart request: feed every decoded QR text to a
`UrDecoder` until `isComplete`; pure and fountain-mixed parts in any order are accepted.

## make_request.py mapping

| make_request.py | @ripar/protocol |
|---|---|
| `build <kind> FIELDS --reqid H --uuid-tag --frag N --extra N --no-now --json` | `buildRequest(kind, {...FIELDS, reqId: H, uuidTag}, {frag, extra, noNow})` → `{type, reqId, map, cbor, ur, parts}` (same field names) |
| `build_pair_req` / `build_cosign_req` / `build_mandate_req` / `build_deny_req` / `build_privy_req` | `buildPairReq` / `buildCosignReq` / `buildMandateReq` / `buildDenyReq` / `buildPrivyReq` (→ CBOR `Map`) |
| `parse <UR> --req R --pair P --p1 X --k1 A --chain N --contract C` | `parseResponse(ur, {request, pairing, p1Key, k1Address, chainId, contract})`; exit 0/1/3 = `result` `VERIFIED` / `FAIL` / `UNVERIFIED` |
| `read_request` / `read_fields` / `guess_kind` | `readRequest` / `readFields` (`decodeRequest`) / `guessKind` |
| `ur_single` / `ur_parts` / `ur_read` / `cbor_decode` / `U.cbor` | `urSingle` / `urParts` / `urRead` / `cborDecode` / `cborEncode` |
| `terms_pulse` / `caveat_terms` / `caveat_from_spec` / `caveat_dump` | `encodePulseTerms` / `caveatTerms` / `caveatFromSpec` / `caveatDump` |
| `decode_erc20` / `ai_matches` / `token_check` / `E.calldata` | `decodeErc20` / `aiMatches` / `tokenCheck` / `erc20Transfer`, `erc20Approve`, `erc20TransferFrom` |
| `cosign_digest` / `cosign_request_hash` / `mandate_digest` / `deny_digest` / `pair_digest` / `revoke_digest` / `panic_digest` / `reopen_digest` / `presence_hash` / `delegation_struct_hash` | `cosignDigest` / `cosignRequestHash` / `mandateDigest` / `denyDigest` / `pairDigest` / `revokeDigest` / `panicDigest` / `reopenDigest` / `presenceHash` / `delegationHash` |
| `canonical_json` / `privy_parse` / `privy_dump` / `p256_spki_b64` / `der_parse` | `canonicalJson` / `privyParse` / `privyDump` / `p256SpkiB64` / `derParse` |
| `ai_text_trunc` / `_text` / `u256_min` / `E.format_units` / `eip55` | `aiTextTrunc` / `checkText` / `u256Min` / `formatUnitsDevice` / `toChecksumAddress` |

Field names of the builders (JSON-compatible; addresses / bytes as `0x` hex or `Uint8Array`, integers as `bigint`,
safe `number`, or `"0x.."` / decimal strings; integers above 2^53 must be `bigint` or strings):

- **pair**: `chainId, registry, manager?, enforcer?, sentinel?, relay?, vault?, now?, minEpoch?, reopenNonce?`
  (`buildRequest` adds `now` = current unix time unless given or `noNow`).
- **cosign**: `chainId, enforcer, delegationHash, delegator, redeemer, target, value?, nonce, expiry`, one of
  `calldata | transfer {to, amount} | approve {spender, amount} | transferFrom {from, to, amount}`,
  `risk? {src, category, label, ageDays}`, `ai? {text, claims? {to, token?, amount}}`, `budgetLeft?`, `decimals?`,
  `symbol?`.
- **mandate**: `chainId, manager, delegate, delegator, authority? (default ROOT), caveats, salt, label?, agentId?`;
  a caveat is `[enforcer, terms]`, `{enforcer, terms}` or typed `{kind, ...}`: `pulse {enforcer, p1Key | px+py,
  token?, perTxAutoCap, periodAutoCap, period, epoch?, newPayeeNeedsHuman?, sentinel?}`,
  `erc20TransferAmount {token, amount}`, `nativeTokenTransferAmount | valueLte | limitedCalls {amount}`,
  `erc20PeriodTransfer {token, amount, duration, start}`, `timestamp {after?, before?}`,
  `allowedTargets | redeemer {addresses}` (MetaMask v1.3.0 enforcer addresses by default, `MM_ENFORCERS`).
- **deny**: `chainId, relay, agentId, requestHash`.
- **privy**: `json` — a string (exact UTF-8 bytes), bytes, or an object (canonical JSON: sorted keys, compact).
- all: `reqId?` (16 bytes; random by default), `uuidTag?` (CBOR tag 37 around the req-id).

## Public API

All exports come from the package root (`src/index.ts`).

**Errors and bytes** (`errors.ts`, `bytes.ts`, `hash.ts`)
- `class ProtoError extends Error` — every refusal (bad builder input, malformed CBOR / UR / response). Signature
  failures are never thrown: they are failed checks.
- types `Hex`, `Address` (`0x${string}`), `BytesLike = Uint8Array | string`, `IntLike = bigint | number | string | Uint8Array`;
  `MAX256`, `MAX64`.
- `unhex(s)`, `h(b)`, `toHex(b)`, `concatBytes(...b)`, `bytesEqual(a, b)`, `isZero(b)`, `bytesToBigInt(b)`,
  `bigIntToBytes(x, n)`, `bitLengthBytes(x)`, `word(x)`, `addrWord(a)`, `toInt(v)`, `toBytes(v, n?, what?)`,
  `toAddr(v, what?)`, `u256Min(x)`, `pyTruthy(v)`, `utf8.{encode, decodeStrict}`, `randomBytes(n)`.
- `sha256(b)`, `keccak256(b)`, `toChecksumAddress(a)` (EIP-55), `isValidAddress(s)`, `parseAddress(s, what?)`
  (refuses a bad checksum), `ethAddressOfXY(xy64)`, `keyIdOf(p1Key)` = keccak256(abi.encode(px, py)).

**CBOR** (`cbor.ts`): `class Tag(tag, value)`; types `CborValue`, `CborKey`, `CborMap = Map<CborKey, CborValue>`;
`cborEncode(v)` (shortest heads, maps in insertion order: ref_ur `cbor()`); `cborDecode(bytes)` (strict: definite
lengths, depth ≤ 16, no floats, scalar untagged unique map keys, UTF-8 text, no trailing bytes; integers decode as
`bigint`); `mget(m, k)`, `mhas(m, k)`, `mkeys(m)`, `cborEqual(a, b)`.

**BC-UR** (`bytewords.ts`, `fountain.ts`, `ur.ts`)
- `WORDS`, `crc32(b)`, `be32(x)`, `bytewordsEncode(b, style?)`, `bytewordsDecode(s, style?)` (`'minimal' | 'standard' | 'uri'`).
- `class Xoshiro256` (`fromString`, `fromCrc32`, `next`, `nextDouble`, `nextInt`, `nextByte`, `nextData`),
  `class RandomSampler`, `chooseDegree`, `shuffled`, `chooseFragments(seqNum, seqLen, crc)`,
  `findNominalFragmentLength`, `partitionMessage`, interface `FountainPart`, `class FountainEncoder(msg, maxFrag,
  minFrag = 10)` (`seqLen`, `fragLen`, `checksum`, `indexes(seq)`, `part(seq)`, `partCbor(seq)`),
  `class FountainDecoder` (optimal GF(2) solver: `receive(part)`, `isComplete`, `message`, `rank`, `seqLen`).
- `DEFAULT_FRAGMENT_LEN = 70`; `urSingle(type, cbor)` and `urPart(type, enc, seq)` (upper case);
  `urParts(type, cbor, frag = 70, extra = 0)` = make_request `ur_parts` (pure parts, then `extra` mixed);
  `urRead(text)` = make_request `ur_read` (a single part wins; pure parts reassembled; CRC checked) → `UrContent
  {type, cbor}`; `decodePartCbor(b)`; `class UrDecoder` (`receive(text)` → `'accepted' | 'duplicate' | 'complete' |
  'ignored'`, `isComplete`, `result`, `progress`, `seqLen`, `partsReceived`, `type`, `reset()`); `isMultipartUr(text)`.

**EIP-712** (`eip712.ts`): `DOMAIN_TYPE`, `TYPE_STRINGS` (exact type strings), `typeHash(name)`, `DOMAIN_NAMES`,
`DOMAIN_OF` (message kind → domain name), `ROOT_AUTHORITY`, `domainSeparator(name, chainId, contract)`,
`digestFrom(sep, structHash)`, `caveatHash`, `delegationHash(d)` (= MetaMask EncoderLib), `humanApprovalHash`,
`revokeHash`, `panicHash`, `reopenHash`, `denyHash`, `bindDeviceHash`, `presenceHash(ev12, salt16)` (SHA-256),
`pairDigest(chain, registry, k1, p1Key)`, `cosignDigest(q, presence)`, `cosignRequestHash(q)` (presence 0: the
requestHash of a device deny), `mandateDigest(chain, manager, d)`, `denyDigest(chain, relay, agentId, requestHash,
presence)`, `revokeDigest(chain, enforcer, dh)`, `panicDigest(chain, enforcer, minEpoch)`, `reopenDigest(chain,
sentinel, vault, nonce)`; viem typed data (`hashTypedData` gives the same digests, tested): `EIP712_TYPES`,
`typedDataDomain`, `typedDataDelegation`, `typedDataHumanApproval`, `typedDataRevoke`, `typedDataPanic`,
`typedDataReopen`, `typedDataDeny`, `typedDataBindDevice`; interfaces `DelegationFields`, `CaveatLike`,
`HumanApprovalFields`, `CosignDigestInput`, `RiparTypedData`, `TypedDataDomain`.

**Caveats, ERC-20, tokens** (`caveats.ts`, `erc20.ts`, `tokens.ts`)
- `MM_ENFORCERS` (MetaMask v1.3.0 addresses), `KIND_ENFORCER`, `enforcerKind(addr)`, interface `PulseTerms`,
  `encodePulseTerms(t)` (288 bytes), `decodePulseTerms(terms)` (strict, canonical words) → `DecodedPulseTerms`,
  types `CaveatSpec`, `CaveatSpecTyped`, `CaveatPair`, `caveatTerms(kind, c)`, `caveatFromSpec(c)`,
  `caveatDump(chain, enforcer, terms, pulseChain, pulseEnforcer)` (the device's decode text, `null` = refused).
- `SEL_TRANSFER`, `SEL_APPROVE`, `SEL_TRANSFER_FROM`, `erc20Transfer(to, amount)`, `erc20Approve(spender, amount)`,
  `erc20TransferFrom(from, to, amount)`, `decodeErc20(calldata)` → `Erc20Call {kind, from, to, amount}`,
  `ERC20_KIND_NUM`, `describeErc20`.
- `AUSD_10143`, `FIRMWARE_TOKENS`, `NATIVE_COINS`, `SUPPORTED_CHAINS`, `firmwareToken(chain, token)`,
  `nativeCoin(chain)`, `tokenCheck(q)` (throws for key 15/16 claims that contradict the firmware table, as the device
  refuses), `aiMatches(q)`, `formatUnits(amount, decimals)`, `formatUnitsDevice(amount, decimals, maxFrac = 6)` (the
  device's amount text, e.g. `1,234.5`, `0.000000...`).

**Privy** (`privy.ts`): `PRIVY_API`, `PRIVY_WALLETS`, `PRIVY_QUORUMS`, `SPKI_P256_PREFIX`, `base64Encode`,
`base64DecodeStrict`, `p256SpkiB64(p1Key)`, `canonicalJson(obj)`, `parseStrictJson(bytes)` (`null` = refused),
`privyParse(json)` → `PrivyView` (throws for anything outside the allow-list), `privyDump(view)`.

**Crypto** (`crypto.ts`): `P256_N`, `SECP256K1_N`, `isLowS(s, n)`, `p256OnCurve(p1Key)`, `p256Verify(p1Key, digest,
r, s)` (plain ECDSA; low-s is a separate check), `k1RecoverAddress(digest, r, s, recid)`, `splitRS(rs)`,
`derParse(der)` (strict), `derEncode(r, s)`.

**Requests** (`requests.ts`)
- `REQ_TYPES`, `RESP_TYPES`, types `RequestKind`, `PairFields`, `CosignFields`, `MandateFields`, `DenyFields`,
  `PrivyFields`, `RequestFields`, `BuildOptions {frag?, extra?, noNow?, nowSeconds?}`, `BuiltRequest {kind, type,
  reqId, map, cbor, ur, parts}`.
- `buildRequest(kind, fields, opts?)`, `buildPairReq`, `buildCosignReq`, `buildMandateReq`, `buildDenyReq`,
  `buildPrivyReq`, `BUILDERS`, `cosignCalldata(f)`, `checkText(s, limit, what)`, `aiTextTrunc(s, limit = 100)`.
- `readFields(kind, map)` / `decodeRequest(kind, cbor)` → `PairRequest | CosignRequest | MandateRequest |
  DenyRequest | PrivyRequest` (`AnyRequest`, bigint / Uint8Array fields), `guessKind(map)`, `readRequest(text)`
  (UR, multipart parts or CBOR hex → `{kind, cbor}`), `requestKindOfType(urType)`.

**Responses** (`responses.ts`)
- `parseResponse(ur | UrContent, opts?)` → `VerifyReport` = `{type, fields, checks: {name, ok}[], unverified:
  string[], ok, result: 'VERIFIED' | 'UNVERIFIED' | 'FAIL'}`. `ParseOptions`: `request` (a `BuiltRequest`,
  `{kind, cbor}` or UR / hex text), `p1Key`, `k1Address`, `pairing` (a pairing UR to take the keys from), `chainId`,
  `contract`, `pinned: PinnedContext {chainId, enforcer?, sentinel?, relay?}` (picks the domain contract per type:
  revoke / panic → enforcer, reopen → sentinel, deny → relay). Malformed responses throw `ProtoError`.
- Field types: `PairResponseFields` (`k1Address, p1Key, px, py, keyId, firmwareId, emulator, reqId?, p1Signature?,
  k1Signature?, bindDigest?`), `CosignResponseFields` (`reqId, rs, r, s, evidence12, evidence, salt16,
  presenceHash, digest?, caveatArgs?`), `DenyResponseFields` (`… agentId, requestHash, digest?`),
  `MandateResponseFields` (`reqId, rsv, delegationHash?, digest?, signer?`), `DerSigResponseFields` (`reqId, der,
  derBase64, r, s`), `RevokeResponseFields`, `PanicResponseFields`, `ReopenResponseFields`, `Evidence`,
  `evidenceFields(ev12)`.
- `expectVerified(rep)` (throws unless `VERIFIED`), `verifyPairing(pairUr, request)` → `DeviceIdentity {k1Address,
  p1Key, px, py, keyId, firmwareId, emulator, p1Signature, k1Signature, bindDigest}` (the registry's
  `registerDevice` arguments), `cosignCaveatArgs(nonce, expiry, presenceHash, rs)` = abi.encode(nonce, expiry,
  presenceHash, r, s) (160 bytes), `denyRequestHashOf(cosignRequest)`, `pinnedContractFor(type, pinned)`,
  `RESPONSE_TYPES`, `EMULATOR_FIRMWARE_ID`.

**Delegations and vault** (`delegation.ts`, `vault.ts`, `constants.ts`, `proxy-bytecode.ts`)
- interfaces `Caveat {enforcer, terms, args}`, `Delegation {delegate, delegator, authority, caveats, salt,
  signature}`, `Redemption {delegations, target, value, callData}`; `CAVEAT_ABI`, `DELEGATION_ABI`,
  `REDEEM_DELEGATIONS_ABI`, `SINGLE_DEFAULT_MODE`.
- `signedDelegation(mandateRequest, rsv)`, `hashDelegation(d)`, `withCaveatArgs(d, enforcer, args)` (`'0x'` =
  AUTO, 160-byte co-sign args = HUMAN), `encodePermissionContext(delegations)` = abi.encode(Delegation[]) (leaf
  first), `decodePermissionContext(ctx)`, `encodeSingleExecution(target, value, callData)`,
  `encodeRedeemDelegations(redemptions)` (single-call default mode). Byte-identical to smart-accounts-kit (tested).
- `computeVaultAddress(k1, opts?)` (the canonical HybridDeleGator counterfactual, deployParams `[K1, [], [], []]`,
  salt 0), `vaultInitCalldata(k1)`, `vaultCreationCode(k1)`, `vaultInitCodeHash(k1)`, `vaultFactoryData(k1)`,
  `VAULT_DEPLOY_SALT`, `HYBRID_INITIALIZE_ABI`, `SIMPLE_FACTORY_DEPLOY_ABI`, `ERC1967_PROXY_CREATION_CODE`.
- `DELEGATION_MANAGER`, `SIMPLE_FACTORY`, `HYBRID_DELEGATOR_IMPL`, `ENTRY_POINT_V07`, `ANY_DELEGATE`,
  `ERC8004_TESTNET`, `MONAD_TESTNET_CHAIN_ID`, `MONAD_MAINNET_CHAIN_ID`, `FIRMWARE_CHAIN_IDS`.

**Contracts, deployments, AUTO path, nonces** (`abis.ts`, `deployments.ts`, `budget.ts`, `nonce.ts`)
- viem ABIs: `PULSE_COSIGN_ENFORCER_ABI`, `RIPAR_DEVICE_REGISTRY_ABI`, `RIPAR_SENTINEL_ABI`,
  `RIPAR_REPUTATION_RELAY_ABI` (= `contracts/src/interfaces/*.sol`, tested), `DELEGATION_MANAGER_ABI`,
  `ERC8004_IDENTITY_ABI`, `ERC173_OWNER_ABI`.
- `parseDeployment(json, expectChainId?)` → `RiparDeployment {chainId, salt, create2Deployer, registry, enforcer,
  sentinel, relay, mockUsd, creForwarder, expectedWorkflowOwner, erc8004Identity, erc8004Reputation,
  delegationManager}`, `DEPLOYMENT_JSON_KEYS`, `pairFieldsFromDeployment(dep, extra?)` (refuses a chain outside the
  firmware table or a foreign DelegationManager).
- `AutoBudget {spent, remaining, periodStart, periodEnd}` (the enforcer's `autoBudget` view), `StoredPeriod`,
  `rolloverPeriod`, `computeAutoBudget(terms, stored, now)`, `autoPathDecision(terms, call, state)` →
  `{path: 'auto', …} | {path: 'human', reason}` with `EscalationReason = 'not-meterable' | 'lane-closed' |
  'per-tx-cap' | 'new-payee' | 'period-cap'` (the enforcer's order), `ExecutionCall`, `AutoPathState`,
  `EscalationRequest` (what an agent hands the companion to build a co-sign).
- `randomCosignNonce(bytes = 8)` (non-zero, CSPRNG), `class CosignNonceTracker(bytes = 8)` (`next(dh)`,
  `nextUnused(dh, isUsedOnChain)`, `markUsed`, `has`): v1.2 nonces are single-use per mandate.

## Tests

```bash
export npm_config_cache=F:/tools/npm-cache
cd packages/protocol
npx vitest run          # python on PATH (or RIPAR_PYTHON); ~25 s
npx tsc -p tsconfig.json --noEmit
npm run build           # dist/ (ESM + .d.ts)
```

- `test/vectors.test.ts`: byte-for-byte against `contracts/test/vectors/device_vectors.json` (every request CBOR /
  UR / part count rebuilt from the generator's inputs, every response parsed and verified, digests, type hashes,
  domain separators, terms, caveat args, delegation / presence / request hashes, the firmware ERC-20 decode table,
  viem `hashTypedData` equality).
- `test/differential.test.ts`: `make_request.py build --json` (spawned, fixed `--reqid`) vs `buildRequest`, builder
  refusals, a corpus from make_request's own generators (`test/py/oracle.py corpus`: identical CBOR / parts /
  read_fields facts / demo responses / check lists), TS requests answered by `make_request.py simulate` and TS
  responses verified by `make_request.py parse`, the Privy allow-list and strict-JSON vectors, `format_units`,
  `caveat_dump`.
- `test/emulator.test.ts`: round trips with `firmware/emu/dist/ripar-emu.mjs` (test mode): pair (multipart), keys-only
  pairing QR, mandate, co-signs, deny from the review, companion deny, Privy fed as mixed fountain parts, revoke,
  PANIC, reopen, and refusals (NOT PAIRED, MANDATE WITHOUT PULSE CO-SIGN, WRONG CHAIN, UNKNOWN CALLDATA, token
  table, NOT THE PINNED AGENT, Privy `/rpc`, stale epoch).
- `test/negative.test.ts`: tampered signatures / evidence / values / req-ids, high-s twins (P-256 and secp256k1),
  wrong chain and contract domains, wrong keys, missing context, malformed CBOR / UR / DER.
- `test/transport.test.ts`: official bc-ur vectors, fountain decoding from mixed parts only, canonical CBOR.
- `test/apps.test.ts`: vault derivation and `redeemDelegations` encoding vs `@metamask/smart-accounts-kit` 2.0.0,
  ABIs vs the `.sol` interfaces, deployments, AUTO budget / escalation, nonces, EIP-55.

The Python helpers run with `python -B` and never write into `firmware/`.

## Differences from make_request.py (deliberate)

- `canonicalJson` refuses non-integer numbers (Privy payloads carry none; Python would print its float `repr`).
- `privyParse` refuses `"privy-idempotency-key": null`, as the firmware does (`protocol.cpp`); make_request's
  `privy_parse` treats it as absent.
- `readFields` type-checks every key it reads (a malformed map is a `ProtoError`, not a Python exception).
- `urRead` is make_request's `ur_read` (pure parts only); `UrDecoder` additionally solves fountain-mixed parts.
- JavaScript `number`s above 2^53 are refused: pass `bigint` or a string.
- `guessKind` keeps make_request's heuristic, including its quirk: a bare CBOR pair map with key 11 (`reopenNonce`)
  reads as a co-sign. A UR always carries its type, so prefer URs.

## Development without a build

`package.json` exports a `ripar-source` condition that points at `src/index.ts`: a Vite / TS bundler consumer can
set `resolve.conditions: ['ripar-source']` (and `customConditions` in its tsconfig) to use the sources directly.
Otherwise run `npm run build -w @ripar/protocol` first.
