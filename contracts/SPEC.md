# Ripar contracts: behaviour spec (v1.2)

The interfaces in `src/interfaces/` are the API and are fixed. This file gives the behaviour. `docs/PROTOCOL.md` is the byte-level contract with the device firmware. Where the two disagree, PROTOCOL.md wins; flag the difference instead of guessing.

## Toolchain and layout

- **Foundry:** Foundry 1.5.1 (`F:/tools/foundry` on the build PC; the drive letter can change), solc **0.8.23** (the framework pins `pragma solidity 0.8.23`), `evm_version = "shanghai"`.
- **OpenZeppelin:** v5.1.0 in `lib/openzeppelin-contracts`. It provides `P256`, `ECDSA`, `EIP712`, `ERC20` and `IERC165`. Don't import files whose pragma needs 0.8.24 or later (the transient-storage ones).
- **Delegation framework:** MetaMask v1.3.0 in `lib/delegation-framework`. Import it as `@delegation-framework/...`, `@erc7579/...`, `@account-abstraction/...` or `@SCL/...`.
- **Contracts:**
  - `src/PulseCosignEnforcer.sol` inherits the framework's `CaveatEnforcer` and implements `IPulseCosignEnforcer`.
  - `src/RiparDeviceRegistry.sol`
  - `src/RiparSentinel.sol`
  - `src/RiparReputationRelay.sol`
  - `src/MockUSD.sol`
- **No admin keys, upgradability or pausing** in any Ripar contract. The contracts are deployed with CREATE2 through the deterministic deployer `0x4e59b44847b379578588920cA78FbF26c0B4956C`, so the firmware can pin their addresses.

## EIP-712 (must match firmware byte-for-byte)

- **Domain type:** `EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)`. OpenZeppelin `EIP712(name, "1")` produces exactly this type.
- **Domain names:**
  - `RiparPulseCosign` for the enforcer;
  - `RiparDeviceRegistry`;
  - `RiparSentinel`;
  - `RiparReputationRelay`.
- **Structs** (type strings exactly as written):
  - `HumanApproval(bytes32 delegationHash,address delegator,address redeemer,address target,uint256 value,bytes32 callDataHash,uint256 nonce,uint64 expiry,bytes32 presenceHash)`
  - `Revoke(bytes32 delegationHash)`
  - `Panic(uint64 minEpoch)`
  - `Reopen(address vault,uint256 nonce)`
  - `Deny(uint256 agentId,bytes32 requestHash,bytes32 presenceHash)`
  - `BindDevice(address owner,bytes32 px,bytes32 py)`
- **Hashing rules:**
  - `callDataHash = keccak256(callData)` of the single execution's callData.
  - `presenceHash` is an opaque bytes32 on-chain; the device computes it as `sha256(evidence12 ‖ salt16)`.
- **Signatures:** every P-256 signature is `(r, s)` with **low-s**; OZ `P256.verify` rejects high-s. K1 signatures are 65 bytes `r‖s‖v` with v = 27/28, verified with OZ `ECDSA.recover`.
- **`keyId = keccak256(abi.encode(px, py))`.**

## PulseCosignEnforcer.beforeHook(terms, args, mode, executionCallData, delegationHash, delegator, redeemer)

**Modifiers and storage keys:**
- Modifiers: `onlySingleCallTypeMode(mode)` and `onlyDefaultExecutionMode(mode)`.
- State is keyed by `msg.sender` (the DelegationManager) wherever these notes say "manager".

**Steps:**

1. **Decode terms.** `terms.length == 288`, otherwise `InvalidTerms()`. Decode with `abi.decode(terms, (PulseTerms))`; the ABI decoder already reverts on non-canonical words. `keyId = keyIdOf(px, py)`.
2. **Revocation and epoch.**
   - Revert `DelegationRevoked()` if `isRevoked(keyId, delegationHash)`.
   - Revert `StaleEpoch()` if `terms.epoch < minEpoch(keyId)`.
3. **Decode the call.** `(target, value, callData) = ExecutionLib.decodeSingle(executionCallData)` gives `callDataHash`, the payee and the amount:
   - **Native send:** `callData.length == 0`. The payee is `target` and the amount is `value`.
   - **ERC-20** (the first 4 bytes are the selector and the call is exactly ABI-sized):
     - `transfer(address to,uint256 amount)` (0xa9059cbb): payee `to`, amount `amount`.
     - `approve(address spender,uint256 amount)` (0x095ea7b3): payee `spender`, amount `amount`.
     - `transferFrom(address from,address to,uint256 amount)` (0x23b872dd): payee `to`, amount `amount`.
   - **Anything else:** payee `address(0)`, amount 0, and the call is "unmetered".
4. **Choose the path by `args`.** An empty `args` is the **AUTO** path. `args.length == 160` is the **HUMAN** path, decoded as `abi.decode(args, (uint256 nonce, uint64 expiry, bytes32 presenceHash, bytes32 r, bytes32 s))`. Any other length reverts `InvalidArgs()`.

**AUTO path.** The checks run in this order:
1. **Meterable call.** The call must be meterable for the terms:
   - `terms.token == 0`: a native send (empty callData) with `value > 0`.
   - `terms.token != 0`: `target == terms.token`, `value == 0`, and a `transfer` call. **`approve` and `transferFrom` are never auto.**
   - Anything else reverts `HumanRequired()`.
2. **Sentinel.** If `terms.sentinel != 0` and `IRiparSentinel(terms.sentinel).laneOpen(delegator)` is false, revert `LaneClosed()`.
3. **Per-transaction cap.** Revert `HumanRequired()` if `amount > terms.perTxAutoCap`.
4. **Known payee.** Revert `HumanRequired()` if `terms.newPayeeNeedsHuman` and `!isKnownPayee(manager, delegationHash, payee)`. Known payees are **per mandate** (v1.1).
5. **Period.** Storage `(spent, start)` is keyed by `(manager, delegationHash)`.
   - The period is reset when `terms.period != 0 && start != 0 && block.timestamp >= start + period`. The new start is aligned: `start += ((now - start) / period) * period`, and `spent` returns to 0.
   - The first AUTO spend sets `start = block.timestamp`.
   - `terms.period == 0` means the cap never resets.
   - Revert `HumanRequired()` if `spent + amount > terms.periodAutoCap`. Otherwise store `spent += amount` and emit `AutoSpend(delegationHash, delegator, redeemer, payee, amount, spent)`.

**HUMAN path.**
1. Revert `CosignExpired()` if `block.timestamp > expiry`.
2. `digest = approvalDigest(delegationHash, delegator, redeemer, target, value, keccak256(callData), nonce, expiry, presenceHash)`. Revert `CosignReplayed()` if `consumed(manager, digest)`.
3. Revert `BadCosign()` unless `P256.verify(digest, r, s, px, py)`.
4. **Record.** Store `Approval{keyId, delegationHash, delegator, redeemer, payee, timestamp}` under the digest; this marks it consumed.
   - The record is keyed by `(manager, digest)` (v1.1). Replay protection is per manager.
   - **Known payees (v1.1).** Only a native-send target or an ERC-20 `transfer` recipient (`payee != 0`) becomes a known payee, for `(manager, delegationHash)`; emit `PayeeApproved(manager, delegationHash, payee)` the first time. An `approve` spender, a `transferFrom` recipient and unmetered calls never do.
   - Emit `HumanCosigned(...)`. Its amount is the decoded amount, or `value` for native or unmetered calls.
5. HUMAN spends do **not** count toward the AUTO period.
6. The HUMAN path works whatever the sentinel says. Any call the device signed is allowed; the device itself refuses calldata it cannot decode.

**Kill switch.** Both functions are callable by anyone and carry the device's signature.
- **`revoke`:** `P256.verify(revokeDigest(h), r, s, px, py)`, otherwise `BadSignature()`. Idempotent: the event fires only the first time.
- **`panic`:** `newMinEpoch > minEpoch(keyId)`, otherwise `EpochNotIncreasing()`. `P256.verify(panicDigest(newMinEpoch))`, otherwise `BadSignature()`. It then sets `minEpoch` and emits `Panicked`.

**Views (v1.1).** `autoBudget(manager, delegationHash, terms)` returns the AUTO budget with the period rollover applied:
- `spent` in the current period, `remaining = periodAutoCap - spent`, and the period's `periodStart` / `periodEnd`;
- a period that has elapsed reads as spent 0 with the next aligned window;
- `periodEnd = 0` when `period == 0` or nothing was spent yet.

**Events (v1.1).** `AutoSpend` and `HumanCosigned` carry `delegationManager` (the hook's msg.sender), so indexers can keep only the canonical DelegationManager.

**Other hooks.** `afterHook` and the other hooks stay no-ops, inherited from the framework.

**Gas.** Monad charges for the gas **limit**, so keep storage writes minimal: pack `Approval` into as few slots as possible. The precompile at 0x0100 costs 6,900 gas. OZ `P256.verify` falls back to Solidity verification when the precompile is absent, as in a local EVM.

## RiparDeviceRegistry

- **Registering:** `registerDevice` checks `owner != 0` and `P256.verify(bindDigest)`, otherwise `BadDeviceSignature()`. `ECDSA.recover(bindDigest, ownerSig)` must equal `owner`, otherwise `BadOwnerSignature()`; malformed signatures must revert with that error, not bubble up OZ errors.
- **Key already bound:** if the key is bound to a different owner, revert `KeyTaken()`.
- **Re-registering an owner:** the owner's old key is unlinked (`keyOf(old).owner = 0`), and the new key is bound both ways.
- **Same owner and same key again:** a no-op success that still emits the event.

## RiparSentinel

- **Constructor:** `constructor(address forwarder, IRiparDeviceRegistry registry, address expectedWorkflowOwner)`. When `expectedWorkflowOwner` is `address(0)`, the metadata check is skipped.
- **`onReport`:**
  - Only the forwarder may call it, otherwise `NotForwarder()`.
  - The workflow owner in the metadata is `address(bytes20(metadata[42:62]))`, from the packed layout `workflowId(32) ‖ workflowName(10) ‖ workflowOwner(20)`. If an owner is expected, it must match, otherwise `BadWorkflowOwner()`.
  - The report must be exactly 128 bytes (`abi.encode(address,bool,uint8,uint64)`), otherwise `BadReport()`.
  - A report with `open == true` reverts `BadReport()`.
  - If `asOfBlock < lastReopenBlock[vault]`, emit `ReportIgnored` and return. Otherwise close the lane and emit `LaneChanged(vault, false, reason, asOfBlock)`.
- **`supportsInterface`:** returns true for `IReceiver` and `IERC165`.
- **`reopen`:**
  - The owner is `IERC173(vault).owner()`, read with try/catch; a failure reverts `NoDeviceForVault()`.
  - `keyId = registry.keyIdOf(owner)`; `keyId == 0` reverts `NoDeviceForVault()`.
  - `nonce > lastReopenNonce[vault]`, otherwise `NonceNotIncreasing()`.
  - `P256.verify(reopenDigest)`, otherwise `BadReopenSignature()`.
  - It then opens the lane, stores the nonce, sets `lastReopenBlock = block.number` and emits `LaneChanged(vault, true, 0, uint64(block.number))`.

## RiparReputationRelay

- **Constructor:** `constructor(IERC8004Reputation reputation, IERC8004Identity identity, IPulseCosignEnforcer enforcer, IRiparDeviceRegistry registry, address delegationManager)`. `delegationManager` is the canonical MetaMask DelegationManager `0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3`.
- **`attestApproval`** (v1.1):
  - `enforcer.consumed(delegationManager, d)` for the relay's canonical DelegationManager (an immutable), otherwise `NotConsumed()`. Records made by anyone calling `beforeHook` directly are never trusted.
  - With `a = enforcer.approvalOf(delegationManager, d)`: `msg.sender == a.redeemer`, otherwise `NotRedeemer()`.
  - `identity.isAuthorizedOrOwner(a.redeemer, agentId)` must be true (a revert counts as false), otherwise `NotAgentRedeemer()`.
  - The digest must not have been attested yet, otherwise `AlreadyAttested()`.
  - It calls `giveFeedback(agentId, 1, 0, "ripar", "cosigned", "", "", d)` and emits `Verdict(agentId, a.keyId, d, true)`.
- **`attestDenial`:**
  - `keyId = keccak256(abi.encode(px, py))`. `registry.keyOf(keyId).owner != 0`, otherwise `UnknownDevice()`.
  - `P256.verify(denyDigest(agentId, requestHash, presenceHash))`, otherwise `BadDenySignature()`.
  - Each `(keyId, requestHash)` counts once, otherwise `AlreadyAttested()`.
  - It calls `giveFeedback(agentId, -1, 0, "ripar", "denied", "", "", requestHash)` and emits `Verdict(agentId, keyId, requestHash, false)`.
- **Known limitation (document it):** anyone can register a device key, so denials are Sybil-able. Reputation readers should weigh the verdicts.

## MockUSD

- An `ERC20("MockUSD (Ripar demo)", "mUSD")` with **6 decimals**, matching `firmware/src/tokens.cpp`.
- A public `faucet(address to, uint256 amount)` with at most `1_000e6` per call.
- No owner. Testnet only; say so in the NatSpec.

## Changes in v1.1 (after the first build's findings)

| # | Problem found | v1.1 behaviour |
|---|---|---|
| 1 | Anyone could call `beforeHook` directly with a pending redemption's caveat args. That burnt the device co-sign (the real redemption then got `CosignReplayed`) and left an `Approval` record the relay would credit. | Approvals and replay protection are keyed by `(manager, digest)`. The relay trusts only the canonical DelegationManager's records. |
| 2 | Known payees were keyed by `(manager, delegator)`, so they survived revoke and panic: a fresh mandate could AUTO-pay every earlier payee. | Known payees are keyed by `(manager, delegationHash)`. A new mandate starts with an empty list. |
| 3 | A human `approve` made the spender an AUTO payee, and `transferFrom` did the same for its recipient. | Only native-send targets and `transfer` recipients become known payees. |
| 4 | Anyone could run `attestApproval` for any agent that authorized the redeemer, so another agent's owner could front-run and take the credit. | Only the approval's redeemer can attest it. |
| 5 | `periodSpent` is lazy, so companions misread the budget after a rollover. | Added the `autoBudget` view, which applies the rollover. |

**Documented, not changed:**
- **Failure-path gas.** OZ `P256.verify` falls back to Solidity when the precompile returns empty, which is how it reports an invalid signature. A failing co-sign, revoke or panic therefore costs about 250k gas, even on Monad.
- **Stale reports.** The CRE workflow must report `asOfBlock >= ` the block of the last reopen, otherwise its close report is ignored.
- **Re-delegation.** An agent can re-delegate its mandate. The AUTO caps stay shared (keyed by the root delegation hash), and co-signs must name the sub-agent. The device can forbid this with a RedeemerEnforcer caveat.
- **Deny is reputation-only.** A deny does not block a later co-sign.
- **Denials are Sybil-able.** Anyone can register a device key.

## Changes in v1.2 (after the adversarial review: 25 raw findings, 12 confirmed by the judge)

These rules override the sections above wherever the two differ.

**Enforcer**
- **Known-payee predicate.** A HUMAN co-sign whitelists its payee only when all of these hold:
  - the call is *meterable for the mandate*, meaning the AUTO step-1 predicate holds:
    - `token == 0`: a native send with `value > 0`;
    - otherwise: `transfer` on `terms.token`, with `value == 0` and `amount > 0`;
  - `payee != 0`.

  A 0-value co-sign, a foreign-asset co-sign, or one on another token never whitelists.
- **Nonce.** The co-sign nonce is single-use per `(manager, delegationHash, nonce)`.
  - After the digest replay check, revert `CosignReplayed()` if the nonce is used.
  - Mark it used only after `P256.verify` succeeds.
  - The view `nonceUsed(manager, delegationHash, nonce)` reads it.

**Relay**
- **`attestApproval` checks.** After `NotRedeemer`, the approval's `keyId` must be registered (`registry.keyOf(keyId).owner != 0`) *and* equal the owner of the vault, `IERC173(approval.delegator).owner()`, read with the sentinel's safe staticcall. Otherwise revert `UnknownDevice()`.

  So approvals can only be credited for vaults whose owner's registered Ripar device co-signed. This closes the farming with throwaway vaults and software keys, and the AUTO-spend laundering.
- **Shield.** `attestDenial` pre-checks `identity.isAuthorizedOrOwner(address(this), agentId)`, with a revert counting as false.
  - If the relay is authorized (the agent's owner made it an operator, so ERC-8004 would refuse the feedback as self-feedback), the denial is still recorded:
    - set `denialAttested`, increment `shieldedDenials[agentId]`, emit `Verdict(agentId, keyId, requestHash, false)` and `AgentShielded(agentId, keyId, requestHash)`;
    - **do not** call `giveFeedback`.
  - `attestApproval` reverts `AgentIsShielded()` while `shieldedDenials[agentId] > 0`. That check comes after `NotConsumed`, `NotRedeemer` and `UnknownDevice`, and before `NotAgentRedeemer`.

**Sentinel**
- **`reopen` needs a closed lane.** `reopen` reverts `LaneNotClosed()` unless the lane is closed. This is checked before the nonce and the signature.
- **Future `asOfBlock`.** `onReport` reverts `BadReport()` when `asOfBlock > block.number`, so a report cannot claim a future block to out-rank every reopen.

**Registry**
- **Retired keys.** When an owner re-registers with a new key, the old key is **retired**. Binding a retired key reverts `KeyTaken()`, both for the same owner and for any other owner. The view is `isRetired(keyId)`.

**Deploy**
- **Workflow owner.** On 10143 and 143, `DeployConfig` requires `RIPAR_WORKFLOW_OWNER != 0`, otherwise it reverts `MissingWorkflowOwner()`. The value is the address that owns the Chainlink CRE workflow. On 31337, 0 is still allowed. The sentinel and relay addresses therefore depend on that owner and are only known once it is chosen.

**Documented limitations after v1.2** (no contract change):
- **Reopen is a bearer authorization.** A reopen QR stays valid until a higher nonce is relayed, so relay it immediately. Protocol v1.2 may add a deadline. Since v1.2 a withheld reopen can only undo a close, never pre-empt one, and PANIC and revoke are unaffected.
- **Vault choice.** The vault is only as trustworthy as its DelegationManager. The companion must build it with the canonical MetaMask SimpleFactory and HybridDeleGator implementation. Firmware v1.2 derives the vault address from K1 and pins the enforcer and registry CREATE2 addresses; see the firmware changes.
- **DelegationManager pause.** The canonical DelegationManager's owner (an EOA on Monad testnet) can pause it. Funds can then be frozen but not stolen. Revoke and panic still work.
- **AUTO windows.** A window is fixed and anchored at the first AUTO spend, so up to 2x `periodAutoCap` can leave within seconds across a window boundary. Period 0 is a lifetime cap.
- **Deny targets.** A deny's `agentId` is chosen by the companion at mandate time (the device shows it as companion data).
