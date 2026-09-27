// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { P256 } from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { ExecutionLib } from "@erc7579/lib/ExecutionLib.sol";
import { CaveatEnforcer } from "@delegation-framework/enforcers/CaveatEnforcer.sol";
import { ModeCode } from "@delegation-framework/utils/Types.sol";

import { IPulseCosignEnforcer } from "./interfaces/IPulseCosignEnforcer.sol";
import { IRiparSentinel } from "./interfaces/IRiparSentinel.sol";

/// @title PulseCosignEnforcer
/// @notice Caveat enforcer (MetaMask delegation-framework v1.3.0) that lets an agent redeem a delegation on its own
///         (AUTO path, empty caveat args) inside per-transaction and per-period caps, to payees a human approved
///         before, while the RiparSentinel lane of the delegator is open. Everything else needs a P-256 co-signature
///         of the Ripar device over `HumanApproval` (HUMAN path, 160-byte caveat args). The device can kill mandates
///         at any time with a signed `Revoke` (one delegation) or `Panic` (every mandate below an epoch).
/// @dev    - EIP-712 domain: name "RiparPulseCosign", version "1" (docs/PROTOCOL.md §3), byte-exact with the firmware.
///         - Only single-call, default-exec modes are accepted.
///         - Every piece of state a redemption writes is keyed by `msg.sender` (the DelegationManager) (SPEC.md v1.1):
///           the AUTO period spend by (manager, delegationHash), the known payees by (manager, delegationHash, payee),
///           the used co-sign nonces by (manager, delegationHash, nonce), and the consumed co-signatures with their
///           `Approval` records by (manager, digest). Anyone may call `beforeHook` directly, but that only writes the
///           caller's own state: it can neither burn a pending co-signature or its nonce for the real
///           DelegationManager (no `CosignReplayed()` there) nor create a record that RiparReputationRelay, which
///           reads the canonical DelegationManager's records only, would credit.
///         - Known payees are per mandate (delegationHash): a revoke or a panic kills the mandate and its payee list
///           with it, and a fresh mandate starts empty. A HUMAN co-sign whitelists its payee only when the call is one
///           the AUTO path could meter under the mandate's terms (AUTO step 1: a native send with `value > 0` when
///           `terms.token == 0`, otherwise a `transfer` on `terms.token` with `value == 0`), moves a non-zero amount,
///           and has a non-zero payee (SPEC.md v1.2). So a 0-value co-sign, a co-sign on another asset, an `approve`,
///           a `transferFrom` or an unmetered call never whitelists anyone.
///         - A co-sign nonce is single-use per (manager, delegationHash) (SPEC.md v1.2): signing the same request twice
///           (same nonce, fresh presence salt, so a different digest) cannot pay twice. The nonce is checked after the
///           digest replay check and marked used only once the P-256 signature verified.
///         - No owner, no upgradability, no pausing.
contract PulseCosignEnforcer is CaveatEnforcer, IPulseCosignEnforcer, EIP712 {
    using ExecutionLib for bytes;

    ////////////////////////////// Constants //////////////////////////////

    /// @notice EIP-712 typehash of `HumanApproval` (SPEC.md / docs/PROTOCOL.md §3).
    bytes32 public constant HUMAN_APPROVAL_TYPEHASH = keccak256(
        "HumanApproval(bytes32 delegationHash,address delegator,address redeemer,address target,uint256 value,bytes32 callDataHash,uint256 nonce,uint64 expiry,bytes32 presenceHash)"
    );
    /// @notice EIP-712 typehash of `Revoke`.
    bytes32 public constant REVOKE_TYPEHASH = keccak256("Revoke(bytes32 delegationHash)");
    /// @notice EIP-712 typehash of `Panic`.
    bytes32 public constant PANIC_TYPEHASH = keccak256("Panic(uint64 minEpoch)");

    /// @dev abi.encode(PulseTerms): nine 32-byte words.
    uint256 private constant TERMS_LENGTH = 288;
    /// @dev abi.encode(uint256 nonce, uint64 expiry, bytes32 presenceHash, bytes32 r, bytes32 s).
    uint256 private constant HUMAN_ARGS_LENGTH = 160;
    /// @dev ExecutionLib single encoding: target (20) ‖ value (32) ‖ callData.
    uint256 private constant EXEC_CALLDATA_OFFSET = 52;

    bytes4 private constant TRANSFER_SELECTOR = 0xa9059cbb; // transfer(address,uint256)
    bytes4 private constant APPROVE_SELECTOR = 0x095ea7b3; // approve(address,uint256)
    bytes4 private constant TRANSFER_FROM_SELECTOR = 0x23b872dd; // transferFrom(address,address,uint256)

    uint256 private constant MASK_64 = (1 << 64) - 1;
    uint256 private constant MASK_96 = (1 << 96) - 1;

    ////////////////////////////// Types //////////////////////////////

    /// @dev How the single execution was decoded.
    enum CallKind {
        Unmetered, // anything that is not one of the kinds below: payee 0, amount 0
        Native, // empty callData: payee = target, amount = value
        Transfer, // ERC-20 transfer(to, amount), exactly 68 bytes, canonical `to`
        Approve, // ERC-20 approve(spender, amount), exactly 68 bytes, canonical `spender`
        TransferFrom // ERC-20 transferFrom(from, to, amount), exactly 100 bytes, canonical `from` and `to`
    }

    /// @dev Everything the two paths need about the hook call (kept in memory to stay clear of stack-too-deep).
    struct Hook {
        bytes32 delegationHash;
        address delegator;
        address redeemer;
        bytes32 keyId;
        address target;
        uint256 value;
        CallKind kind;
        address payee;
        uint256 amount;
    }

    /// @dev AUTO period state, one slot. `spent <= periodAutoCap < 2^128` always holds after a successful spend.
    struct Period {
        uint128 spent;
        uint64 start;
    }

    /// @dev `Approval` packed into 4 slots (Solidity's own layout of the struct takes 5):
    ///      slot0 keyId, slot1 delegationHash,
    ///      slot2 = delegator (160) ‖ redeemer[159:64] (96),
    ///      slot3 = redeemer[63:0] (64) ‖ payee (160) ‖ timestamp (32).
    ///      The timestamp is stored as uint32 (seconds, fine until 2106-02-07).
    ///      keyId = keccak256(px, py) is never 0, so `keyId != 0` doubles as the "consumed" flag.
    struct PackedApproval {
        bytes32 keyId;
        bytes32 delegationHash;
        uint256 word2;
        uint256 word3;
    }

    ////////////////////////////// State //////////////////////////////

    /// @dev Consumed co-signatures and their records, per DelegationManager (v1.1: replay protection per manager).
    mapping(address delegationManager => mapping(bytes32 approvalDigest => PackedApproval)) private _approvals;
    /// @dev AUTO period accounting, per DelegationManager and mandate.
    mapping(address delegationManager => mapping(bytes32 delegationHash => Period)) private _periods;
    /// @dev AUTO payees a human co-signed, per DelegationManager and mandate (v1.1: no longer per delegator).
    mapping(address delegationManager => mapping(bytes32 delegationHash => mapping(address payee => bool))) private
        _knownPayees;
    /// @dev Used co-sign nonces, per DelegationManager and mandate (v1.2), as bitmaps: nonce `n` is bit `n & 0xff` of
    ///      word `n >> 8`. Nonces 0..255 of a mandate share one slot, so after the first co-sign in a word the next
    ///      ones update an existing slot instead of writing a fresh one (Monad bills the gas limit).
    mapping(address delegationManager => mapping(bytes32 delegationHash => mapping(uint256 wordIndex => uint256)))
        private _usedNonces;
    mapping(bytes32 keyId => mapping(bytes32 delegationHash => bool)) private _revoked;
    mapping(bytes32 keyId => uint64) private _minEpochs;

    ////////////////////////////// Constructor //////////////////////////////

    constructor() EIP712("RiparPulseCosign", "1") { }

    ////////////////////////////// Hook //////////////////////////////

    /// @notice Enforces the Pulse co-sign policy before the execution of a delegation.
    /// @dev    Empty `_args` = AUTO path, 160-byte `_args` = HUMAN path, anything else reverts `InvalidArgs()`.
    ///         See SPEC.md for the exact order of the checks.
    /// @param _terms abi.encode(PulseTerms), exactly 288 bytes, every word canonical.
    /// @param _args Empty (AUTO) or abi.encode(uint256 nonce, uint64 expiry, bytes32 presenceHash, bytes32 r, bytes32 s).
    /// @param _mode The execution mode (single call type, default exec type only).
    /// @param _executionCallData ExecutionLib single encoding: target ‖ value ‖ callData.
    /// @param _delegationHash The hash of the delegation being redeemed.
    /// @param _delegator The delegator (the vault).
    /// @param _redeemer The address redeeming the delegation.
    function beforeHook(
        bytes calldata _terms,
        bytes calldata _args,
        ModeCode _mode,
        bytes calldata _executionCallData,
        bytes32 _delegationHash,
        address _delegator,
        address _redeemer
    ) public override onlySingleCallTypeMode(_mode) onlyDefaultExecutionMode(_mode) {
        // 1. terms
        PulseTerms memory terms_ = _decodeTerms(_terms);
        Hook memory hook_;
        hook_.keyId = keyIdOf(terms_.px, terms_.py);

        // 2. revocation and epoch
        if (_revoked[hook_.keyId][_delegationHash]) revert DelegationRevoked();
        if (terms_.epoch < _minEpochs[hook_.keyId]) revert StaleEpoch();

        // 3. the call
        hook_.delegationHash = _delegationHash;
        hook_.delegator = _delegator;
        hook_.redeemer = _redeemer;
        _decodeCall(hook_, _executionCallData);

        // 4. the path
        if (_args.length == 0) {
            _autoPath(terms_, hook_);
        } else if (_args.length == HUMAN_ARGS_LENGTH) {
            _humanPath(terms_, hook_, _args, keccak256(_executionCallData[EXEC_CALLDATA_OFFSET:]));
        } else {
            revert InvalidArgs();
        }
    }

    ////////////////////////////// Kill switch //////////////////////////////

    /// @inheritdoc IPulseCosignEnforcer
    /// @dev Reverts `BadSignature()` unless (r, s) is a low-s P-256 signature of `revokeDigest(delegationHash)` by
    ///      (px, py). Emits `Revoked` only the first time.
    function revoke(bytes32 px, bytes32 py, bytes32 delegationHash, bytes32 r, bytes32 s) external {
        if (!P256.verify(revokeDigest(delegationHash), r, s, px, py)) revert BadSignature();
        bytes32 keyId_ = keyIdOf(px, py);
        if (!_revoked[keyId_][delegationHash]) {
            _revoked[keyId_][delegationHash] = true;
            emit Revoked(keyId_, delegationHash);
        }
    }

    /// @inheritdoc IPulseCosignEnforcer
    /// @dev Reverts `EpochNotIncreasing()` unless `newMinEpoch > minEpoch(keyId)`, then `BadSignature()` unless (r, s)
    ///      is a low-s P-256 signature of `panicDigest(newMinEpoch)` by (px, py).
    function panic(bytes32 px, bytes32 py, uint64 newMinEpoch, bytes32 r, bytes32 s) external {
        bytes32 keyId_ = keyIdOf(px, py);
        if (newMinEpoch <= _minEpochs[keyId_]) revert EpochNotIncreasing();
        if (!P256.verify(panicDigest(newMinEpoch), r, s, px, py)) revert BadSignature();
        _minEpochs[keyId_] = newMinEpoch;
        emit Panicked(keyId_, newMinEpoch);
    }

    ////////////////////////////// Views / helpers //////////////////////////////

    /// @inheritdoc IPulseCosignEnforcer
    /// @dev Reverts `InvalidTerms()` unless `terms` is exactly 288 bytes with every word canonical for its type.
    function getTermsInfo(bytes calldata terms) external pure returns (PulseTerms memory) {
        return _decodeTerms(terms);
    }

    /// @inheritdoc IPulseCosignEnforcer
    function keyIdOf(bytes32 px, bytes32 py) public pure returns (bytes32) {
        // forge-lint: disable-next-line(asm-keccak256)
        return keccak256(abi.encode(px, py));
    }

    /// @inheritdoc IPulseCosignEnforcer
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @inheritdoc IPulseCosignEnforcer
    function approvalStructHash(
        bytes32 delegationHash,
        address delegator,
        address redeemer,
        address target,
        uint256 value,
        bytes32 callDataHash,
        uint256 nonce,
        uint64 expiry,
        bytes32 presenceHash
    ) external pure returns (bytes32) {
        return _approvalStructHash(
            delegationHash, delegator, redeemer, target, value, callDataHash, nonce, expiry, presenceHash
        );
    }

    /// @inheritdoc IPulseCosignEnforcer
    function approvalDigest(
        bytes32 delegationHash,
        address delegator,
        address redeemer,
        address target,
        uint256 value,
        bytes32 callDataHash,
        uint256 nonce,
        uint64 expiry,
        bytes32 presenceHash
    ) external view returns (bytes32) {
        return _hashTypedDataV4(
            _approvalStructHash(
                delegationHash, delegator, redeemer, target, value, callDataHash, nonce, expiry, presenceHash
            )
        );
    }

    /// @inheritdoc IPulseCosignEnforcer
    function revokeDigest(bytes32 delegationHash) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(REVOKE_TYPEHASH, delegationHash)));
    }

    /// @inheritdoc IPulseCosignEnforcer
    function panicDigest(uint64 minEpoch_) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(PANIC_TYPEHASH, minEpoch_)));
    }

    /// @inheritdoc IPulseCosignEnforcer
    function consumed(address delegationManager, bytes32 approvalDigest_) external view returns (bool) {
        return _approvals[delegationManager][approvalDigest_].keyId != bytes32(0);
    }

    /// @inheritdoc IPulseCosignEnforcer
    /// @dev All fields are zero for a digest that `delegationManager` never consumed.
    function approvalOf(address delegationManager, bytes32 approvalDigest_)
        external
        view
        returns (Approval memory approval_)
    {
        PackedApproval storage packed_ = _approvals[delegationManager][approvalDigest_];
        // the casts below cut the packed words back into their fields (layout: see PackedApproval)
        // forge-lint: disable-start(unsafe-typecast)
        uint256 word2_ = packed_.word2;
        uint256 word3_ = packed_.word3;
        approval_.keyId = packed_.keyId;
        approval_.delegationHash = packed_.delegationHash;
        approval_.delegator = address(uint160(word2_ >> 96));
        approval_.redeemer = address(uint160(((word2_ & MASK_96) << 64) | (word3_ >> 192)));
        approval_.payee = address(uint160(word3_ >> 32));
        approval_.timestamp = uint64(uint32(word3_));
        // forge-lint: disable-end(unsafe-typecast)
    }

    /// @inheritdoc IPulseCosignEnforcer
    function isRevoked(bytes32 keyId, bytes32 delegationHash) external view returns (bool) {
        return _revoked[keyId][delegationHash];
    }

    /// @inheritdoc IPulseCosignEnforcer
    function minEpoch(bytes32 keyId) external view returns (uint64) {
        return _minEpochs[keyId];
    }

    /// @inheritdoc IPulseCosignEnforcer
    /// @dev The values stored by the last AUTO spend. An elapsed period is reset lazily by the next AUTO spend, so
    ///      when `block.timestamp >= start + period` the spendable amount is the full `periodAutoCap`. Use
    ///      `autoBudget` for the budget with the rollover applied.
    function periodSpent(address delegationManager, bytes32 delegationHash)
        external
        view
        returns (uint256 spent, uint64 start)
    {
        Period memory period_ = _periods[delegationManager][delegationHash];
        return (period_.spent, period_.start);
    }

    /// @inheritdoc IPulseCosignEnforcer
    /// @dev Reverts `InvalidTerms()` like the hook. Applies the aligned rollover exactly as an AUTO spend at
    ///      `block.timestamp` would (same `_rollover`), so an AUTO spend of `x` in this block passes the period check
    ///      if and only if `x <= remaining`.
    ///      - Nothing spent yet (no AUTO spend recorded): (0, periodAutoCap, 0, 0).
    ///      - `period == 0`: the window started at the first AUTO spend and never ends (periodEnd = 0).
    ///      - Otherwise the current aligned window [periodStart, periodEnd); an elapsed one reads as spent 0 with the
    ///        next aligned window.
    ///      `remaining` is `periodAutoCap - spent`, floored at 0 (spent > periodAutoCap is only possible when `terms`
    ///      are not the terms the spends were made under).
    function autoBudget(address delegationManager, bytes32 delegationHash, bytes calldata terms)
        external
        view
        returns (uint256 spent, uint256 remaining, uint64 periodStart, uint64 periodEnd)
    {
        PulseTerms memory terms_ = _decodeTerms(terms);
        Period memory stored_ = _periods[delegationManager][delegationHash];
        (uint256 spent_, uint256 start_) = _rollover(stored_.spent, stored_.start, terms_.period);
        spent = spent_;
        remaining = spent_ < terms_.periodAutoCap ? terms_.periodAutoCap - spent_ : 0;
        if (start_ != 0) {
            // start_ <= max(stored start, block.timestamp); the end is clamped rather than wrapped
            // forge-lint: disable-next-line(unsafe-typecast)
            periodStart = uint64(start_);
            if (terms_.period != 0) {
                uint256 end_ = start_ + terms_.period;
                // forge-lint: disable-next-line(unsafe-typecast)
                periodEnd = end_ > type(uint64).max ? type(uint64).max : uint64(end_);
            }
        }
    }

    /// @inheritdoc IPulseCosignEnforcer
    function isKnownPayee(address delegationManager, bytes32 delegationHash, address payee)
        external
        view
        returns (bool)
    {
        return _knownPayees[delegationManager][delegationHash][payee];
    }

    /// @inheritdoc IPulseCosignEnforcer
    /// @dev True once `delegationManager` consumed a verified co-sign with this nonce under this mandate. Only calls
    ///      by `delegationManager` itself mark its nonces.
    function nonceUsed(address delegationManager, bytes32 delegationHash, uint256 nonce) external view returns (bool) {
        return _usedNonces[delegationManager][delegationHash][nonce >> 8] & (1 << (nonce & 0xff)) != 0;
    }

    ////////////////////////////// Internal: paths //////////////////////////////

    /// @dev AUTO path: meterable call, sentinel lane, per-tx cap, known payee, period cap (in that order).
    function _autoPath(PulseTerms memory _t, Hook memory _h) private {
        // 1. meterable for these terms
        if (!_meterable(_t, _h)) revert HumanRequired();

        // 2. sentinel lane (a reverting or non-contract sentinel reverts the hook: fail closed)
        if (_t.sentinel != address(0) && !IRiparSentinel(_t.sentinel).laneOpen(_h.delegator)) revert LaneClosed();

        // 3. per-transaction cap (after this, amount < 2^128)
        if (_h.amount > _t.perTxAutoCap) revert HumanRequired();

        // 4. known payee (per mandate)
        if (_t.newPayeeNeedsHuman && !_knownPayees[msg.sender][_h.delegationHash][_h.payee]) revert HumanRequired();

        // 5. period cap
        Period storage slot_ = _periods[msg.sender][_h.delegationHash];
        (uint256 spent_, uint256 start_) = _rollover(slot_.spent, slot_.start, _t.period);
        if (start_ == 0) start_ = block.timestamp; // the first AUTO spend opens the first window
        spent_ += _h.amount; // both < 2^128: no overflow
        if (spent_ > _t.periodAutoCap) revert HumanRequired();

        // forge-lint: disable-start(unsafe-typecast)
        slot_.spent = uint128(spent_); // <= periodAutoCap (uint128)
        slot_.start = uint64(start_); // <= block.timestamp
        // forge-lint: disable-end(unsafe-typecast)
        emit AutoSpend(_h.delegationHash, _h.delegator, _h.redeemer, msg.sender, _h.payee, _h.amount, spent_);
    }

    /// @dev HUMAN path: expiry, digest replay (per manager), nonce replay (per manager and mandate, v1.2), P-256
    ///      co-signature, then mark the nonce, record the approval and, for a meterable non-zero payment, the payee.
    function _humanPath(PulseTerms memory _t, Hook memory _h, bytes calldata _args, bytes32 _callDataHash) private {
        {
            uint256 expiry_ = _word(_args, 32);
            if (expiry_ > type(uint64).max) revert InvalidArgs(); // non-canonical uint64 word
            if (block.timestamp > expiry_) revert CosignExpired();
        }

        bytes32 digest_ = _hashTypedDataV4(_humanStructHash(_h, _callDataHash, _args));
        PackedApproval storage record_ = _approvals[msg.sender][digest_];
        if (record_.keyId != bytes32(0)) revert CosignReplayed();

        // v1.2: the nonce is single-use per (manager, mandate), whatever else the co-sign binds (a fresh presence
        // salt makes a fresh digest for the very same request). Bit `nonce & 0xff` of word `nonce >> 8`.
        mapping(uint256 wordIndex => uint256) storage nonceWords_ = _usedNonces[msg.sender][_h.delegationHash];
        uint256 markedWord_;
        {
            uint256 nonce_ = _word(_args, 0);
            uint256 word_ = nonceWords_[nonce_ >> 8];
            markedWord_ = word_ | (1 << (nonce_ & 0xff));
            if (markedWord_ == word_) revert CosignReplayed(); // the bit was already set
        }

        if (!P256.verify(digest_, bytes32(_word(_args, 96)), bytes32(_word(_args, 128)), _t.px, _t.py)) {
            revert BadCosign();
        }

        nonceWords_[_word(_args, 0) >> 8] = markedWord_; // marked only once the signature verified
        record_.keyId = _h.keyId;
        record_.delegationHash = _h.delegationHash;
        record_.word2 = (uint256(uint160(_h.delegator)) << 96) | (uint256(uint160(_h.redeemer)) >> 64);
        record_.word3 = ((uint256(uint160(_h.redeemer)) & MASK_64) << 192) | (uint256(uint160(_h.payee)) << 32)
            | uint256(uint32(block.timestamp));

        // v1.2: only a payment the AUTO path could meter under these terms, of a non-zero amount to a non-zero payee,
        // makes that payee known for this mandate (never a 0-value, foreign-asset, approve or transferFrom co-sign)
        if (
            _meterable(_t, _h) && _h.amount != 0 && _h.payee != address(0)
                && !_knownPayees[msg.sender][_h.delegationHash][_h.payee]
        ) {
            _knownPayees[msg.sender][_h.delegationHash][_h.payee] = true;
            emit PayeeApproved(msg.sender, _h.delegationHash, _h.payee);
        }

        _emitHumanCosigned(_h, digest_, bytes32(_word(_args, 64)));
    }

    /// @dev AUTO step 1 (SPEC.md): whether the call is meterable for the terms. With `terms.token == 0` only a native
    ///      send (empty callData) with `value > 0`; otherwise only an ERC-20 `transfer` on `terms.token` with no native
    ///      value (`approve` and `transferFrom` never). Shared by the AUTO path and the HUMAN known-payee rule (v1.2)
    ///      so the two can never drift apart.
    function _meterable(PulseTerms memory _t, Hook memory _h) private pure returns (bool) {
        if (_t.token == address(0)) return _h.kind == CallKind.Native && _h.value != 0;
        return _h.kind == CallKind.Transfer && _h.target == _t.token && _h.value == 0;
    }

    /// @dev Emits `HumanCosigned` with the decoded payee; the amount is the decoded ERC-20 amount (transfer, approve,
    ///      transferFrom), or `value` for native / unmetered calls.
    function _emitHumanCosigned(Hook memory _h, bytes32 _digest, bytes32 _presenceHash) private {
        uint256 amount_ = (_h.kind == CallKind.Native || _h.kind == CallKind.Unmetered) ? _h.value : _h.amount;
        emit HumanCosigned(
            _h.delegationHash,
            _h.delegator,
            _h.redeemer,
            msg.sender,
            _h.payee,
            amount_,
            _h.keyId,
            _digest,
            _presenceHash
        );
    }

    /// @dev The AUTO period state `(spent, start)` with the aligned rollover applied at `block.timestamp` (SPEC.md
    ///      AUTO step 5). Shared by the AUTO path and `autoBudget` so the view can never drift from the hook.
    ///      `start == 0` (no AUTO spend yet) is returned unchanged; the AUTO path then opens the window at now.
    function _rollover(uint256 _spent, uint256 _start, uint256 _period)
        private
        view
        returns (uint256 spent_, uint256 start_)
    {
        if (_period != 0 && _start != 0 && block.timestamp >= _start + _period) {
            // forge-lint: disable-next-line(divide-before-multiply)
            return (0, _start + ((block.timestamp - _start) / _period) * _period); // aligned: truncation intended
        }
        return (_spent, _start);
    }

    ////////////////////////////// Internal: decoding //////////////////////////////

    /// @dev Strict decode of abi.encode(PulseTerms): exact length and canonical words, else `InvalidTerms()`.
    function _decodeTerms(bytes calldata _terms) private pure returns (PulseTerms memory t_) {
        if (_terms.length != TERMS_LENGTH) revert InvalidTerms();
        uint256 token_ = _word(_terms, 64);
        uint256 perTxAutoCap_ = _word(_terms, 96);
        uint256 periodAutoCap_ = _word(_terms, 128);
        uint256 period_ = _word(_terms, 160);
        uint256 epoch_ = _word(_terms, 192);
        uint256 newPayeeNeedsHuman_ = _word(_terms, 224);
        uint256 sentinel_ = _word(_terms, 256);
        if (
            (token_ | sentinel_) >> 160 != 0 || (perTxAutoCap_ | periodAutoCap_) >> 128 != 0 || period_ >> 32 != 0
                || epoch_ >> 64 != 0 || newPayeeNeedsHuman_ > 1
        ) revert InvalidTerms();

        // every word was range-checked above, so none of these casts truncates
        // forge-lint: disable-start(unsafe-typecast)
        t_.px = bytes32(_word(_terms, 0));
        t_.py = bytes32(_word(_terms, 32));
        t_.token = address(uint160(token_));
        t_.perTxAutoCap = uint128(perTxAutoCap_);
        t_.periodAutoCap = uint128(periodAutoCap_);
        t_.period = uint32(period_);
        t_.epoch = uint64(epoch_);
        t_.newPayeeNeedsHuman = newPayeeNeedsHuman_ == 1;
        t_.sentinel = address(uint160(sentinel_));
        // forge-lint: disable-end(unsafe-typecast)
    }

    /// @dev Decodes the single execution into target, value, kind, payee and amount (SPEC.md step 3).
    ///      ERC-20 calls must be exactly ABI-sized with canonical address words, otherwise the call is unmetered.
    function _decodeCall(Hook memory _h, bytes calldata _executionCallData) private pure {
        (address target_, uint256 value_, bytes calldata callData_) = _executionCallData.decodeSingle();
        _h.target = target_;
        _h.value = value_;

        uint256 length_ = callData_.length;
        if (length_ == 0) {
            _h.kind = CallKind.Native;
            _h.payee = target_;
            _h.amount = value_;
            return;
        }
        if (length_ != 68 && length_ != 100) return; // Unmetered

        // address words are checked canonical (upper 96 bits zero) before they are cast
        // forge-lint: disable-start(unsafe-typecast)
        bytes4 selector_ = bytes4(callData_[:4]);
        uint256 word1_ = _word(callData_, 4);
        uint256 word2_ = _word(callData_, 36);
        if (length_ == 68) {
            if (word1_ >> 160 != 0) return; // dirty address word
            if (selector_ == TRANSFER_SELECTOR) {
                _h.kind = CallKind.Transfer;
            } else if (selector_ == APPROVE_SELECTOR) {
                _h.kind = CallKind.Approve;
            } else {
                return;
            }
            _h.payee = address(uint160(word1_));
            _h.amount = word2_;
        } else if (selector_ == TRANSFER_FROM_SELECTOR && (word1_ | word2_) >> 160 == 0) {
            _h.kind = CallKind.TransferFrom;
            _h.payee = address(uint160(word2_));
            _h.amount = _word(callData_, 68);
        }
        // forge-lint: disable-end(unsafe-typecast)
    }

    /// @dev The 32-byte word of `_data` at byte offset `_offset`. Callers guarantee `_offset + 32 <= _data.length`.
    function _word(bytes calldata _data, uint256 _offset) private pure returns (uint256 word_) {
        assembly ("memory-safe") {
            word_ := calldataload(add(_data.offset, _offset))
        }
    }

    ////////////////////////////// Internal: hashing //////////////////////////////

    /// @dev hashStruct(HumanApproval) for the hook call, with nonce / expiry / presenceHash read from the args.
    function _humanStructHash(Hook memory _h, bytes32 _callDataHash, bytes calldata _args)
        private
        pure
        returns (bytes32)
    {
        return _approvalStructHash(
            _h.delegationHash,
            _h.delegator,
            _h.redeemer,
            _h.target,
            _h.value,
            _callDataHash,
            _word(_args, 0),
            uint64(_word(_args, 32)), // checked canonical by the caller
            bytes32(_word(_args, 64))
        );
    }

    /// @dev keccak256(abi.encode(HUMAN_APPROVAL_TYPEHASH, ...)) built in scratch memory (not allocated).
    function _approvalStructHash(
        bytes32 _delegationHash,
        address _delegator,
        address _redeemer,
        address _target,
        uint256 _value,
        bytes32 _callDataHash,
        uint256 _nonce,
        uint64 _expiry,
        bytes32 _presenceHash
    ) private pure returns (bytes32 hash_) {
        bytes32 typehash_ = HUMAN_APPROVAL_TYPEHASH;
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, typehash_)
            mstore(add(m, 0x20), _delegationHash)
            mstore(add(m, 0x40), and(_delegator, 0xffffffffffffffffffffffffffffffffffffffff))
            mstore(add(m, 0x60), and(_redeemer, 0xffffffffffffffffffffffffffffffffffffffff))
            mstore(add(m, 0x80), and(_target, 0xffffffffffffffffffffffffffffffffffffffff))
            mstore(add(m, 0xa0), _value)
            mstore(add(m, 0xc0), _callDataHash)
            mstore(add(m, 0xe0), _nonce)
            mstore(add(m, 0x100), and(_expiry, 0xffffffffffffffff))
            mstore(add(m, 0x120), _presenceHash)
            hash_ := keccak256(m, 0x140)
        }
    }
}
