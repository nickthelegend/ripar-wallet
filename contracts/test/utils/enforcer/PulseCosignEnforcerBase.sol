// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { Vm } from "forge-std/Vm.sol";
import { ExecutionLib } from "@erc7579/lib/ExecutionLib.sol";
import { ModeLib, ModeCode } from "@erc7579/lib/ModeLib.sol";

import { PulseCosignEnforcer } from "../../../src/PulseCosignEnforcer.sol";
import { IPulseCosignEnforcer } from "../../../src/interfaces/IPulseCosignEnforcer.sol";
import { P256TestUtils } from "../P256TestUtils.sol";
import { MockSentinel } from "./MockSentinel.sol";

/// @notice Shared fixtures and builders for the PulseCosignEnforcer suites. The test contract itself acts as the
///         DelegationManager (msg.sender of beforeHook). Digests are rebuilt here by hand, independently of the
///         enforcer's own helpers.
abstract contract PulseCosignEnforcerBase is P256TestUtils {
    // ------------------------------------------------------------------ events (same signatures as the interface)
    event AutoSpend(
        bytes32 indexed delegationHash,
        address indexed delegator,
        address indexed redeemer,
        address delegationManager,
        address payee,
        uint256 amount,
        uint256 periodSpent
    );
    event HumanCosigned(
        bytes32 indexed delegationHash,
        address indexed delegator,
        address indexed redeemer,
        address delegationManager,
        address payee,
        uint256 amount,
        bytes32 keyId,
        bytes32 approvalDigest,
        bytes32 presenceHash
    );
    event PayeeApproved(address indexed delegationManager, bytes32 indexed delegationHash, address indexed payee);
    event Revoked(bytes32 indexed keyId, bytes32 indexed delegationHash);
    event Panicked(bytes32 indexed keyId, uint64 minEpoch);

    // ------------------------------------------------------------------ fixtures
    uint256 internal constant DEVICE_PK = 0xA11CE5EED;
    uint256 internal constant OTHER_PK = 0xB0B5EED;

    bytes32 internal constant DH = keccak256("ripar.delegation.1");
    bytes32 internal constant DH2 = keccak256("ripar.delegation.2");
    address internal constant DELEGATOR = address(0xde1e9A70DE1e9a70de1E9a70de1E9a70de1E9a70);
    address internal constant DELEGATOR2 = address(0x2222222222222222222222222222222222222222);
    // all 160 bits used, so the 4-slot Approval packing (redeemer split across two words) is exercised
    address internal constant REDEEMER = address(0xFFEEDDCCbBaa99887766554433221100fFeedDcC);
    address internal constant PAYEE = address(0xBEEF);
    address internal constant PAYEE2 = address(0xCAFE);
    address internal constant TOKEN = address(0x70ce70CE70Ce70Ce70Ce70cE70CE70Ce70Ce70ce);
    address internal constant MANAGER_B = address(0xB0B0);
    // someone who calls beforeHook directly (not a DelegationManager), e.g. a mempool watcher
    address internal constant ATTACKER = address(0xA77AC4E4);

    uint256 internal constant T0 = 1_790_000_000; // 2026-09-21

    uint128 internal constant NATIVE_PER_TX = 1 ether;
    uint128 internal constant NATIVE_PERIOD_CAP = 3 ether;
    uint128 internal constant TOKEN_PER_TX = 100e6;
    uint128 internal constant TOKEN_PERIOD_CAP = 250e6;
    uint32 internal constant PERIOD = 1 days;

    bytes32 internal constant HUMAN_APPROVAL_TYPEHASH_STR = keccak256(
        "HumanApproval(bytes32 delegationHash,address delegator,address redeemer,address target,uint256 value,bytes32 callDataHash,uint256 nonce,uint64 expiry,bytes32 presenceHash)"
    );
    bytes32 internal constant DOMAIN_TYPEHASH_STR =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    PulseCosignEnforcer internal enforcer;
    MockSentinel internal sentinel;
    bytes32 internal px;
    bytes32 internal py;
    bytes32 internal keyId;
    bytes32 internal otherPx;
    bytes32 internal otherPy;
    ModeCode internal single;

    /// @notice A HUMAN request: everything the device signs.
    struct Req {
        bytes32 delegationHash;
        address delegator;
        address redeemer;
        address target;
        uint256 value;
        bytes callData;
        uint256 nonce;
        uint64 expiry;
        bytes32 presenceHash;
    }

    function setUp() public virtual {
        vm.warp(T0);
        enforcer = new PulseCosignEnforcer();
        sentinel = new MockSentinel();
        (px, py) = p256Key(DEVICE_PK);
        keyId = p256KeyId(px, py);
        (otherPx, otherPy) = p256Key(OTHER_PK);
        single = ModeLib.encodeSimpleSingle();
    }

    // ------------------------------------------------------------------ terms
    function _nativeTerms() internal view returns (IPulseCosignEnforcer.PulseTerms memory) {
        return IPulseCosignEnforcer.PulseTerms({
            px: px,
            py: py,
            token: address(0),
            perTxAutoCap: NATIVE_PER_TX,
            periodAutoCap: NATIVE_PERIOD_CAP,
            period: PERIOD,
            epoch: 0,
            newPayeeNeedsHuman: false,
            sentinel: address(0)
        });
    }

    function _tokenTerms() internal view returns (IPulseCosignEnforcer.PulseTerms memory t) {
        t = _nativeTerms();
        t.token = TOKEN;
        t.perTxAutoCap = TOKEN_PER_TX;
        t.periodAutoCap = TOKEN_PERIOD_CAP;
    }

    function _enc(IPulseCosignEnforcer.PulseTerms memory t) internal pure returns (bytes memory) {
        return abi.encode(t);
    }

    // ------------------------------------------------------------------ executions
    function _exec(address target, uint256 value, bytes memory data) internal pure returns (bytes memory) {
        return ExecutionLib.encodeSingle(target, value, data);
    }

    function _transfer(address to, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(bytes4(0xa9059cbb), to, amount);
    }

    function _approve(address spender, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(bytes4(0x095ea7b3), spender, amount);
    }

    function _transferFrom(address from, address to, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(bytes4(0x23b872dd), from, to, amount);
    }

    // ------------------------------------------------------------------ hook calls (msg.sender = this test)
    function _auto(bytes memory terms, bytes memory exec) internal {
        enforcer.beforeHook(terms, "", single, exec, DH, DELEGATOR, REDEEMER);
    }

    function _autoNative(bytes memory terms, address to, uint256 value) internal {
        _auto(terms, _exec(to, value, ""));
    }

    function _human(bytes memory terms, Req memory q, bytes memory args) internal {
        enforcer.beforeHook(
            terms, args, single, _exec(q.target, q.value, q.callData), q.delegationHash, q.delegator, q.redeemer
        );
    }

    // ------------------------------------------------------------------ HUMAN requests, hand-rolled EIP-712
    function _req(address target, uint256 value, bytes memory data) internal view returns (Req memory) {
        return Req({
            delegationHash: DH,
            delegator: DELEGATOR,
            redeemer: REDEEMER,
            target: target,
            value: value,
            callData: data,
            nonce: 1,
            expiry: uint64(block.timestamp + 1 hours),
            presenceHash: sha256(abi.encodePacked(bytes12(0x01483c0100000200001e0320), bytes16(keccak256("salt"))))
        });
    }

    /// @dev `_req` with an explicit nonce (v1.2: a nonce is single-use per manager and mandate, so every co-sign a test
    ///      makes under one mandate needs its own).
    function _reqN(address target, uint256 value, bytes memory data, uint256 nonce)
        internal
        view
        returns (Req memory q)
    {
        q = _req(target, value, data);
        q.nonce = nonce;
    }

    /// @dev presenceHash = sha256(evidence12 ‖ salt16) with a salt derived from `seed`: the device draws a fresh salt
    ///      for every signature, so signing the same request twice gives two presence hashes (two digests).
    function _presence(uint256 seed) internal pure returns (bytes32) {
        return
            sha256(abi.encodePacked(bytes12(0x01483c0100000200001e0320), bytes16(keccak256(abi.encode("salt", seed)))));
    }

    function _copy(Req memory q) internal pure returns (Req memory c) {
        c = Req({
            delegationHash: q.delegationHash,
            delegator: q.delegator,
            redeemer: q.redeemer,
            target: q.target,
            value: q.value,
            callData: q.callData,
            nonce: q.nonce,
            expiry: q.expiry,
            presenceHash: q.presenceHash
        });
    }

    function _domainSeparatorFor(uint256 chainId, address verifyingContract) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH_STR, keccak256("RiparPulseCosign"), keccak256("1"), chainId, verifyingContract)
        );
    }

    function _domainSeparator() internal view returns (bytes32) {
        return _domainSeparatorFor(block.chainid, address(enforcer));
    }

    function _structHash(Req memory q) internal pure returns (bytes32) {
        bytes memory head = abi.encode(HUMAN_APPROVAL_TYPEHASH_STR, q.delegationHash, q.delegator, q.redeemer, q.target);
        bytes memory tail = abi.encode(q.value, keccak256(q.callData), q.nonce, q.expiry, q.presenceHash);
        return keccak256(bytes.concat(head, tail));
    }

    function _digest(Req memory q) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", _domainSeparator(), _structHash(q)));
    }

    function _args(Req memory q, bytes32 r, bytes32 s) internal pure returns (bytes memory) {
        return abi.encode(q.nonce, q.expiry, q.presenceHash, r, s);
    }

    function _sign(uint256 pk, Req memory q) internal view returns (bytes memory args, bytes32 digest) {
        digest = _digest(q);
        (bytes32 r, bytes32 s) = p256Sign(pk, digest);
        args = _args(q, r, s);
    }

    function _rs(bytes memory args) internal pure returns (bytes32 r, bytes32 s) {
        (,,, r, s) = abi.decode(args, (uint256, uint64, bytes32, bytes32, bytes32));
    }

    /// @dev Signs and submits a HUMAN co-sign of `q` (device key, default native terms unless given).
    function _cosign(bytes memory terms, Req memory q) internal returns (bytes32 digest) {
        bytes memory args;
        (args, digest) = _sign(DEVICE_PK, q);
        _human(terms, q, args);
    }

    function _revokeDigest(bytes32 delegationHash) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                hex"1901",
                _domainSeparator(),
                keccak256(abi.encode(keccak256("Revoke(bytes32 delegationHash)"), delegationHash))
            )
        );
    }

    function _panicDigest(uint64 epoch) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                hex"1901", _domainSeparator(), keccak256(abi.encode(keccak256("Panic(uint64 minEpoch)"), epoch))
            )
        );
    }

    function _revokeAs(uint256 pk, bytes32 delegationHash) internal {
        (bytes32 x, bytes32 y) = p256Key(pk);
        (bytes32 r, bytes32 s) = p256Sign(pk, _revokeDigest(delegationHash));
        enforcer.revoke(x, y, delegationHash, r, s);
    }

    function _panicAs(uint256 pk, uint64 epoch) internal {
        (bytes32 x, bytes32 y) = p256Key(pk);
        (bytes32 r, bytes32 s) = p256Sign(pk, _panicDigest(epoch));
        enforcer.panic(x, y, epoch, r, s);
    }

    // ------------------------------------------------------------------ bytes utils
    function _resize(bytes memory b, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        uint256 n = len < b.length ? len : b.length;
        for (uint256 i; i < n; ++i) {
            out[i] = b[i];
        }
    }

    function _setWord(bytes memory b, uint256 index, uint256 word) internal pure returns (bytes memory out) {
        out = _resize(b, b.length);
        assembly {
            mstore(add(add(out, 0x20), mul(index, 0x20)), word)
        }
    }

    function _countLogs(Vm.Log[] memory logs, bytes32 topic0) internal pure returns (uint256 n) {
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics.length > 0 && logs[i].topics[0] == topic0) ++n;
        }
    }
}
