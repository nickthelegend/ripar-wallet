// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import { RiparSentinel } from "../src/RiparSentinel.sol";
import { RiparDeviceRegistry } from "../src/RiparDeviceRegistry.sol";
import { IRiparSentinel } from "../src/interfaces/IRiparSentinel.sol";
import { IReceiver } from "../src/interfaces/external/IReceiver.sol";
import { PeripheryTestBase } from "./utils/periphery/PeripheryTestBase.sol";
import {
    MockVault,
    NoOwnerVault,
    RevertingOwnerVault,
    DirtyOwnerVault,
    ShortOwnerVault
} from "./utils/periphery/MockVaults.sol";
import { InconsistentRegistry } from "./utils/periphery/MockRegistry.sol";

abstract contract RiparSentinelTestBase is PeripheryTestBase {
    event LaneChanged(address indexed vault, bool open, uint8 reason, uint64 asOfBlock);
    event ReportIgnored(address indexed vault, uint8 reason, uint64 asOfBlock);

    uint256 internal constant P1 = 0xA11CE; // the vault owner's device (P-256)
    uint256 internal constant K1 = 0xB0B; // the vault owner (secp256k1)
    uint256 internal constant P1_B = 0xB1B1; // another registered device
    uint256 internal constant K1_B = 0xB2B2;
    uint256 internal constant P1_C = 0xC1C1; // an unregistered P-256 key

    bytes32 internal constant WORKFLOW_ID = keccak256("ripar-sentinel workflow");
    bytes10 internal constant WORKFLOW_NAME = bytes10("ripar-sent");

    RiparDeviceRegistry internal reg;
    RiparSentinel internal sentinel; // checks the workflow owner
    RiparSentinel internal sentinelNoCheck; // expectedWorkflowOwner = 0
    address internal forwarder;
    address internal wfOwner;
    address internal owner;
    MockVault internal vault;

    function setUp() public virtual {
        forwarder = makeAddr("KeystoneForwarder");
        wfOwner = makeAddr("workflowOwner");
        reg = new RiparDeviceRegistry();
        sentinel = new RiparSentinel(forwarder, reg, wfOwner);
        sentinelNoCheck = new RiparSentinel(forwarder, reg, address(0));
        owner = vm.addr(K1);
        registerPair(reg, P1, K1);
        registerPair(reg, P1_B, K1_B);
        vault = new MockVault(owner);
        vm.roll(1000);
    }

    // ------------------------------------------------------------------ helpers

    /// @dev What the KeystoneForwarder passes: rawReport[45:109] = workflowId ‖ workflowName ‖ workflowOwner ‖ reportId.
    function _meta(address wo) internal pure returns (bytes memory) {
        return abi.encodePacked(WORKFLOW_ID, WORKFLOW_NAME, wo, bytes2(0x0001));
    }

    function _report(address v, bool open, uint8 reason, uint64 asOfBlock) internal pure returns (bytes memory) {
        return abi.encode(v, open, reason, asOfBlock);
    }

    function _close(RiparSentinel s, address v, uint8 reason, uint64 asOfBlock) internal {
        vm.prank(forwarder);
        s.onReport(_meta(wfOwner), _report(v, false, reason, asOfBlock));
    }

    function _reopenSig(RiparSentinel s, uint256 p1Pk, address v, uint256 nonce)
        internal
        view
        returns (bytes32 r, bytes32 sig)
    {
        return p256Sign(p1Pk, s.reopenDigest(v, nonce));
    }

    function _reopen(RiparSentinel s, uint256 p1Pk, address v, uint256 nonce) internal {
        (bytes32 r, bytes32 sg) = _reopenSig(s, p1Pk, v, nonce);
        s.reopen(v, nonce, r, sg);
    }

    /// @dev v1.2: reopen needs a closed lane. Closes `v` with a report as of the current block, then reopens it.
    function _closeAndReopen(RiparSentinel s, uint256 p1Pk, address v, uint256 nonce) internal {
        _close(s, v, 1, uint64(block.number));
        _reopen(s, p1Pk, v, nonce);
    }

    // ------------------------------------------------------------------ constructor / views / ERC-165

    function test_constructor() public view {
        assertEq(sentinel.forwarder(), forwarder);
        assertEq(address(sentinel.registry()), address(reg));
        assertEq(sentinel.expectedWorkflowOwner(), wfOwner);
        assertEq(sentinelNoCheck.expectedWorkflowOwner(), address(0));
    }

    function test_laneOpen_defaultTrue() public {
        assertTrue(sentinel.laneOpen(address(vault)));
        assertTrue(sentinel.laneOpen(address(0)));
        assertTrue(sentinel.laneOpen(makeAddr("any")));
        assertEq(sentinel.lastReopenNonce(address(vault)), 0);
        assertEq(sentinel.lastReopenBlock(address(vault)), 0);
    }

    function test_supportsInterface() public view {
        assertEq(type(IReceiver).interfaceId, bytes4(0x805f2132), "IReceiver id = onReport(bytes,bytes)");
        assertTrue(sentinel.supportsInterface(type(IReceiver).interfaceId));
        assertTrue(sentinel.supportsInterface(type(IERC165).interfaceId));
        assertTrue(sentinel.supportsInterface(0x01ffc9a7));
        assertFalse(sentinel.supportsInterface(0xffffffff));
        assertFalse(sentinel.supportsInterface(0x00000000));
        assertFalse(sentinel.supportsInterface(type(IRiparSentinel).interfaceId));
    }

    // ------------------------------------------------------------------ EIP-712

    function test_domainSeparator_matchesHandRolled() public view {
        assertEq(sentinel.domainSeparator(), handDomain("RiparSentinel", block.chainid, address(sentinel)));
        (, string memory name, string memory version, uint256 chainId, address verifying,,) = sentinel.eip712Domain();
        assertEq(name, "RiparSentinel");
        assertEq(version, "1");
        assertEq(chainId, block.chainid);
        assertEq(verifying, address(sentinel));
        assertTrue(sentinel.domainSeparator() != sentinelNoCheck.domainSeparator());
    }

    function test_reopenDigest_matchesHandRolled() public view {
        assertEq(sentinel.REOPEN_TYPEHASH(), keccak256("Reopen(address vault,uint256 nonce)"));
        bytes32 structHash =
            keccak256(abi.encode(keccak256("Reopen(address vault,uint256 nonce)"), address(vault), uint256(7)));
        bytes32 expected = keccak256(
            abi.encodePacked(hex"1901", handDomain("RiparSentinel", block.chainid, address(sentinel)), structHash)
        );
        assertEq(sentinel.reopenDigest(address(vault), 7), expected);
    }

    function testFuzz_reopenDigest_matchesHandRolled(address v, uint256 nonce) public view {
        bytes32 structHash = keccak256(abi.encode(sentinel.REOPEN_TYPEHASH(), v, nonce));
        assertEq(
            sentinel.reopenDigest(v, nonce),
            handDigest(handDomain("RiparSentinel", block.chainid, address(sentinel)), structHash)
        );
    }

    /// @dev Vectors from firmware/test/host/vectors_eip712_abi.h (generated by the Python reference encoder).
    function test_firmwareVectors() public {
        // DOMAINS[2]: RiparSentinel v1, chainId 1
        address at = hexAddr(hex"3662e86d5fa1d558d85503e2f45f6f8ee46bd4d2");
        vm.etch(at, address(sentinel).code);
        vm.chainId(1);
        assertEq(
            RiparSentinel(at).domainSeparator(), hex"802c677dfdd818bb42f64f73ebc25376d321cb501013b5dd1040357832df2ac2"
        );
        // REOPENS[4]: chainId 31337
        at = hexAddr(hex"5afff7890185ed000706b4d06d9f6da8ceb53458");
        vm.etch(at, address(sentinel).code);
        vm.chainId(31_337);
        address v = hexAddr(hex"ee426950ced282c269fb0b6bc8380eb4810674ab");
        uint256 nonce = 0x5abf3206c8f476f8;
        assertEq(
            keccak256(abi.encode(sentinel.REOPEN_TYPEHASH(), v, nonce)),
            hex"e0097f34d18e64cb20bdf8f8d68b4da6391f7a9565fd44791b0a2fa52996cf3c",
            "structHash"
        );
        assertEq(
            RiparSentinel(at).reopenDigest(v, nonce),
            hex"1bd9511fd468384b7c59be0b1b40dc207b025cf7eaa3db21b0e84b06dcb0bbb6",
            "digest"
        );
        // REOPENS[0]: chainId 10143, 256-bit nonce
        at = hexAddr(hex"ca9e24b777d1da0a05d099109fd4f6295a4c332f");
        vm.etch(at, address(sentinel).code);
        vm.chainId(10_143);
        assertEq(
            RiparSentinel(at)
                .reopenDigest(
                    hexAddr(hex"879287b65b4a6b12cb1f7143f44738f02bb5462f"),
                    0x9e74ae74c872f1ab6c5209c35c605c5874c3352c9e652706a15a36ef7427cf80
                ),
            hex"01686deb79f4fa55e3c1aea34b39284c0740d84b0198ebed08064eaf9b17040f"
        );
    }

    // ------------------------------------------------------------------ onReport: access and metadata

    function test_onReport_closes() public {
        vm.expectEmit(true, false, false, true, address(sentinel));
        emit LaneChanged(address(vault), false, 3, 999);
        vm.prank(forwarder);
        sentinel.onReport(_meta(wfOwner), _report(address(vault), false, 3, 999));
        assertFalse(sentinel.laneOpen(address(vault)));
        // other vaults are untouched
        assertTrue(sentinel.laneOpen(makeAddr("otherVault")));
    }

    function test_onReport_closeAgain_staysClosedAndEmits() public {
        _close(sentinel, address(vault), 1, 10);
        vm.expectEmit(true, false, false, true, address(sentinel));
        emit LaneChanged(address(vault), false, 2, 5);
        _close(sentinel, address(vault), 2, 5); // no reopen yet: lastReopenBlock = 0, any asOfBlock closes
        assertFalse(sentinel.laneOpen(address(vault)));
    }

    function testFuzz_onReport_onlyForwarder(address caller) public {
        vm.assume(caller != forwarder);
        bytes memory meta = _meta(wfOwner);
        bytes memory rep = _report(address(vault), false, 1, 1);
        vm.prank(caller);
        vm.expectRevert(IRiparSentinel.NotForwarder.selector);
        sentinel.onReport(meta, rep);
        vm.prank(caller);
        vm.expectRevert(IRiparSentinel.NotForwarder.selector);
        sentinelNoCheck.onReport(meta, rep);
    }

    function test_onReport_notForwarder_checkedFirst() public {
        vm.expectRevert(IRiparSentinel.NotForwarder.selector);
        sentinel.onReport("", "");
    }

    function test_onReport_workflowOwner_wrong() public {
        bytes memory rep = _report(address(vault), false, 1, 1);
        bytes memory meta = _meta(makeAddr("mallory"));
        vm.prank(forwarder);
        vm.expectRevert(IRiparSentinel.BadWorkflowOwner.selector);
        sentinel.onReport(meta, rep);
        meta = _meta(address(0));
        vm.prank(forwarder);
        vm.expectRevert(IRiparSentinel.BadWorkflowOwner.selector);
        sentinel.onReport(meta, rep);
        assertTrue(sentinel.laneOpen(address(vault)));
    }

    function test_onReport_workflowOwner_layout() public {
        bytes memory rep = _report(address(vault), false, 1, 1);
        // the owner at metadata[42:62]: 62 bytes (no reportId) is enough
        bytes memory meta62 = abi.encodePacked(WORKFLOW_ID, WORKFLOW_NAME, wfOwner);
        assertEq(meta62.length, 62);
        vm.prank(forwarder);
        sentinel.onReport(meta62, rep);
        assertFalse(sentinel.laneOpen(address(vault)));

        // the owner shifted by one byte is not accepted
        bytes memory shifted = abi.encodePacked(WORKFLOW_ID, bytes11(WORKFLOW_NAME), wfOwner);
        vm.prank(forwarder);
        vm.expectRevert(IRiparSentinel.BadWorkflowOwner.selector);
        sentinel.onReport(shifted, rep);

        // trailing bytes after the owner are ignored
        bytes memory longer = abi.encodePacked(_meta(wfOwner), keccak256("extra"));
        vm.prank(forwarder);
        sentinel.onReport(longer, rep);
    }

    function test_onReport_workflowOwner_shortMetadata() public {
        bytes memory rep = _report(address(vault), false, 1, 1);
        bytes memory meta61 = abi.encodePacked(WORKFLOW_ID, WORKFLOW_NAME, bytes19(bytes20(wfOwner)));
        assertEq(meta61.length, 61);
        vm.prank(forwarder);
        vm.expectRevert(IRiparSentinel.BadWorkflowOwner.selector);
        sentinel.onReport(meta61, rep);
        vm.prank(forwarder);
        vm.expectRevert(IRiparSentinel.BadWorkflowOwner.selector);
        sentinel.onReport("", rep);
    }

    function test_onReport_workflowOwner_checkedBeforeReport() public {
        vm.prank(forwarder);
        vm.expectRevert(IRiparSentinel.BadWorkflowOwner.selector);
        sentinel.onReport(_meta(address(1)), hex"00");
    }

    function test_onReport_workflowOwnerCheckOff() public {
        bytes memory rep = _report(address(vault), false, 4, 1);
        vm.prank(forwarder);
        sentinelNoCheck.onReport("", rep); // any metadata, even empty
        assertFalse(sentinelNoCheck.laneOpen(address(vault)));

        bytes memory rep2 = _report(makeAddr("v2"), false, 4, 1);
        vm.prank(forwarder);
        sentinelNoCheck.onReport(_meta(makeAddr("anyone")), rep2);
        assertFalse(sentinelNoCheck.laneOpen(makeAddr("v2")));

        // the check-off sentinel still enforces the forwarder and the report format
        vm.expectRevert(IRiparSentinel.NotForwarder.selector);
        sentinelNoCheck.onReport("", rep);
        bytes memory openRep = _report(address(vault), true, 0, 1);
        vm.prank(forwarder);
        vm.expectRevert(IRiparSentinel.BadReport.selector);
        sentinelNoCheck.onReport("", openRep);
    }

    // ------------------------------------------------------------------ onReport: report format

    function _expectBadReport(bytes memory rep) internal {
        bytes memory meta = _meta(wfOwner);
        vm.prank(forwarder);
        vm.expectRevert(IRiparSentinel.BadReport.selector);
        sentinel.onReport(meta, rep);
    }

    function test_onReport_openTrue_reverts() public {
        _expectBadReport(_report(address(vault), true, 0, 1));
        _expectBadReport(_report(address(vault), true, 7, 2000));
        assertTrue(sentinel.laneOpen(address(vault)));

        // a closed lane cannot be reopened by CRE either
        _close(sentinel, address(vault), 1, 1);
        _expectBadReport(_report(address(vault), true, 0, 2000));
        assertFalse(sentinel.laneOpen(address(vault)));
    }

    function test_onReport_wrongLength() public {
        bytes memory good = _report(address(vault), false, 1, 1);
        _expectBadReport("");
        _expectBadReport(hex"00");
        _expectBadReport(abi.encodePacked(bytes32(uint256(uint160(address(vault)))), bytes32(0), bytes32(uint256(1))));
        _expectBadReport(abi.encodePacked(good, uint8(0))); // 129
        _expectBadReport(abi.encodePacked(good, bytes32(0))); // 160: abi.decode would accept trailing bytes
        bytes memory short = new bytes(127);
        _expectBadReport(short);
        assertTrue(sentinel.laneOpen(address(vault)));
    }

    function test_onReport_nonCanonical() public {
        uint256 v = uint256(uint160(address(vault)));
        // dirty address (bits above 160)
        _expectBadReport(abi.encode(v | (1 << 160), false, uint8(1), uint64(1)));
        _expectBadReport(abi.encode(v | (uint256(1) << 255), false, uint8(1), uint64(1)));
        // bool not 0/1
        _expectBadReport(abi.encode(v, uint256(2), uint8(1), uint64(1)));
        _expectBadReport(abi.encode(v, type(uint256).max, uint8(1), uint64(1)));
        // uint8 overflow
        _expectBadReport(abi.encode(v, false, uint256(256), uint64(1)));
        // uint64 overflow
        _expectBadReport(abi.encode(v, false, uint8(1), uint256(1) << 64));
        _expectBadReport(abi.encode(v, false, uint8(1), type(uint256).max));
        assertTrue(sentinel.laneOpen(address(vault)));

        // the extremes that are canonical do close (asOfBlock = uint64 max once the chain got there, v1.2)
        vm.roll(type(uint64).max);
        vm.prank(forwarder);
        sentinel.onReport(_meta(wfOwner), abi.encode(v, false, uint256(255), uint256(type(uint64).max)));
        assertFalse(sentinel.laneOpen(address(vault)));
    }

    /// @dev Any 4 words: a canonical close as of a past or current block closes that vault, everything else
    ///      (including a canonical close as of a future block, v1.2) is BadReport.
    function testFuzz_onReport_words(uint256 w0, uint256 w1, uint256 w2, uint256 w3) public {
        // bias towards canonical words so both branches get exercised
        if (w0 % 2 == 0) w0 = uint160(w0);
        if (w1 % 3 != 0) w1 = w1 % 2;
        if (w2 % 2 == 0) w2 = uint8(w2);
        if (w3 % 2 == 0) w3 = uint64(w3);
        if (w3 % 3 == 0) w3 = w3 % (block.number + 2); // around the current block (1000)
        bytes memory rep = abi.encode(w0, w1, w2, w3);
        bool canonical = w0 >> 160 == 0 && w1 <= 1 && w2 <= 255 && w3 >> 64 == 0;
        bytes memory meta = _meta(wfOwner);
        if (!canonical || w1 == 1 || w3 > block.number) {
            vm.prank(forwarder);
            vm.expectRevert(IRiparSentinel.BadReport.selector);
            sentinel.onReport(meta, rep);
        } else {
            address v = address(uint160(w0));
            vm.expectEmit(true, false, false, true, address(sentinel));
            emit LaneChanged(v, false, uint8(w2), uint64(w3));
            vm.prank(forwarder);
            sentinel.onReport(meta, rep);
            assertFalse(sentinel.laneOpen(v));
        }
    }

    // ------------------------------------------------------------------ onReport: future asOfBlock (v1.2)

    /// @dev A report cannot claim a block the chain has not reached (it would out-rank every later reopen).
    function test_onReport_futureAsOfBlock_isBadReport() public {
        _expectBadReport(_report(address(vault), false, 1, uint64(block.number + 1)));
        _expectBadReport(_report(address(vault), false, 1, uint64(block.number + 1_000_000)));
        _expectBadReport(_report(address(vault), false, 1, type(uint64).max));
        assertTrue(sentinel.laneOpen(address(vault)));

        // the current block and older ones close
        vm.expectEmit(true, false, false, true, address(sentinel));
        emit LaneChanged(address(vault), false, 1, uint64(block.number));
        _close(sentinel, address(vault), 1, uint64(block.number));
        assertFalse(sentinel.laneOpen(address(vault)));
        _close(sentinel, address(vault), 1, 0);

        // the check-off sentinel refuses future reports too
        bytes memory rep = _report(address(vault), false, 1, uint64(block.number + 1));
        vm.prank(forwarder);
        vm.expectRevert(IRiparSentinel.BadReport.selector);
        sentinelNoCheck.onReport("", rep);
    }

    /// @dev The forwarder and the workflow owner are still checked first.
    function test_onReport_futureAsOfBlock_checkOrder() public {
        bytes memory future = _report(address(vault), false, 1, type(uint64).max);
        vm.expectRevert(IRiparSentinel.NotForwarder.selector);
        sentinel.onReport(_meta(wfOwner), future);
        bytes memory meta = _meta(makeAddr("mallory"));
        vm.prank(forwarder);
        vm.expectRevert(IRiparSentinel.BadWorkflowOwner.selector);
        sentinel.onReport(meta, future);
    }

    function testFuzz_onReport_asOfBlockVsBlockNumber(uint64 blockNumber, uint64 asOfBlock) public {
        vm.roll(blockNumber);
        bytes memory meta = _meta(wfOwner);
        bytes memory rep = _report(address(vault), false, 5, asOfBlock);
        vm.prank(forwarder);
        if (asOfBlock > blockNumber) vm.expectRevert(IRiparSentinel.BadReport.selector);
        sentinel.onReport(meta, rep);
        assertEq(sentinel.laneOpen(address(vault)), asOfBlock > blockNumber);
    }

    // ------------------------------------------------------------------ reopen

    function test_reopen_happyPath() public {
        _close(sentinel, address(vault), 9, 990);
        assertFalse(sentinel.laneOpen(address(vault)));

        (bytes32 r, bytes32 s) = _reopenSig(sentinel, P1, address(vault), 1);
        vm.expectEmit(true, false, false, true, address(sentinel));
        emit LaneChanged(address(vault), true, 0, uint64(block.number));
        vm.prank(makeAddr("relayer")); // anyone may relay
        sentinel.reopen(address(vault), 1, r, s);

        assertTrue(sentinel.laneOpen(address(vault)));
        assertEq(sentinel.lastReopenNonce(address(vault)), 1);
        assertEq(sentinel.lastReopenBlock(address(vault)), block.number);
    }

    /// @dev v1.2: a lane that is open (never closed, or reopened since) cannot be "reopened". The revert burns
    ///      nothing: the same signature still works once the lane is closed.
    function test_revert_reopen_whileOpen_laneNotClosed() public {
        (bytes32 r, bytes32 s) = _reopenSig(sentinel, P1, address(vault), 3);
        vm.expectRevert(IRiparSentinel.LaneNotClosed.selector);
        sentinel.reopen(address(vault), 3, r, s);
        assertTrue(sentinel.laneOpen(address(vault)));
        assertEq(sentinel.lastReopenNonce(address(vault)), 0);
        assertEq(sentinel.lastReopenBlock(address(vault)), 0);

        _close(sentinel, address(vault), 1, 999);
        sentinel.reopen(address(vault), 3, r, s);
        assertTrue(sentinel.laneOpen(address(vault)));
        assertEq(sentinel.lastReopenNonce(address(vault)), 3);
        assertEq(sentinel.lastReopenBlock(address(vault)), 1000);

        // reopened: a further reopen (higher nonce, genuine signature) is refused until the next close
        (r, s) = _reopenSig(sentinel, P1, address(vault), 4);
        vm.roll(1001);
        vm.expectRevert(IRiparSentinel.LaneNotClosed.selector);
        sentinel.reopen(address(vault), 4, r, s);
        assertEq(sentinel.lastReopenNonce(address(vault)), 3);
        assertEq(sentinel.lastReopenBlock(address(vault)), 1000);
    }

    /// @dev LaneNotClosed comes after NoDeviceForVault and before NonceNotIncreasing and BadReopenSignature.
    function test_reopen_laneNotClosed_checkOrder() public {
        // no device for the vault: NoDeviceForVault first, open lane or not
        address noDevice = address(new MockVault(makeAddr("noDevice")));
        (bytes32 r, bytes32 s) = p256Sign(P1, sentinel.reopenDigest(noDevice, 1));
        vm.expectRevert(IRiparSentinel.NoDeviceForVault.selector);
        sentinel.reopen(noDevice, 1, r, s);
        // open lane: LaneNotClosed before a stale nonce and a garbage signature
        vm.expectRevert(IRiparSentinel.LaneNotClosed.selector);
        sentinel.reopen(address(vault), 0, bytes32(0), bytes32(0));
        _closeAndReopen(sentinel, P1, address(vault), 5);
        vm.expectRevert(IRiparSentinel.LaneNotClosed.selector);
        sentinel.reopen(address(vault), 5, bytes32(0), bytes32(0));
        // closed lane: NonceNotIncreasing, then BadReopenSignature
        _close(sentinel, address(vault), 1, uint64(block.number));
        vm.expectRevert(IRiparSentinel.NonceNotIncreasing.selector);
        sentinel.reopen(address(vault), 5, bytes32(0), bytes32(0));
        vm.expectRevert(IRiparSentinel.BadReopenSignature.selector);
        sentinel.reopen(address(vault), 6, bytes32(0), bytes32(0));
    }

    function testFuzz_revert_reopen_openLane(uint256 nonce, bytes32 r, bytes32 s) public {
        vm.expectRevert(IRiparSentinel.LaneNotClosed.selector);
        sentinel.reopen(address(vault), nonce, r, s);
    }

    function test_reopen_nonceMustIncrease() public {
        _close(sentinel, address(vault), 1, 1);
        (bytes32 r, bytes32 s) = _reopenSig(sentinel, P1, address(vault), 0);
        vm.expectRevert(IRiparSentinel.NonceNotIncreasing.selector);
        sentinel.reopen(address(vault), 0, r, s);

        _reopen(sentinel, P1, address(vault), 5);
        _close(sentinel, address(vault), 1, uint64(block.number));

        (r, s) = _reopenSig(sentinel, P1, address(vault), 5);
        vm.expectRevert(IRiparSentinel.NonceNotIncreasing.selector);
        sentinel.reopen(address(vault), 5, r, s); // replay

        (r, s) = _reopenSig(sentinel, P1, address(vault), 4);
        vm.expectRevert(IRiparSentinel.NonceNotIncreasing.selector);
        sentinel.reopen(address(vault), 4, r, s);

        _reopen(sentinel, P1, address(vault), 6);
        _closeAndReopen(sentinel, P1, address(vault), 1_000_000); // gaps are fine (pairing floor, lost QR codes)
        _closeAndReopen(sentinel, P1, address(vault), type(uint256).max);
        assertEq(sentinel.lastReopenNonce(address(vault)), type(uint256).max);

        _close(sentinel, address(vault), 1, uint64(block.number));
        (r, s) = _reopenSig(sentinel, P1, address(vault), type(uint256).max);
        vm.expectRevert(IRiparSentinel.NonceNotIncreasing.selector);
        sentinel.reopen(address(vault), type(uint256).max, r, s);
    }

    function test_reopen_noncesArePerVault() public {
        MockVault vault2 = new MockVault(owner);
        _closeAndReopen(sentinel, P1, address(vault), 10);
        _closeAndReopen(sentinel, P1, address(vault2), 1);
        assertEq(sentinel.lastReopenNonce(address(vault)), 10);
        assertEq(sentinel.lastReopenNonce(address(vault2)), 1);
    }

    function test_reopen_nonceCheckedBeforeSignature() public {
        _closeAndReopen(sentinel, P1, address(vault), 5);
        _close(sentinel, address(vault), 1, uint64(block.number));
        vm.expectRevert(IRiparSentinel.NonceNotIncreasing.selector);
        sentinel.reopen(address(vault), 5, bytes32(0), bytes32(0));
    }

    function test_reopen_wrongKey() public {
        _close(sentinel, address(vault), 1, 1);
        // another registered device, and an unregistered key
        (bytes32 r, bytes32 s) = _reopenSig(sentinel, P1_B, address(vault), 1);
        vm.expectRevert(IRiparSentinel.BadReopenSignature.selector);
        sentinel.reopen(address(vault), 1, r, s);
        (r, s) = _reopenSig(sentinel, P1_C, address(vault), 1);
        vm.expectRevert(IRiparSentinel.BadReopenSignature.selector);
        sentinel.reopen(address(vault), 1, r, s);
        assertFalse(sentinel.laneOpen(address(vault)));
        assertEq(sentinel.lastReopenNonce(address(vault)), 0);
    }

    function test_reopen_highS() public {
        _close(sentinel, address(vault), 1, 1);
        (bytes32 r, bytes32 s) = _reopenSig(sentinel, P1, address(vault), 1);
        vm.expectRevert(IRiparSentinel.BadReopenSignature.selector);
        sentinel.reopen(address(vault), 1, r, p256HighS(s));
        sentinel.reopen(address(vault), 1, r, s); // the low-s original works
    }

    function test_reopen_signatureBindsVaultNonceAndDomain() public {
        MockVault vault2 = new MockVault(owner); // same owner, same device
        _close(sentinel, address(vault), 1, 1);
        // signed for vault2, relayed for vault
        (bytes32 r, bytes32 s) = _reopenSig(sentinel, P1, address(vault2), 1);
        vm.expectRevert(IRiparSentinel.BadReopenSignature.selector);
        sentinel.reopen(address(vault), 1, r, s);
        // signed for nonce 1, relayed as nonce 2
        (r, s) = _reopenSig(sentinel, P1, address(vault), 1);
        vm.expectRevert(IRiparSentinel.BadReopenSignature.selector);
        sentinel.reopen(address(vault), 2, r, s);
        // signed for another sentinel (another domain)
        (r, s) = _reopenSig(sentinelNoCheck, P1, address(vault), 1);
        vm.expectRevert(IRiparSentinel.BadReopenSignature.selector);
        sentinel.reopen(address(vault), 1, r, s);
        // signed on another chain
        vm.chainId(143);
        (r, s) = _reopenSig(sentinel, P1, address(vault), 1);
        vm.chainId(31_337);
        vm.expectRevert(IRiparSentinel.BadReopenSignature.selector);
        sentinel.reopen(address(vault), 1, r, s);
    }

    function testFuzz_revert_reopen_garbageSig(bytes32 r, bytes32 s) public {
        _close(sentinel, address(vault), 1, 1);
        (bytes32 gr, bytes32 gs) = _reopenSig(sentinel, P1, address(vault), 1);
        vm.assume(r != gr || s != gs);
        vm.expectRevert(IRiparSentinel.BadReopenSignature.selector);
        sentinel.reopen(address(vault), 1, r, s);
    }

    function test_reopen_followsOwnerKeyRotation() public {
        // the owner re-pairs with a new device key: the old key can no longer reopen, the new one can
        _close(sentinel, address(vault), 1, 1);
        registerPair(reg, P1_C, K1);
        (bytes32 r, bytes32 s) = _reopenSig(sentinel, P1, address(vault), 1);
        vm.expectRevert(IRiparSentinel.BadReopenSignature.selector);
        sentinel.reopen(address(vault), 1, r, s);
        _reopen(sentinel, P1_C, address(vault), 1);
    }

    function test_reopen_followsVaultOwnerChange() public {
        _close(sentinel, address(vault), 1, 1);
        vault.setOwner(vm.addr(K1_B));
        (bytes32 r, bytes32 s) = _reopenSig(sentinel, P1, address(vault), 1);
        vm.expectRevert(IRiparSentinel.BadReopenSignature.selector);
        sentinel.reopen(address(vault), 1, r, s);
        _reopen(sentinel, P1_B, address(vault), 1);
    }

    // ------------------------------------------------------------------ reopen: NoDeviceForVault

    function _expectNoDevice(address v) internal {
        (bytes32 r, bytes32 s) = p256Sign(P1, sentinel.reopenDigest(v, 1));
        vm.expectRevert(IRiparSentinel.NoDeviceForVault.selector);
        sentinel.reopen(v, 1, r, s);
    }

    function test_reopen_noOwnerFunction() public {
        _expectNoDevice(makeAddr("eoaVault")); // no code: the call succeeds with no return data
        _expectNoDevice(address(0));
        _expectNoDevice(address(new NoOwnerVault())); // no owner(), no fallback: reverts
        _expectNoDevice(address(new RevertingOwnerVault())); // owner() reverts with a reason
        _expectNoDevice(address(new ShortOwnerVault())); // 20 bytes of return data
        _expectNoDevice(address(new DirtyOwnerVault(uint256(uint160(owner)) | (1 << 160)))); // not an address
        _expectNoDevice(address(reg)); // a contract without owner()
    }

    function test_reopen_dirtyVaultWithCleanWordWorks() public {
        // a raw fallback returning exactly the owner word is accepted (only the ABI word matters)
        address v = address(new DirtyOwnerVault(uint256(uint160(owner))));
        _closeAndReopen(sentinel, P1, v, 1);
        assertEq(sentinel.lastReopenNonce(v), 1);
    }

    function test_reopen_unregisteredOwner() public {
        _expectNoDevice(address(new MockVault(makeAddr("noDevice"))));
        _expectNoDevice(address(new MockVault(address(0))));
    }

    function test_reopen_ownerKeyUnlinkedElsewhere_stillResolvesCurrentKey() public {
        // owner B moves to a new key: B's vault reopens only with the new key
        MockVault vaultB = new MockVault(vm.addr(K1_B));
        _close(sentinel, address(vaultB), 1, 1);
        registerPair(reg, P1_C, K1_B);
        (bytes32 r, bytes32 s) = _reopenSig(sentinel, P1_B, address(vaultB), 1);
        vm.expectRevert(IRiparSentinel.BadReopenSignature.selector);
        sentinel.reopen(address(vaultB), 1, r, s);
        _reopen(sentinel, P1_C, address(vaultB), 1);
    }

    function test_reopen_inconsistentRegistry() public {
        InconsistentRegistry bad = new InconsistentRegistry();
        (bytes32 px, bytes32 py) = p256Key(P1);
        bad.set(p256KeyId(px, py), px, py, makeAddr("someoneElse"));
        RiparSentinel s2 = new RiparSentinel(forwarder, bad.asRegistry(), address(0));
        _close(s2, address(vault), 1, 1);
        (bytes32 r, bytes32 sg) = p256Sign(P1, s2.reopenDigest(address(vault), 1));
        vm.expectRevert(IRiparSentinel.NoDeviceForVault.selector);
        s2.reopen(address(vault), 1, r, sg);
        // once consistent it works
        bad.set(p256KeyId(px, py), px, py, owner);
        s2.reopen(address(vault), 1, r, sg);
        assertTrue(s2.laneOpen(address(vault)));
    }

    // ------------------------------------------------------------------ close vs reopen ordering

    function test_staleCloseAfterReopen_isIgnored() public {
        vm.roll(100);
        _close(sentinel, address(vault), 1, 95);
        assertFalse(sentinel.laneOpen(address(vault)));

        vm.roll(120);
        _reopen(sentinel, P1, address(vault), 1);
        assertEq(sentinel.lastReopenBlock(address(vault)), 120);

        // a delayed report computed as of block 119 (before the reopen) must not undo it
        vm.roll(130);
        vm.expectEmit(true, false, false, true, address(sentinel));
        emit ReportIgnored(address(vault), 2, 119);
        _close(sentinel, address(vault), 2, 119);
        assertTrue(sentinel.laneOpen(address(vault)));

        // a report as of the reopen block itself or later closes
        vm.expectEmit(true, false, false, true, address(sentinel));
        emit LaneChanged(address(vault), false, 3, 120);
        _close(sentinel, address(vault), 3, 120);
        assertFalse(sentinel.laneOpen(address(vault)));

        // the device can reopen again, with a higher nonce
        vm.roll(140);
        _reopen(sentinel, P1, address(vault), 2);
        assertTrue(sentinel.laneOpen(address(vault)));
        vm.roll(145);
        _close(sentinel, address(vault), 4, 139); // ignored
        assertTrue(sentinel.laneOpen(address(vault)));
        _close(sentinel, address(vault), 4, 141);
        assertFalse(sentinel.laneOpen(address(vault)));
    }

    /// @dev DOCUMENTED LIMITATION (SPEC v1.2 "Reopen is a bearer authorization"): a reopen signed earlier and withheld
    ///      cannot pre-empt a close (LaneNotClosed while the lane is open), but once a LATER close landed it is
    ///      accepted and undoes that close, until a higher nonce is relayed.
    function test_knownLimitation_withheldReopenUndoesALaterClose() public {
        _close(sentinel, address(vault), 1, 999);
        (bytes32 r1, bytes32 s1) = _reopenSig(sentinel, P1, address(vault), 1);
        (bytes32 r2, bytes32 s2) = _reopenSig(sentinel, P1, address(vault), 2); // withheld
        sentinel.reopen(address(vault), 1, r1, s1);
        vm.expectRevert(IRiparSentinel.LaneNotClosed.selector);
        sentinel.reopen(address(vault), 2, r2, s2); // cannot pre-empt anything while the lane is open

        vm.roll(2000);
        _close(sentinel, address(vault), 7, 1999); // a later close
        sentinel.reopen(address(vault), 2, r2, s2); // LIMITATION: the withheld reopen undoes it
        assertTrue(sentinel.laneOpen(address(vault)));
        _close(sentinel, address(vault), 7, 1999); // a report computed before that reopen is ignored
        assertTrue(sentinel.laneOpen(address(vault)));
        _close(sentinel, address(vault), 7, 2000); // as of the reopen block: closes, and nonce 2 is spent
        assertFalse(sentinel.laneOpen(address(vault)));
        vm.expectRevert(IRiparSentinel.NonceNotIncreasing.selector);
        sentinel.reopen(address(vault), 2, r2, s2);
    }

    function test_staleReport_doesNotAffectOtherVaults() public {
        MockVault vault2 = new MockVault(owner);
        vm.roll(500);
        _closeAndReopen(sentinel, P1, address(vault), 1);
        _close(sentinel, address(vault2), 1, 10); // vault2 was never reopened: closes
        assertFalse(sentinel.laneOpen(address(vault2)));
        assertTrue(sentinel.laneOpen(address(vault)));
    }

    function testFuzz_closeVsReopenBlock(uint64 reopenBlock, uint64 asOfBlock) public {
        reopenBlock = uint64(bound(reopenBlock, 1, type(uint64).max));
        vm.roll(reopenBlock);
        _closeAndReopen(sentinel, P1, address(vault), 1);
        // the report lands once the chain reached its asOfBlock (a future asOfBlock is BadReport, v1.2)
        if (asOfBlock > reopenBlock) vm.roll(asOfBlock);
        _close(sentinel, address(vault), 1, asOfBlock);
        assertEq(sentinel.laneOpen(address(vault)), asOfBlock < reopenBlock);
    }
}

/// @notice OZ P256 Solidity fallback (no code at 0x0100, like a local EVM).
contract RiparSentinelTest is RiparSentinelTestBase {
    function setUp() public override {
        super.setUp();
        _setUpP256Path(false);
    }
}

/// @notice P256VERIFY precompile at 0x0100 (like Monad).
contract RiparSentinelPrecompileTest is RiparSentinelTestBase {
    function setUp() public override {
        super.setUp();
        _setUpP256Path(true);
    }

    function test_reopen_usesPrecompile() public {
        _close(sentinel, address(vault), 1, 1);
        bytes32 d = sentinel.reopenDigest(address(vault), 1);
        (bytes32 r, bytes32 s) = p256Sign(P1, d);
        (bytes32 px, bytes32 py) = p256Key(P1);
        vm.expectCall(P256_PRECOMPILE, abi.encode(d, r, s, px, py));
        sentinel.reopen(address(vault), 1, r, s);
    }
}
