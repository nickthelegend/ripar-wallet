// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { Vm } from "forge-std/Vm.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { ExecutionLib } from "@erc7579/lib/ExecutionLib.sol";
import { HybridDeleGator } from "@delegation-framework/HybridDeleGator.sol";
import { DelegationManager } from "@delegation-framework/DelegationManager.sol";
import { Delegation, Caveat, ModeCode } from "@delegation-framework/utils/Types.sol";

import { RiparReputationRelay } from "../../src/RiparReputationRelay.sol";
import { IPulseCosignEnforcer } from "../../src/interfaces/IPulseCosignEnforcer.sol";
import { IRiparSentinel } from "../../src/interfaces/IRiparSentinel.sol";
import { IRiparDeviceRegistry } from "../../src/interfaces/IRiparDeviceRegistry.sol";
import { IRiparReputationRelay } from "../../src/interfaces/IRiparReputationRelay.sol";
import { IERC8004Identity, IERC8004Reputation } from "../../src/interfaces/external/IERC8004.sol";
import { IntegrationBase } from "../utils/integration/IntegrationBase.sol";
import { IntegrationIdentityStub } from "../utils/integration/IntegrationMocks.sol";
import { AcceptAllDelegator, AcceptAllOwnedDelegator, DenialShield } from "../utils/periphery/RegressionActors.sol";

/// @notice Regression suite for the periphery findings of the v1.1 adversarial review (SPEC "Changes in v1.2"). Each
///         original PoC (.work/snap-v11/poc/**) is ported as a NEGATIVE test that passes on v1.2, on the REAL
///         MetaMask delegation framework v1.3.0 (IntegrationBase: DelegationManager, HybridDeleGator vault, EntryPoint)
///         with the real Ripar contracts. Tests named test_LIMITATION_* pin a documented limitation that v1.2 keeps by
///         design (SPEC "Documented limitations after v1.2"); they assert today's behaviour and say so.
///         Throwaway test keys only.
abstract contract PeripheryRegressionBase is IntegrationBase {
    event AgentShielded(uint256 indexed agentId, bytes32 indexed keyId, bytes32 requestHash);

    uint256 internal constant SOFT_P1 = 0xBADC0FFEE; // an attacker's software P-256 key
    uint256 internal constant ATK_K1 = 0xBAD1; // the attacker's own secp256k1 key

    address internal atk;
    uint256 internal atkAgentId; // the attacker's own ERC-8004 agent (atk owns it)

    function setUp() public virtual override {
        super.setUp();
        atk = vm.addr(ATK_K1);
        vm.label(atk, "attacker");
        vm.prank(atk);
        atkAgentId = identity.register("ipfs://sock-puppet", new IERC8004Identity.MetadataEntry[](0));
    }

    // ================================================================== helpers

    /// @dev Pulse terms naming `p1Pk`'s key, no caps, no sentinel (only the HUMAN path is used).
    function _softTerms(uint256 p1Pk) internal view returns (IPulseCosignEnforcer.PulseTerms memory t) {
        (bytes32 sx, bytes32 sy) = p256Key(p1Pk);
        t = _tokenTerms();
        t.px = sx;
        t.py = sy;
        t.sentinel = address(0);
    }

    function _p1KeyId(uint256 p1Pk) internal pure returns (bytes32) {
        (bytes32 x, bytes32 y) = p256Key(p1Pk);
        return p256KeyId(x, y);
    }

    /// @dev A root delegation `delegator` -> `delegate` with one Pulse caveat, signed by `k1Pk` (or unsigned: "00" for
    ///      a delegator that accepts every signature when k1Pk == 0).
    function _rootFrom(
        address delegator,
        address delegate,
        IPulseCosignEnforcer.PulseTerms memory t,
        uint256 salt,
        uint256 k1Pk
    ) internal view returns (Delegation memory d) {
        Caveat[] memory caveats = new Caveat[](1);
        caveats[0] = Caveat({ enforcer: address(enforcer), terms: abi.encode(t), args: "" });
        d = Delegation({
            delegate: delegate,
            delegator: delegator,
            authority: ROOT_AUTHORITY,
            caveats: caveats,
            salt: salt,
            signature: hex"00"
        });
        if (k1Pk != 0) {
            d.signature =
                _k1Sign(k1Pk, _digest(delegationManager.getDomainHash(), delegationManager.getDelegationHash(d)));
        }
    }

    /// @dev A HybridDeleGator (the framework's vault) owned by `owner_`, holding nothing.
    function _hybridVault(address owner_) internal returns (address) {
        bytes memory init =
            abi.encodeCall(HybridDeleGator.initialize, (owner_, new string[](0), new uint256[](0), new uint256[](0)));
        return address(new ERC1967Proxy(address(hybridImpl), init));
    }

    /// @dev The HUMAN path of `d` co-signed with `p1Pk` (whatever key the terms name), redeemed by `red` through the
    ///      fixture's DelegationManager (the one the relay credits). Returns the approval digest.
    function _selfCosign(
        Delegation memory d,
        uint256 p1Pk,
        address red,
        address target,
        uint256 value,
        bytes memory data,
        uint256 nonce
    ) internal returns (bytes32 digest) {
        Cosign memory c = _cosignFor(d, red, target, value, data, nonce);
        c.delegationHash = delegationManager.getDelegationHash(d);
        digest = _approvalDigest(c);
        (bytes32 r, bytes32 s) = p256Sign(p1Pk, digest);
        _redeemAs(red, d, abi.encode(c.nonce, c.expiry, c.presenceHash, r, s), target, value, data);
        assertTrue(enforcer.consumed(address(delegationManager), digest), "consumed at the relay's DelegationManager");
    }

    function _expectAttestRevert(address caller, uint256 id, bytes32 digest, bytes4 err) internal {
        vm.expectRevert(err);
        vm.prank(caller);
        relay.attestApproval(id, digest);
    }

    /// @dev registers (p1Pk, k1Pk) in the fixture registry with genuine signatures
    function _register(uint256 p1Pk, uint256 k1Pk) internal returns (bytes32) {
        (bytes32 x, bytes32 y) = p256Key(p1Pk);
        address o = vm.addr(k1Pk);
        bytes32 b = registry.bindDigest(o, x, y);
        (bytes32 r, bytes32 s) = p256Sign(p1Pk, b);
        return registry.registerDevice(o, x, y, r, s, _k1Sign(k1Pk, b));
    }

    /// @dev the user co-signs `payee` once on `m`, which makes it a known AUTO payee of that mandate
    function _approvePayee(Delegation memory m) internal returns (bytes32 digest) {
        bytes memory data = _transfer(payee, 1e6);
        bytes memory args;
        (args, digest) = _signCosign(_cosign(m, address(musd), 0, data, 1));
        _redeem(m, args, address(musd), 0, data);
    }

    function _denyAs(uint256 p1Pk, uint256 id, bytes32 requestHash) internal {
        (bytes32 x, bytes32 y) = p256Key(p1Pk);
        (bytes32 r, bytes32 s) = p256Sign(p1Pk, relay.denyDigest(id, requestHash, bytes32(0)));
        relay.attestDenial(id, requestHash, bytes32(0), x, y, r, s);
    }

    // ================================================================== positive control

    /// @dev The fix does not touch the real flow: the vault owner's registered device co-signs, the agent redeems
    ///      through the canonical DelegationManager and credits its agent.
    function test_control_genuineDeviceCosign_isCredited() public {
        Delegation memory m = _mandate(_tokenTerms(), 100);
        bytes32 digest = _approvePayee(m);
        uint256 before = reputation.feedbackCount();
        vm.expectEmit(true, true, false, true, address(relay));
        emit Verdict(agentId, keyId, digest, true);
        vm.prank(agent);
        relay.attestApproval(agentId, digest);
        assertEq(reputation.feedbackCount(), before + 1);
    }

    // ================================================================== PERIPHERY-1 / INTEGRATION-1 / ENF-2 / ATTACKER-2
    // v1.1: an agent minted unlimited "ripar/cosigned" +1s for itself with a software P-256 key and a vault of its own
    // (or a contract accepting every delegation signature). v1.2: the co-signing key must be the registered device of
    // the vault's owner, otherwise attestApproval reverts UnknownDevice.

    /// @dev PERIPHERY-1: the attacker's own HybridDeleGator, its software key (never registered), one batched
    ///      redemption of n self co-signs through the canonical DelegationManager.
    function test_PERIPHERY1_selfMintedApprovals_unregisteredKey_UnknownDevice() public {
        address fakeVault = _hybridVault(atk);
        IPulseCosignEnforcer.PulseTerms memory t = _softTerms(SOFT_P1);
        t.token = address(0);
        Delegation memory d = _rootFrom(fakeVault, atk, t, 1, ATK_K1);
        bytes32 dh = delegationManager.getDelegationHash(d);

        uint256 n = 5;
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes[] memory contexts = new bytes[](n);
        ModeCode[] memory modes = new ModeCode[](n);
        bytes[] memory executions = new bytes[](n);
        bytes32[] memory digests = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            digests[i] = enforcer.approvalDigest(dh, fakeVault, atk, atk, 0, keccak256(""), i + 1, expiry, bytes32(0));
            (bytes32 r, bytes32 s) = p256Sign(SOFT_P1, digests[i]);
            Delegation[] memory chain = new Delegation[](1);
            chain[0] = _withArgs(d, abi.encode(i + 1, expiry, bytes32(0), r, s));
            contexts[i] = abi.encode(chain);
            modes[i] = singleMode;
            executions[i] = ExecutionLib.encodeSingle(atk, 0, "");
        }
        vm.prank(atk);
        delegationManager.redeemDelegations(contexts, modes, executions);

        uint256 before = reputation.feedbackCount();
        for (uint256 i; i < n; ++i) {
            assertTrue(enforcer.consumed(address(delegationManager), digests[i]), "the enforcer still records it");
            _expectAttestRevert(atk, atkAgentId, digests[i], IRiparReputationRelay.UnknownDevice.selector);
            assertFalse(relay.approvalAttested(digests[i]));
        }
        assertEq(reputation.feedbackCount(), before, "no self-minted +1");
        (,, address softOwner) = registry.keyOf(_p1KeyId(SOFT_P1));
        assertEq(softOwner, address(0), "the co-signing key is not a registered device");

        // registering the software key to someone else than the vault's owner does not help either
        uint256 atk2K1 = 0xBAD3;
        _register(SOFT_P1, atk2K1);
        _expectAttestRevert(atk, atkAgentId, digests[0], IRiparReputationRelay.UnknownDevice.selector);
        assertEq(reputation.feedbackCount(), before);
    }

    /// @dev PERIPHERY-1b: every AUTO spend of the user's vault laundered into a "cosigned" record: the agent
    ///      re-delegates the user's mandate to itself (agent -> agent) under its own Pulse caveat and "co-signs" each
    ///      leaf with its software key. The leaf's delegator is the agent (an EOA, no owner()): UnknownDevice, even
    ///      after the agent registers its software key to itself.
    function test_PERIPHERY1b_autoSpendLaundering_UnknownDevice() public {
        Delegation memory root = _mandate(_tokenTerms(), 7);
        bytes32 rootHash = _hash(root);
        _approvePayee(root); // the only human act: payee becomes a known AUTO payee
        uint256 before = reputation.feedbackCount();

        Caveat[] memory caveats = new Caveat[](1);
        caveats[0] = Caveat({ enforcer: address(enforcer), terms: abi.encode(_softTerms(SOFT_P1)), args: "" });
        Delegation memory leaf = Delegation({
            delegate: agent, delegator: agent, authority: rootHash, caveats: caveats, salt: 1, signature: ""
        });
        bytes32 leafHash = delegationManager.getDelegationHash(leaf);
        leaf.signature = _k1Sign(agentPk, _digest(delegationManager.getDomainHash(), leafHash));

        bytes32[3] memory digests;
        for (uint256 i; i < 3; ++i) {
            digests[i] = _launder(leaf, root, leafHash, i + 1);
            _expectAttestRevert(agent, agentId, digests[i], IRiparReputationRelay.UnknownDevice.selector);
        }
        assertEq(musd.balanceOf(payee), 1e6 + 15e6, "the AUTO spends themselves still happen (known payee, caps)");

        // the agent registers its software key to its own K1 (the agent EOA): the leaf's delegator still has no
        // owner(), so nothing is credited
        _register(SOFT_P1, agentPk);
        for (uint256 i; i < 3; ++i) {
            _expectAttestRevert(agent, agentId, digests[i], IRiparReputationRelay.UnknownDevice.selector);
        }
        assertEq(reputation.feedbackCount(), before, "no laundered +1");
    }

    function _launder(Delegation memory leaf, Delegation memory root, bytes32 leafHash, uint256 i)
        internal
        returns (bytes32 digest)
    {
        bytes memory data = _transfer(payee, 5e6);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        digest = enforcer.approvalDigest(leafHash, agent, agent, address(musd), 0, keccak256(data), i, expiry, 0);
        Delegation[] memory chain = new Delegation[](2);
        {
            (bytes32 r, bytes32 s) = p256Sign(SOFT_P1, digest);
            chain[0] = _withArgs(leaf, abi.encode(i, expiry, bytes32(0), r, s)); // HUMAN path, the agent's own key
        }
        chain[1] = _withArgs(root, ""); // the user's mandate: AUTO path
        _redeemChain(agent, chain, singleMode, ExecutionLib.encodeSingle(address(musd), 0, data));
        assertTrue(enforcer.consumed(address(delegationManager), digest));
    }

    /// @dev ENF-2: a delegator accepting every signature (no owner()), a software key, the fixture's agent as
    ///      redeemer (authorized for agentId), a 1,000,000 mUSD "payment" that moves nothing.
    function test_ENF2_selfDealtApprovals_acceptAllDelegator_UnknownDevice() public {
        address fake = address(new AcceptAllDelegator());
        Delegation memory d = _rootFrom(fake, agent, _softTerms(SOFT_P1), 0, 0);
        uint256 before = reputation.feedbackCount();
        for (uint256 i = 1; i <= 5; ++i) {
            bytes32 digest = _selfCosign(d, SOFT_P1, agent, address(musd), 0, _transfer(payee, 1_000_000e6), i);
            _expectAttestRevert(agent, agentId, digest, IRiparReputationRelay.UnknownDevice.selector);
        }
        assertEq(reputation.feedbackCount(), before, "no self-dealt +1");
        assertEq(musd.balanceOf(payee), 0, "nothing was ever paid");
    }

    /// @dev INTEGRATION-1: the same with the attacker's own agent and 0-value native self co-signs. A fake vault that
    ///      claims the VICTIM (whose device is registered) as its owner() does not help: the key must be the one the
    ///      registry binds to that owner.
    function test_INTEGRATION1_selfMintedApprovals_fakeVault_UnknownDevice() public {
        IPulseCosignEnforcer.PulseTerms memory t = _softTerms(SOFT_P1);
        t.token = address(0);
        Delegation memory d = _rootFrom(address(new AcceptAllDelegator()), atk, t, 0, 0);
        Delegation memory spoof = _rootFrom(address(new AcceptAllOwnedDelegator(k1)), atk, t, 0, 0);
        uint256 before = reputation.feedbackCount();
        for (uint256 i = 1; i <= 4; ++i) {
            bytes32 digest = _selfCosign(d, SOFT_P1, atk, atk, 0, "", i);
            _expectAttestRevert(atk, atkAgentId, digest, IRiparReputationRelay.UnknownDevice.selector);
            digest = _selfCosign(spoof, SOFT_P1, atk, atk, 0, "", i);
            _expectAttestRevert(atk, atkAgentId, digest, IRiparReputationRelay.UnknownDevice.selector);
        }
        assertEq(reputation.feedbackCount(), before);
    }

    /// @dev ATTACKER-2: a genuine HybridDeleGator owned by the attacker's K1, co-signed by the attacker's unregistered
    ///      P-256 key, redeemed by the fixture's agent. Also refused when the key is registered to another owner.
    function test_ATTACKER2_selfFarmedApprovals_ownHybridVault_UnknownDevice() public {
        uint256 evilK1 = 0xBAD1_0001;
        uint256 evilP1 = 0xBAD2;
        address evilVault = _hybridVault(vm.addr(evilK1));
        Delegation memory d = _rootFrom(evilVault, agent, _softTerms(evilP1), 666, evilK1);
        uint256 before = reputation.feedbackCount();
        bytes32[5] memory digests;
        for (uint256 i; i < 5; ++i) {
            digests[i] = _selfCosign(d, evilP1, agent, agent, 0, "", i + 1);
            _expectAttestRevert(agent, agentId, digests[i], IRiparReputationRelay.UnknownDevice.selector);
        }
        _register(evilP1, 0xBAD1_0002); // bound to a K1 that does not own evilVault
        _expectAttestRevert(agent, agentId, digests[0], IRiparReputationRelay.UnknownDevice.selector);
        assertEq(reputation.feedbackCount(), before, "no farmed +1");
    }

    /// @dev DOCUMENTED LIMITATION (relay NatSpec KNOWN LIMITATION 2; registry: anyone can register a key): the device
    ///      check ties the co-signing key to the vault's owner, not to genuine hardware. An attacker that registers
    ///      its software key to its own K1 and delegates from a vault that K1 owns is credited, one +1 per co-sign,
    ///      exactly like a real device. Readers must weigh approvals by keyId / vault owner, as for denials.
    function test_LIMITATION_PERIPHERY1_selfRegisteredKeyOnOwnVault_isCredited() public {
        bytes32 softId = _register(SOFT_P1, ATK_K1);
        address ownVault = _hybridVault(atk);
        IPulseCosignEnforcer.PulseTerms memory t = _softTerms(SOFT_P1);
        t.token = address(0);
        Delegation memory d = _rootFrom(ownVault, atk, t, 1, ATK_K1);
        uint256 before = reputation.feedbackCount();
        bytes32 digest = _selfCosign(d, SOFT_P1, atk, atk, 0, "", 1);
        vm.expectEmit(true, true, false, true, address(relay));
        emit Verdict(atkAgentId, softId, digest, true);
        vm.prank(atk);
        relay.attestApproval(atkAgentId, digest);
        assertEq(reputation.feedbackCount(), before + 1, "LIMITATION: a self-registered key on an own vault counts");
    }

    // ================================================================== PERIPHERY-2 / PROTOCOL-3 / ATTACKER-3
    // v1.1: a Reopen signature never expires and is not bound to the close it answers, so a withheld reopen could be
    // relayed while the lane was OPEN, right before an in-flight close report, which it then voided (asOfBlock <
    // lastReopenBlock -> ReportIgnored). v1.2: reopen reverts LaneNotClosed unless the lane is closed. A withheld
    // reopen can still undo a close (by design: SPEC "Reopen is a bearer authorization"), never pre-empt one.

    /// @dev PERIPHERY-2 with the lane open (it was reopened normally): the withheld reopen cannot be relayed ahead of
    ///      the genuine close report, which lands and closes the lane.
    function test_PERIPHERY2_withheldReopen_cannotPreemptCloseWhileOpen() public {
        Delegation memory d = _mandate(_tokenTerms(), 1);
        _approvePayee(d);
        _closeLane(1, uint64(block.number));
        _reopen(1); // relayed normally: the lane is open
        (bytes32 r2, bytes32 s2) = _reopenSig(2); // "relay failed": the companion keeps it

        vm.roll(block.number + 2_000_000);
        vm.warp(block.timestamp + 30 days);
        uint64 m = uint64(block.number); // CRE observes a genuine threat
        vm.roll(m + 2);
        vm.prank(makeAddr("holder of the withheld reopen"));
        vm.expectRevert(IRiparSentinel.LaneNotClosed.selector);
        sentinel.reopen(address(vault), 2, r2, s2);

        vm.roll(m + 3);
        vm.expectEmit(true, true, true, true, address(sentinel));
        emit LaneChanged(address(vault), false, 2, m);
        _closeLane(2, m);
        assertFalse(sentinel.laneOpen(address(vault)), "the fresh threat report closed the lane");
        vm.expectRevert(IPulseCosignEnforcer.LaneClosed.selector);
        _autoTransfer(d, payee, PER_TX);
        assertEq(musd.balanceOf(payee), 1e6);
    }

    /// @dev DOCUMENTED LIMITATION (SPEC v1.2 "Reopen is a bearer authorization"): PERIPHERY-2 as written. The lane was
    ///      closed on day 0 and never reopened; the reopen the user signed for that close is withheld and relayed 30
    ///      days later. It still undoes the close it answers, and a report computed before it is ignored. CRE must
    ///      report again as of a block at or after the reopen (SPEC "Stale reports"); the withheld nonce is then spent.
    function test_LIMITATION_PERIPHERY2_withheldReopenStillUndoesTheCloseItAnswers() public {
        Delegation memory d = _mandate(_tokenTerms(), 1);
        _approvePayee(d);
        _closeLane(1, uint64(block.number));
        (bytes32 r1, bytes32 s1) = _reopenSig(1);

        vm.roll(block.number + 2_000_000);
        vm.warp(block.timestamp + 30 days);
        uint64 m = uint64(block.number);
        vm.roll(m + 2);
        vm.prank(makeAddr("holder of the withheld reopen"));
        sentinel.reopen(address(vault), 1, r1, s1); // LIMITATION: allowed, the lane is closed
        vm.roll(m + 3);
        vm.expectEmit(true, true, true, true, address(sentinel));
        emit ReportIgnored(address(vault), 2, m);
        _closeLane(2, m);
        assertTrue(sentinel.laneOpen(address(vault)), "LIMITATION: the withheld reopen undid the close");
        _autoTransfer(d, payee, PER_TX);

        // a report as of the reopen block or later closes again, and the withheld nonce is spent
        _closeLane(2, m + 3);
        assertFalse(sentinel.laneOpen(address(vault)));
        vm.expectRevert(IRiparSentinel.NonceNotIncreasing.selector);
        sentinel.reopen(address(vault), 1, r1, s1);
    }

    /// @dev PROTOCOL-3 (second half): two reopens signed while the lane was open and withheld. Neither can be relayed
    ///      while the lane is open, in particular not to front-run CRE's in-flight close report.
    function test_PROTOCOL3_withheldReopen_cannotPreemptInFlightClose() public {
        Delegation memory mandate = _mandate(_tokenTerms(), 1);
        _approvePayee(mandate);
        assertTrue(sentinel.laneOpen(address(vault)));
        (bytes32 r1, bytes32 s1) = _reopenSig(1);
        (bytes32 r2, bytes32 s2) = _reopenSig(2);
        vm.expectRevert(IRiparSentinel.LaneNotClosed.selector);
        sentinel.reopen(address(vault), 1, r1, s1);

        vm.roll(block.number + 1000);
        uint64 observedAt = uint64(block.number);
        vm.roll(block.number + 50); // the report is in flight; the companion tries to front-run it
        vm.expectRevert(IRiparSentinel.LaneNotClosed.selector);
        sentinel.reopen(address(vault), 2, r2, s2);
        vm.expectEmit(true, true, true, true, address(sentinel));
        emit LaneChanged(address(vault), false, 8, observedAt);
        _closeLane(8, observedAt);
        assertFalse(sentinel.laneOpen(address(vault)), "the in-flight close is not voided");
        vm.expectRevert(IPulseCosignEnforcer.LaneClosed.selector);
        _autoTransfer(mandate, payee, PER_TX);
        assertEq(sentinel.lastReopenNonce(address(vault)), 0, "no withheld reopen was consumed");
    }

    /// @dev DOCUMENTED LIMITATION: PROTOCOL-3 (first half). A reopen signed while the lane was open and withheld can,
    ///      weeks later, undo a LATER close. Relaying a newer reopen at once is what voids the older ones.
    function test_LIMITATION_PROTOCOL3_withheldReopenUndoesLaterClose() public {
        Delegation memory mandate = _mandate(_tokenTerms(), 1);
        _approvePayee(mandate);
        (bytes32 r1, bytes32 s1) = _reopenSig(1);
        (bytes32 r2, bytes32 s2) = _reopenSig(2);

        vm.roll(B0 + 5_000_000);
        vm.warp(T0 + 30 days);
        _closeLane(7, uint64(block.number));
        vm.expectRevert(IPulseCosignEnforcer.LaneClosed.selector);
        _autoTransfer(mandate, payee, 1e6);
        sentinel.reopen(address(vault), 1, r1, s1); // LIMITATION: the lane is closed, so the reopen is accepted
        assertTrue(sentinel.laneOpen(address(vault)), "LIMITATION: a withheld reopen undid a later close");
        _autoTransfer(mandate, payee, PER_TX);

        // mitigation: the device's next reopen, relayed immediately, voids the still-withheld nonce 2
        _closeLane(8, uint64(block.number));
        _reopen(3);
        vm.roll(block.number + 1);
        _closeLane(9, uint64(block.number));
        vm.expectRevert(IRiparSentinel.NonceNotIncreasing.selector);
        sentinel.reopen(address(vault), 2, r2, s2);
        assertFalse(sentinel.laneOpen(address(vault)));
    }

    /// @dev ATTACKER-3 (front-run variant): a reopen signed long ago while the lane was open, relayed right before the
    ///      in-flight close report: LaneNotClosed, the close lands, AUTO stops.
    function test_ATTACKER3_withheldReopen_cannotFrontRunInFlightClose() public {
        Delegation memory m = _mandate(_tokenTerms(), 14);
        _approvePayee(m);
        (bytes32 r, bytes32 s) = _reopenSig(1);

        vm.roll(B0 + 500);
        vm.expectRevert(IRiparSentinel.LaneNotClosed.selector);
        sentinel.reopen(address(vault), 1, r, s);
        vm.expectEmit(true, true, true, true, address(sentinel));
        emit LaneChanged(address(vault), false, 9, B0 + 499);
        _closeLane(9, B0 + 499);
        assertFalse(sentinel.laneOpen(address(vault)));
        vm.expectRevert(IPulseCosignEnforcer.LaneClosed.selector);
        _autoTransfer(m, payee, PER_TX);
    }

    /// @dev DOCUMENTED LIMITATION: ATTACKER-3 (override variant). The companion relays reopen 1 and keeps reopen 2;
    ///      after a NEW close, relaying reopen 2 undoes it (the lane is closed, so it is accepted), and a report
    ///      computed before that reopen is ignored. A report as of the reopen block or later closes again.
    function test_LIMITATION_ATTACKER3_withheldReopenOverridesLaterClose() public {
        Delegation memory m = _mandate(_tokenTerms(), 13);
        _approvePayee(m);
        vm.roll(B0 + 5);
        _closeLane(1, B0 + 5);
        vm.roll(B0 + 10);
        (bytes32 r1, bytes32 s1) = _reopenSig(1);
        (bytes32 r2, bytes32 s2) = _reopenSig(2);
        sentinel.reopen(address(vault), 1, r1, s1);
        // while the lane is open the withheld reopen is refused (v1.2)
        vm.expectRevert(IRiparSentinel.LaneNotClosed.selector);
        sentinel.reopen(address(vault), 2, r2, s2);

        vm.roll(B0 + 100);
        _closeLane(7, B0 + 100);
        vm.expectRevert(IPulseCosignEnforcer.LaneClosed.selector);
        _autoTransfer(m, payee, PER_TX);

        vm.roll(B0 + 101);
        vm.prank(agent);
        sentinel.reopen(address(vault), 2, r2, s2); // LIMITATION: undoes the later close
        assertTrue(sentinel.laneOpen(address(vault)));
        vm.expectEmit(true, true, true, true, address(sentinel));
        emit ReportIgnored(address(vault), 7, B0 + 100);
        _closeLane(7, B0 + 100);
        _autoTransfer(m, payee, PER_TX);

        _closeLane(7, B0 + 101);
        assertFalse(sentinel.laneOpen(address(vault)));
        vm.expectRevert(IRiparSentinel.NonceNotIncreasing.selector);
        sentinel.reopen(address(vault), 2, r2, s2);
    }

    // ================================================================== PERIPHERY-3 / INTEGRATION-5 / ATTACKER-5
    // v1.1: BindDevice has no nonce or deadline and an unlinked key could be bound again, so anyone could replay the
    // owner's old (public) pairing calldata and roll a key rotation back. v1.2: the rotated key is RETIRED and binding
    // it reverts KeyTaken for any owner.

    /// @dev Captures the original pairing calldata, rotates the owner's key to `newPk`, replays the old binding as
    ///      `replayer` (KeyTaken) and checks that the rotation holds everywhere. Returns the new keyId.
    function _bindReplayScenario(uint256 newPk, address replayer) internal returns (bytes32 newKeyId) {
        newKeyId = _rotateAndReplay(newPk, replayer);
        _assertRotationHolds(newPk, newKeyId);
    }

    function _rotateAndReplay(uint256 newPk, address replayer) internal returns (bytes32 newKeyId) {
        bytes32 oldBind = registry.bindDigest(k1, px, py);
        (bytes32 oR, bytes32 oS) = p256Sign(DEVICE_P1_PK, oldBind);
        bytes memory oSig = _k1Sign(DEVICE_K1_PK, oldBind);

        newKeyId = _register(newPk, DEVICE_K1_PK);
        assertTrue(registry.isRetired(keyId), "the old key is retired");

        vm.prank(replayer);
        vm.expectRevert(IRiparDeviceRegistry.KeyTaken.selector);
        registry.registerDevice(k1, px, py, oR, oS, oSig);

        assertEq(registry.keyIdOf(k1), newKeyId, "the rotation holds");
        (,, address o) = registry.keyOf(keyId);
        assertEq(o, address(0), "the old key stays unlinked");
        (,, o) = registry.keyOf(newKeyId);
        assertEq(o, k1, "the new key stays bound");
    }

    function _assertRotationHolds(uint256 newPk, bytes32 newKeyId) internal {
        (bytes32 nx, bytes32 ny) = p256Key(newPk);
        // the old key cannot reopen; the new device can
        _closeLane(1, uint64(block.number));
        vm.roll(block.number + 1);
        (bytes32 r, bytes32 s) = _reopenSig(1); // signed by the retired key
        vm.expectRevert(IRiparSentinel.BadReopenSignature.selector);
        sentinel.reopen(address(vault), 1, r, s);
        (r, s) = p256Sign(newPk, sentinel.reopenDigest(address(vault), 1));
        sentinel.reopen(address(vault), 1, r, s);
        assertTrue(sentinel.laneOpen(address(vault)));

        // the old key cannot deny; the new device can
        bytes32 requestHash = keccak256("some request");
        (r, s) = p256Sign(DEVICE_P1_PK, relay.denyDigest(agentId, requestHash, bytes32(0)));
        vm.expectRevert(IRiparReputationRelay.UnknownDevice.selector);
        relay.attestDenial(agentId, requestHash, bytes32(0), px, py, r, s);
        (r, s) = p256Sign(newPk, relay.denyDigest(agentId, requestHash, bytes32(0)));
        relay.attestDenial(agentId, requestHash, bytes32(0), nx, ny, r, s);
        assertTrue(relay.denialAttested(newKeyId, requestHash));
    }

    function test_PERIPHERY3_bindReplay_afterRotation_KeyTaken() public {
        // a mandate that still names the old key: its co-signs execute (the enforcer does not read the registry) but
        // are no longer credited as approvals once the key is retired
        Delegation memory m = _mandate(_tokenTerms(), 3);
        bytes memory data = _transfer(payee, 2e6);
        (bytes memory args, bytes32 digest) = _signCosign(_cosign(m, address(musd), 0, data, 1));
        _redeem(m, args, address(musd), 0, data);

        _bindReplayScenario(0x5EED00000000000000000000000000000000000000000000000000000000C3, makeAddr("attacker"));
        _expectAttestRevert(agent, agentId, digest, IRiparReputationRelay.UnknownDevice.selector);
    }

    function test_INTEGRATION5_bindReplay_afterRotation_KeyTaken() public {
        _bindReplayScenario(0xA11CE, makeAddr("anyone"));
    }

    function test_ATTACKER5_bindReplay_afterRotation_KeyTaken() public {
        _bindReplayScenario(0xC0FFEE, makeAddr("anyone"));
        // the retired key cannot be bound to another owner either, even with fresh consent from both keys
        uint256 otherK1 = 0x0DD0;
        address other = vm.addr(otherK1);
        bytes32 b = registry.bindDigest(other, px, py);
        (bytes32 r, bytes32 s) = p256Sign(DEVICE_P1_PK, b);
        bytes memory sig = _k1Sign(otherK1, b);
        vm.expectRevert(IRiparDeviceRegistry.KeyTaken.selector);
        registry.registerDevice(other, px, py, r, s, sig);
    }

    // ================================================================== PERIPHERY-5 (local mock)
    // v1.1: an agent owner that keeps the relay authorized for its agent made every denial revert ("Self-feedback not
    // allowed" in the ReputationRegistry) and lifted the authorization only inside its own attestApproval. v1.2: the
    // relay pre-checks isAuthorizedOrOwner(relay, agentId); a shielded denial is recorded without giveFeedback
    // (AgentShielded) and bars the agent's approvals (AgentIsShielded).

    function test_PERIPHERY5_shield_localIdentity() public {
        DenialShield shield = new DenialShield();
        uint256 shielded = abi.decode(
            shield.exec(
                address(identity),
                abi.encodeCall(
                    IERC8004Identity.register, ("ipfs://shielded-agent", new IERC8004Identity.MetadataEntry[](0))
                )
            ),
            (uint256)
        );
        bytes memory up = abi.encodeCall(IntegrationIdentityStub.setAuthorized, (shielded, address(relay), true));
        bytes memory lift = abi.encodeCall(IntegrationIdentityStub.setAuthorized, (shielded, address(relay), false));
        shield.exec(address(identity), up);
        assertTrue(identity.isAuthorizedOrOwner(address(relay), shielded), "the identity says the relay is authorized");

        // genuine approvals: the user's mandate to the shield (the agent's smart account), co-signed by the device
        Delegation memory m = _mandateFor(address(shield), _tokenTerms(), 55);
        bytes32[2] memory digests;
        for (uint256 i; i < 2; ++i) {
            bytes memory data = _transfer(payee, 1e6 + i);
            bytes memory args;
            (args, digests[i]) = _signCosign(_cosignFor(m, address(shield), address(musd), 0, data, i + 1));
            _redeemAs(address(shield), m, args, address(musd), 0, data);
        }
        uint256 before = reputation.feedbackCount();

        // before any denial the shield trick still collects approvals (v1.2 bars them only once a denial landed)
        shield.attestShielded(address(identity), lift, up, IRiparReputationRelay(address(relay)), shielded, digests[0]);
        assertEq(reputation.feedbackCount(), before + 1);
        assertTrue(identity.isAuthorizedOrOwner(address(relay), shielded), "shield back up");

        // the registered device denies the agent while the shield is up: recorded, not reverted, no feedback call
        bytes32 requestHash = keccak256("a request the user denied");
        vm.expectEmit(true, true, false, true, address(relay));
        emit Verdict(shielded, keyId, requestHash, false);
        vm.expectEmit(true, true, false, true, address(relay));
        emit AgentShielded(shielded, keyId, requestHash);
        _denyAs(DEVICE_P1_PK, shielded, requestHash);
        assertTrue(relay.denialAttested(keyId, requestHash));
        assertEq(relay.shieldedDenials(shielded), 1);
        assertEq(reputation.feedbackCount(), before + 1, "no feedback call for the shielded denial");

        // the agent can no longer collect approvals, shield lifted or not
        vm.expectRevert(IRiparReputationRelay.AgentIsShielded.selector);
        shield.attestShielded(address(identity), lift, up, IRiparReputationRelay(address(relay)), shielded, digests[1]);
        vm.expectRevert(IRiparReputationRelay.AgentIsShielded.selector);
        vm.prank(address(shield));
        relay.attestApproval(shielded, digests[1]);
        assertFalse(relay.approvalAttested(digests[1]));
        assertEq(reputation.feedbackCount(), before + 1);
    }
}

/// @notice OZ P256 Solidity fallback (no code at 0x0100, like a local EVM).
contract PeripheryRegressionTest is PeripheryRegressionBase {
    function setUp() public override {
        assertEq(P256_PRECOMPILE.code.length, 0, "no precompile in the local EVM");
        super.setUp();
    }
}

/// @notice P256VERIFY precompile mock at 0x0100 (like Monad), etched before the fixture pairs the device.
contract PeripheryRegressionPrecompileTest is PeripheryRegressionBase {
    function setUp() public override {
        etchP256Precompile();
        super.setUp();
    }

    function test_precompileIsUsed() public {
        _closeLane(1, uint64(block.number));
        bytes32 d = sentinel.reopenDigest(address(vault), 1);
        (bytes32 r, bytes32 s) = p256Sign(DEVICE_P1_PK, d);
        vm.expectCall(P256_PRECOMPILE, abi.encode(d, r, s, px, py));
        sentinel.reopen(address(vault), 1, r, s);
    }
}

interface ILiveIdentity {
    function approve(address to, uint256 tokenId) external;
    function getApproved(uint256 tokenId) external view returns (address);
    function isAuthorizedOrOwner(address spender, uint256 agentId) external view returns (bool);
}

interface ILiveReputation {
    function getSummary(uint256 agentId, address[] calldata clients, string calldata tag1, string calldata tag2)
        external
        view
        returns (uint64 count, int128 summaryValue, uint8 summaryValueDecimals);
}

/// @notice PERIPHERY-5 against the LIVE Monad-testnet ERC-8004 registries and the CANONICAL DelegationManager, on a
///         read-only fork (the Ripar contracts are deployed locally on the fork; nothing is broadcast). Skipped unless
///         MONAD_TESTNET_RPC_URL is set:
///         MONAD_TESTNET_RPC_URL=https://testnet-rpc.monad.xyz forge test --mc PeripheryRegressionForkTest
contract PeripheryRegressionForkTest is IntegrationBase {
    event AgentShielded(uint256 indexed agentId, bytes32 indexed keyId, bytes32 requestHash);

    address internal constant CANONICAL_DM = 0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3;
    address internal constant LIVE_IDENTITY = 0x8004A818BFB912233c491871b3d84c89A494BD9e;
    address internal constant LIVE_REPUTATION = 0x8004B663056A597Dffe9eCcC1965A193B7388713;

    RiparReputationRelay internal liveRelay;

    function setUp() public override {
        string memory rpc = vm.envOr("MONAD_TESTNET_RPC_URL", string(""));
        if (bytes(rpc).length == 0) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(rpc);
        assertEq(block.chainid, 10_143);
        super.setUp();
        liveRelay = new RiparReputationRelay(
            IERC8004Reputation(LIVE_REPUTATION),
            IERC8004Identity(LIVE_IDENTITY),
            IPulseCosignEnforcer(address(enforcer)),
            IRiparDeviceRegistry(address(registry)),
            CANONICAL_DM
        );
    }

    function _delegationManager() internal pure override returns (DelegationManager) {
        return DelegationManager(CANONICAL_DM);
    }

    function _summary(uint256 id, string memory tag2) internal view returns (uint64 count) {
        address[] memory clients = new address[](1);
        clients[0] = address(liveRelay);
        (count,,) = ILiveReputation(LIVE_REPUTATION).getSummary(id, clients, "ripar", tag2);
    }

    function test_fork_PERIPHERY5_shield_liveRegistries() public {
        DenialShield shield = new DenialShield();
        uint256 shielded = abi.decode(
            shield.exec(
                LIVE_IDENTITY,
                abi.encodeCall(
                    IERC8004Identity.register, ("ipfs://shielded-agent", new IERC8004Identity.MetadataEntry[](0))
                )
            ),
            (uint256)
        );
        bytes memory up = abi.encodeCall(ILiveIdentity.approve, (address(liveRelay), shielded));
        bytes memory lift = abi.encodeCall(ILiveIdentity.approve, (address(0), shielded));
        shield.exec(LIVE_IDENTITY, up);
        assertTrue(ILiveIdentity(LIVE_IDENTITY).isAuthorizedOrOwner(address(liveRelay), shielded));

        // the fixture's registered device denies the shielded agent: v1.1 reverted "Self-feedback not allowed";
        // v1.2 records it without calling the live ReputationRegistry
        bytes32 requestHash = keccak256("a request the user denied");
        (bytes32 r, bytes32 s) = p256Sign(DEVICE_P1_PK, liveRelay.denyDigest(shielded, requestHash, bytes32(0)));
        vm.expectEmit(true, true, false, true, address(liveRelay));
        emit AgentShielded(shielded, keyId, requestHash);
        liveRelay.attestDenial(shielded, requestHash, bytes32(0), px, py, r, s);
        assertEq(liveRelay.shieldedDenials(shielded), 1);
        assertTrue(liveRelay.denialAttested(keyId, requestHash));
        assertEq(_summary(shielded, "denied"), 0, "nothing reached the live registry");

        // a genuine approval: the user's vault (HybridDeleGator on the canonical DelegationManager) delegates to the
        // shield, the device co-signs, the shield redeems through the canonical DelegationManager ...
        Delegation memory m = _mandateFor(address(shield), _tokenTerms(), 77);
        bytes memory data = _transfer(payee, 1e6);
        (bytes memory args, bytes32 digest) = _signCosign(_cosignFor(m, address(shield), address(musd), 0, data, 1));
        _redeemAs(address(shield), m, args, address(musd), 0, data);
        assertTrue(enforcer.consumed(CANONICAL_DM, digest));
        // ... but the agent is shielded: no approval, even with the shield lifted inside the call
        vm.expectRevert(IRiparReputationRelay.AgentIsShielded.selector);
        shield.attestShielded(LIVE_IDENTITY, lift, up, IRiparReputationRelay(address(liveRelay)), shielded, digest);
        assertEq(_summary(shielded, "cosigned"), 0);
        assertEq(ILiveIdentity(LIVE_IDENTITY).getApproved(shielded), address(liveRelay));

        // control: an agent that does not shield itself receives the denial in the live registry
        address plainOwner = makeAddr("plain agent owner");
        vm.prank(plainOwner);
        uint256 plain =
            IERC8004Identity(LIVE_IDENTITY).register("ipfs://plain-agent", new IERC8004Identity.MetadataEntry[](0));
        bytes32 plainRequest = keccak256("another request the user denied");
        (r, s) = p256Sign(DEVICE_P1_PK, liveRelay.denyDigest(plain, plainRequest, bytes32(0)));
        vm.recordLogs();
        liveRelay.attestDenial(plain, plainRequest, bytes32(0), px, py, r, s);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter == address(liveRelay)) {
                assertTrue(logs[i].topics[0] != AgentShielded.selector, "not shielded");
            }
        }
        assertEq(liveRelay.shieldedDenials(plain), 0);
        assertEq(_summary(plain, "denied"), 1, "the live registry counts the denial");
    }
}
