// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { Test } from "forge-std/Test.sol";
import { Vm } from "forge-std/Vm.sol";
import { console2 } from "forge-std/console2.sol";
import { ExecutionLib } from "@erc7579/lib/ExecutionLib.sol";
import { ModeLib } from "@erc7579/lib/ModeLib.sol";
import { Execution } from "@erc7579/interfaces/IERC7579Account.sol";
import { DeleGatorCore } from "@delegation-framework/DeleGatorCore.sol";
import { HybridDeleGator } from "@delegation-framework/HybridDeleGator.sol";
import { DelegationManager } from "@delegation-framework/DelegationManager.sol";
import { IDelegationManager } from "@delegation-framework/interfaces/IDelegationManager.sol";
import { Delegation, Caveat, ModeCode, ModePayload } from "@delegation-framework/utils/Types.sol";
import { CALLTYPE_SINGLE, EXECTYPE_TRY, MODE_DEFAULT } from "@delegation-framework/utils/Constants.sol";

import { MockUSD } from "../src/MockUSD.sol";
import { PulseCosignEnforcer } from "../src/PulseCosignEnforcer.sol";
import { RiparSentinel } from "../src/RiparSentinel.sol";
import { RiparReputationRelay } from "../src/RiparReputationRelay.sol";
import { IPulseCosignEnforcer } from "../src/interfaces/IPulseCosignEnforcer.sol";
import { IRiparSentinel } from "../src/interfaces/IRiparSentinel.sol";
import { IRiparDeviceRegistry } from "../src/interfaces/IRiparDeviceRegistry.sol";
import { IRiparReputationRelay } from "../src/interfaces/IRiparReputationRelay.sol";
import { IERC8004Identity } from "../src/interfaces/external/IERC8004.sol";
import { IntegrationBase } from "./utils/integration/IntegrationBase.sol";
import { IntegrationReputationStub, MonadP256GasStub } from "./utils/integration/IntegrationMocks.sol";
import { Deploy } from "../script/Deploy.s.sol";
import { DeployConfig } from "../script/DeployConfig.sol";

/// @notice End-to-end behaviour with the REAL MetaMask delegation framework v1.3.0: an agent EOA redeems a K1-signed
///         mandate of a HybridDeleGator vault through the DelegationManager; the Pulse co-signature travels in the
///         (unsigned) caveat args. OpenZeppelin P256 runs its Solidity fallback here (no code at 0x0100).
///         SPEC v1.2 (section "v1.2" below, and updated expectations above): a co-sign nonce is single-use per
///         (DelegationManager, mandate); only a co-sign the AUTO path could meter under the mandate, with a non-zero
///         amount, whitelists its payee; the relay credits an approval only while the co-signing key is registered to
///         the vault's owner(), and records denials of a shielded agent without feedback; the sentinel requires the
///         CRE workflow owner, refuses future asOfBlocks and reopens only a closed lane; rotated device keys retire.
contract IntegrationTest is IntegrationBase {
    uint256 internal constant SALT = 1;

    bytes internal mandateAbi; // abi.encode(the default epoch-0 mUSD mandate vault -> agent)
    bytes32 internal mandateHash;

    function setUp() public virtual override {
        super.setUp();
        Delegation memory d = _mandate(_tokenTerms(), SALT);
        mandateAbi = abi.encode(d);
        mandateHash = _hash(d);
    }

    /// @dev The default mandate (kept ABI-encoded: the compiler cannot copy Caveat[] with bytes into storage).
    function _m() internal view returns (Delegation memory) {
        return abi.decode(mandateAbi, (Delegation));
    }

    function _precompileExpected() internal pure virtual returns (bool) {
        return false;
    }

    /// @dev HUMAN co-sign of an mUSD transfer to `to` under `d` (nonce `nonce`); returns the approval digest.
    function _humanTransfer(Delegation memory d, address to, uint256 amount, uint256 nonce)
        internal
        returns (bytes32 digest)
    {
        bytes memory data = _transfer(to, amount);
        bytes memory args;
        (args, digest) = _signCosign(_cosign(d, address(musd), 0, data, nonce));
        _redeem(d, args, address(musd), 0, data);
    }

    /// @dev HUMAN co-sign of any single call under `d` (nonce `nonce`), redeemed by the agent; returns the digest.
    function _humanCall(Delegation memory d, address target, uint256 value, bytes memory data, uint256 nonce)
        internal
        returns (bytes32 digest)
    {
        bytes memory args;
        (args, digest) = _signCosign(_cosign(d, target, value, data, nonce));
        _redeem(d, args, target, value, data);
    }

    /// @dev The same caveat args with the malleable high-s twin of the signature.
    function _highSArgs(bytes memory args) internal pure returns (bytes memory) {
        (uint256 n, uint64 e, bytes32 ph, bytes32 r, bytes32 s) =
            abi.decode(args, (uint256, uint64, bytes32, bytes32, bytes32));
        return abi.encode(n, e, ph, r, p256HighS(s));
    }

    /// @dev The fixture's DelegationManager: every enforcer record of a real redemption is keyed by it, and it is the
    ///      one the relay credits.
    function _dm() internal view returns (address) {
        return address(delegationManager);
    }

    /// @dev enforcer.autoBudget of mandate `d` (its Pulse caveat is caveat 0) under the fixture's DelegationManager.
    function _assertBudget(Delegation memory d, uint256 spent, uint256 remaining, uint256 start, uint256 end)
        internal
        view
    {
        (uint256 s, uint256 r, uint64 ps, uint64 pe) = enforcer.autoBudget(_dm(), _hash(d), d.caveats[0].terms);
        assertEq(s, spent, "autoBudget.spent");
        assertEq(r, remaining, "autoBudget.remaining");
        assertEq(ps, start, "autoBudget.periodStart");
        assertEq(pe, end, "autoBudget.periodEnd");
    }

    /// @dev Number of PayeeApproved events the enforcer emitted in `logs`.
    function _payeeApprovedCount(Vm.Log[] memory logs) internal view returns (uint256 n) {
        for (uint256 i; i < logs.length; ++i) {
            if (
                logs[i].emitter == address(enforcer) && logs[i].topics.length != 0
                    && logs[i].topics[0] == IPulseCosignEnforcer.PayeeApproved.selector
            ) {
                ++n;
            }
        }
    }

    // ================================================================== environment

    function test_p256Path() public view {
        assertEq(P256_PRECOMPILE.code.length > 0, _precompileExpected());
    }

    function test_setUp_pairingAndWiring() public view {
        Delegation memory mandate = _m();
        (bytes32 x, bytes32 y, address owner) = registry.keyOf(keyId);
        assertEq(x, px);
        assertEq(y, py);
        assertEq(owner, k1);
        assertEq(registry.keyIdOf(k1), keyId);
        assertEq(vault.owner(), k1, "the device K1 owns the vault");
        assertTrue(sentinel.laneOpen(address(vault)));
        assertEq(sentinel.expectedWorkflowOwner(), workflowOwner, "v1.2: the sentinel requires the CRE workflow owner");
        assertFalse(registry.isRetired(keyId));
        assertEq(address(relay.enforcer()), address(enforcer));
        assertEq(relay.delegationManager(), _dm(), "the relay credits this DelegationManager's redemptions only");
        assertEq(enforcer.getTermsInfo(mandate.caveats[0].terms).px, px);
        assertEq(mandate.caveats[0].terms.length, 288);
        assertEq(mandateHash, delegationManager.getDelegationHash(mandate));
    }

    // ================================================================== AUTO / HUMAN basics

    function test_auto_newPayee_revertsHumanRequired() public {
        Delegation memory mandate = _m();
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(mandate, payee, 10e6);
        assertEq(musd.balanceOf(payee), 0);
    }

    function test_human_cosign_transfers_and_records() public {
        Delegation memory mandate = _m();
        uint256 amount = 100e6; // above both AUTO caps: a human may approve anything
        bytes memory data = _transfer(payee, amount);
        Cosign memory c = _cosign(mandate, address(musd), 0, data, 1);
        (bytes memory args, bytes32 digest) = _signCosign(c);

        vm.expectEmit(true, true, true, true, address(enforcer));
        emit PayeeApproved(_dm(), mandateHash, payee);
        vm.expectEmit(true, true, true, true, address(enforcer));
        emit HumanCosigned(mandateHash, address(vault), agent, _dm(), payee, amount, keyId, digest, c.presenceHash);
        _redeem(mandate, args, address(musd), 0, data);

        assertEq(musd.balanceOf(payee), amount);
        assertEq(musd.balanceOf(address(vault)), VAULT_MUSD - amount);
        // the payee is known for this mandate only (v1.1), not for another mandate of the same vault
        assertTrue(enforcer.isKnownPayee(_dm(), mandateHash, payee));
        assertFalse(enforcer.isKnownPayee(_dm(), _hash(_mandate(_tokenTerms(), SALT + 1)), payee));
        // the record and the replay protection are keyed by (DelegationManager, digest)
        assertTrue(enforcer.consumed(_dm(), digest));
        assertFalse(enforcer.consumed(agent, digest));
        assertFalse(enforcer.consumed(address(this), digest));
        // v1.2: the co-sign nonce is used for this (DelegationManager, mandate) only
        assertTrue(enforcer.nonceUsed(_dm(), mandateHash, 1));
        assertFalse(enforcer.nonceUsed(_dm(), mandateHash, 2));
        assertFalse(enforcer.nonceUsed(_dm(), _hash(_mandate(_tokenTerms(), SALT + 1)), 1));
        assertFalse(enforcer.nonceUsed(agent, mandateHash, 1));
        IPulseCosignEnforcer.Approval memory a = enforcer.approvalOf(_dm(), digest);
        assertEq(a.keyId, keyId);
        assertEq(a.delegationHash, mandateHash);
        assertEq(a.delegator, address(vault));
        assertEq(a.redeemer, agent);
        assertEq(a.payee, payee);
        assertEq(a.timestamp, uint64(block.timestamp));
        // HUMAN spends do not count toward the AUTO period
        (uint256 spent, uint64 start) = enforcer.periodSpent(_dm(), mandateHash);
        assertEq(spent, 0);
        assertEq(start, 0);
        _assertBudget(mandate, 0, PERIOD_CAP, 0, 0);
    }

    function test_human_replay_reverts() public {
        Delegation memory mandate = _m();
        bytes memory data = _transfer(payee, 30e6);
        (bytes memory args,) = _signCosign(_cosign(mandate, address(musd), 0, data, 1));
        _redeem(mandate, args, address(musd), 0, data);

        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
        _redeem(mandate, args, address(musd), 0, data);
        assertEq(musd.balanceOf(payee), 30e6);
    }

    function test_auto_knownPayee_withinCaps() public {
        Delegation memory mandate = _m();
        _humanTransfer(mandate, payee, 1e6, 1);

        vm.expectEmit(true, true, true, true, address(enforcer));
        emit AutoSpend(mandateHash, address(vault), agent, _dm(), payee, 20e6, 20e6);
        _autoTransfer(mandate, payee, 20e6);
        assertEq(musd.balanceOf(payee), 21e6);

        (uint256 spent, uint64 start) = enforcer.periodSpent(_dm(), mandateHash);
        assertEq(spent, 20e6);
        assertEq(start, uint64(block.timestamp));
        _assertBudget(mandate, 20e6, PERIOD_CAP - 20e6, T0, T0 + PERIOD);

        // another payee is still unknown
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(mandate, payee2, 1e6);
    }

    function test_auto_perTxCap() public {
        Delegation memory mandate = _m();
        _humanTransfer(mandate, payee, 1e6, 1);

        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(mandate, payee, PER_TX + 1);

        _autoTransfer(mandate, payee, PER_TX);
        assertEq(musd.balanceOf(payee), 1e6 + PER_TX);
    }

    function test_auto_periodCap_then_nextDay() public {
        Delegation memory mandate = _m();
        _humanTransfer(mandate, payee, 1e6, 1);

        _autoTransfer(mandate, payee, 25e6);
        _autoTransfer(mandate, payee, 20e6);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(mandate, payee, 6e6); // 51 > 50
        _autoTransfer(mandate, payee, 5e6); // exactly 50
        _assertBudget(mandate, 50e6, 0, T0, T0 + PERIOD);

        vm.warp(T0 + PERIOD - 1);
        _assertBudget(mandate, 50e6, 0, T0, T0 + PERIOD);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(mandate, payee, 1);

        // the budget after the rollover: the stored accounting is lazy, autoBudget applies the rollover
        vm.warp(T0 + PERIOD);
        (uint256 spent, uint64 start) = enforcer.periodSpent(_dm(), mandateHash);
        assertEq(spent, 50e6, "periodSpent: still the old period");
        assertEq(start, T0);
        _assertBudget(mandate, 0, PERIOD_CAP, T0 + PERIOD, T0 + 2 * PERIOD);

        vm.expectEmit(true, true, true, true, address(enforcer));
        emit AutoSpend(mandateHash, address(vault), agent, _dm(), payee, 25e6, 25e6);
        _autoTransfer(mandate, payee, 25e6);
        (spent, start) = enforcer.periodSpent(_dm(), mandateHash);
        assertEq(spent, 25e6);
        assertEq(start, T0 + PERIOD);
        _assertBudget(mandate, 25e6, 25e6, T0 + PERIOD, T0 + 2 * PERIOD);

        // the HUMAN path is never capped by the period, and does not use the AUTO budget
        _humanTransfer(mandate, payee, 500e6, 2);
        assertEq(musd.balanceOf(payee), 1e6 + 50e6 + 25e6 + 500e6);
        _assertBudget(mandate, 25e6, 25e6, T0 + PERIOD, T0 + 2 * PERIOD);
    }

    /// @dev SPEC v1.1 #5: autoBudget applies the aligned rollover (several periods later) exactly as the next AUTO
    ///      spend does, while periodSpent keeps the lazily stored values.
    function test_autoBudget_afterRollover_matchesTheHook() public {
        Delegation memory mandate = _m();
        _humanTransfer(mandate, payee, 1e6, 1);
        _assertBudget(mandate, 0, PERIOD_CAP, 0, 0); // nothing AUTO-spent yet

        uint256 start = T0 + 5 hours;
        vm.warp(start);
        _autoTransfer(mandate, payee, 20e6); // the first AUTO spend opens the window
        _assertBudget(mandate, 20e6, PERIOD_CAP - 20e6, start, start + PERIOD);

        // three periods and two hours later: the current window is aligned to the first one
        vm.warp(start + 3 * PERIOD + 2 hours);
        (uint256 rawSpent, uint64 rawStart) = enforcer.periodSpent(_dm(), mandateHash);
        assertEq(rawSpent, 20e6, "periodSpent is lazy");
        assertEq(rawStart, start);
        _assertBudget(mandate, 0, PERIOD_CAP, start + 3 * PERIOD, start + 4 * PERIOD);

        // the hook agrees with the view: exactly `remaining` passes in this window, one more base unit does not
        _autoTransfer(mandate, payee, 25e6);
        _assertBudget(mandate, 25e6, 25e6, start + 3 * PERIOD, start + 4 * PERIOD);
        _autoTransfer(mandate, payee, 25e6);
        _assertBudget(mandate, 50e6, 0, start + 3 * PERIOD, start + 4 * PERIOD);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(mandate, payee, 1);
        (rawSpent, rawStart) = enforcer.periodSpent(_dm(), mandateHash);
        assertEq(rawSpent, 50e6);
        assertEq(rawStart, start + 3 * PERIOD);

        // per (DelegationManager, mandate): another mandate, and another manager, have their own (untouched) budget
        _assertBudget(_mandate(_tokenTerms(), SALT + 1), 0, PERIOD_CAP, 0, 0);
        (uint256 otherSpent, uint256 otherRemaining, uint64 otherStart, uint64 otherEnd) =
            enforcer.autoBudget(relayer, mandateHash, mandate.caveats[0].terms);
        assertEq(otherSpent, 0);
        assertEq(otherRemaining, PERIOD_CAP);
        assertEq(otherStart, 0);
        assertEq(otherEnd, 0);
        // the terms are validated like the hook's
        vm.expectRevert(IPulseCosignEnforcer.InvalidTerms.selector);
        enforcer.autoBudget(_dm(), mandateHash, hex"00");

        // a lifetime cap (period 0): the window never ends and the budget never comes back
        IPulseCosignEnforcer.PulseTerms memory t = _tokenTerms();
        t.period = 0;
        Delegation memory lifetime = _mandate(t, SALT + 2);
        _humanTransfer(lifetime, payee, 1e6, 2);
        uint256 opened = block.timestamp;
        _autoTransfer(lifetime, payee, 10e6);
        vm.warp(block.timestamp + 30 * PERIOD);
        _assertBudget(lifetime, 10e6, PERIOD_CAP - 10e6, opened, 0);
    }

    /// @dev approve is never AUTO, and (v1.1) a co-signed approve does not make the spender an AUTO payee.
    function test_auto_approve_neverAuto_human_approve_doesNotWhitelistSpender() public {
        Delegation memory mandate = _m();
        _humanTransfer(mandate, payee, 1e6, 1); // payee known
        // not even to a known payee, within every cap
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _redeem(mandate, "", address(musd), 0, abi.encodeWithSelector(bytes4(0x095ea7b3), payee, 1));

        bytes memory approveData = abi.encodeWithSelector(bytes4(0x095ea7b3), payee2, 5e6);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _redeem(mandate, "", address(musd), 0, approveData);

        Cosign memory c = _cosign(mandate, address(musd), 0, approveData, 2);
        (bytes memory args, bytes32 digest) = _signCosign(c);
        vm.recordLogs();
        vm.expectEmit(true, true, true, true, address(enforcer));
        emit HumanCosigned(mandateHash, address(vault), agent, _dm(), payee2, 5e6, keyId, digest, c.presenceHash);
        _redeem(mandate, args, address(musd), 0, approveData);
        assertEq(_payeeApprovedCount(vm.getRecordedLogs()), 0, "an approve co-sign whitelists nobody");
        assertEq(musd.allowance(address(vault), payee2), 5e6);
        assertEq(enforcer.approvalOf(_dm(), digest).payee, payee2, "the record keeps the decoded spender");
        assertFalse(enforcer.isKnownPayee(_dm(), mandateHash, payee2));

        // so the spender is still a new payee for AUTO
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(mandate, payee2, 1e6);
    }

    /// @dev transferFrom is never AUTO, and (v1.1) a co-signed transferFrom does not make its recipient an AUTO payee.
    function test_human_transferFrom_doesNotWhitelistRecipient() public {
        Delegation memory mandate = _m();
        address holder = makeAddr("holder");
        musd.faucet(holder, 10e6);
        vm.prank(holder);
        musd.approve(address(vault), 10e6);
        bytes memory data = abi.encodeWithSelector(bytes4(0x23b872dd), holder, payee2, 10e6);

        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _redeem(mandate, "", address(musd), 0, data);

        Cosign memory c = _cosign(mandate, address(musd), 0, data, 1);
        (bytes memory args, bytes32 digest) = _signCosign(c);
        vm.recordLogs();
        vm.expectEmit(true, true, true, true, address(enforcer));
        emit HumanCosigned(mandateHash, address(vault), agent, _dm(), payee2, 10e6, keyId, digest, c.presenceHash);
        _redeem(mandate, args, address(musd), 0, data);
        assertEq(_payeeApprovedCount(vm.getRecordedLogs()), 0, "a transferFrom co-sign whitelists nobody");
        assertEq(musd.balanceOf(payee2), 10e6);
        assertEq(musd.balanceOf(holder), 0);
        assertEq(enforcer.approvalOf(_dm(), digest).payee, payee2);
        assertFalse(enforcer.isKnownPayee(_dm(), mandateHash, payee2));

        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(mandate, payee2, 1e6);
        // a co-signed transfer to the same address does whitelist it
        _humanTransfer(mandate, payee2, 1e6, 2);
        assertTrue(enforcer.isKnownPayee(_dm(), mandateHash, payee2));
        _autoTransfer(mandate, payee2, 1e6);
        assertEq(musd.balanceOf(payee2), 12e6);
    }

    // ================================================================== what the co-signature binds

    function test_cosign_bindsCallDelegationRedeemerAndExpiry() public {
        Delegation memory mandate = _m();
        bytes memory data = _transfer(payee, 30e6);
        (bytes memory args,) = _signCosign(_cosign(mandate, address(musd), 0, data, 1));

        // another amount
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _redeem(mandate, args, address(musd), 0, _transfer(payee, 31e6));
        // another payee
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _redeem(mandate, args, address(musd), 0, _transfer(payee2, 30e6));
        // another mandate of the same vault
        Delegation memory other = _mandate(_tokenTerms(), SALT + 1);
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _redeem(other, args, address(musd), 0, data);

        // a co-sign that names another redeemer (a mandate any delegate may redeem)
        Delegation memory anyone = _mandateFor(address(0xa11), _tokenTerms(), SALT + 2);
        (bytes memory argsForAgent,) = _signCosign(_cosignFor(anyone, agent, address(musd), 0, data, 3));
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _redeemAs(relayer, anyone, argsForAgent, address(musd), 0, data);

        // the malleable high-s twin of a valid signature
        (uint256 n, uint64 e, bytes32 ph, bytes32 r, bytes32 s) =
            abi.decode(args, (uint256, uint64, bytes32, bytes32, bytes32));
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _redeem(mandate, abi.encode(n, e, ph, r, p256HighS(s)), address(musd), 0, data);

        // expired
        vm.warp(e + 1);
        vm.expectRevert(IPulseCosignEnforcer.CosignExpired.selector);
        _redeem(mandate, args, address(musd), 0, data);
        vm.warp(e);
        _redeem(mandate, args, address(musd), 0, data); // valid up to and including `expiry`
        _redeemAs(agent, anyone, argsForAgent, address(musd), 0, data); // the named redeemer can use its own
        assertEq(musd.balanceOf(payee), 60e6);
    }

    function test_args_areUnsigned_but_terms_areSigned() public {
        Delegation memory mandate = _m();
        // the same K1 signature serves the AUTO path (empty args) and the HUMAN path (160-byte args)
        _humanTransfer(mandate, payee, 1e6, 1);
        _autoTransfer(mandate, payee, 1e6);

        // raising a cap after K1 signed breaks the vault's ERC-1271 check
        IPulseCosignEnforcer.PulseTerms memory t = _tokenTerms();
        t.perTxAutoCap = 1_000e6;
        Delegation memory forged = _withArgs(mandate, "");
        forged.caveats[0].terms = abi.encode(t);
        vm.expectRevert(IDelegationManager.InvalidERC1271Signature.selector);
        _autoTransfer(forged, payee, 100e6);

        // malformed args: neither empty nor 160 bytes
        vm.expectRevert(IPulseCosignEnforcer.InvalidArgs.selector);
        _redeem(mandate, hex"01", address(musd), 0, _transfer(payee, 1e6));
    }

    function test_onlyTheDelegate_canRedeem() public {
        Delegation memory mandate = _m();
        _humanTransfer(mandate, payee, 1e6, 1);
        vm.expectRevert(IDelegationManager.InvalidDelegate.selector);
        _redeemAs(relayer, mandate, "", address(musd), 0, _transfer(payee, 1e6));
    }

    function test_onlySingleDefaultMode() public {
        Delegation memory mandate = _m();
        _humanTransfer(mandate, payee, 1e6, 1);
        Delegation[] memory chain = new Delegation[](1);
        chain[0] = mandate;

        Execution[] memory batch = new Execution[](1);
        batch[0] = Execution({ target: address(musd), value: 0, callData: _transfer(payee, 1e6) });
        vm.expectRevert("CaveatEnforcer:invalid-call-type");
        _redeemChain(agent, chain, ModeLib.encodeSimpleBatch(), ExecutionLib.encodeBatch(batch));

        ModeCode tryMode = ModeLib.encode(CALLTYPE_SINGLE, EXECTYPE_TRY, MODE_DEFAULT, ModePayload.wrap(0x00));
        vm.expectRevert("CaveatEnforcer:invalid-execution-type");
        _redeemChain(agent, chain, tryMode, ExecutionLib.encodeSingle(address(musd), 0, _transfer(payee, 1e6)));
    }

    // ================================================================== sentinel lane

    function test_sentinel_close_blocksAuto_humanStillWorks_reopenRestores() public {
        Delegation memory mandate = _m();
        _humanTransfer(mandate, payee, 1e6, 1);
        _autoTransfer(mandate, payee, 1e6);

        // CRE closes the lane through the forwarder
        vm.expectEmit(true, true, true, true, address(sentinel));
        emit LaneChanged(address(vault), false, 3, B0);
        _closeLane(3, B0);
        assertFalse(sentinel.laneOpen(address(vault)));

        vm.expectRevert(IPulseCosignEnforcer.LaneClosed.selector);
        _autoTransfer(mandate, payee, 1e6);
        // the HUMAN path ignores the sentinel
        _humanTransfer(mandate, payee, 2e6, 2);
        assertEq(musd.balanceOf(payee), 4e6);

        // only the forwarder may close
        vm.expectRevert(IRiparSentinel.NotForwarder.selector);
        sentinel.onReport("", abi.encode(address(vault), false, uint8(1), B0));

        // the device reopens (P1 of the key the registry binds to vault.owner() = K1)
        vm.roll(B0 + 10);
        vm.expectEmit(true, true, true, true, address(sentinel));
        emit LaneChanged(address(vault), true, 0, B0 + 10);
        _reopen(1);
        assertTrue(sentinel.laneOpen(address(vault)));
        _autoTransfer(mandate, payee, 1e6);

        // v1.2: a reopen needs a closed lane (checked before the nonce and the signature: nothing is burnt)
        (bytes32 r2, bytes32 s2) = _reopenSig(2);
        vm.expectRevert(IRiparSentinel.LaneNotClosed.selector);
        sentinel.reopen(address(vault), 2, r2, s2);
        assertEq(sentinel.lastReopenNonce(address(vault)), 1, "the refused reopen burnt no nonce");
        assertEq(sentinel.lastReopenBlock(address(vault)), B0 + 10);
        // v1.2: only the expected CRE workflow owner can close, and never as of a future block
        address stranger = makeAddr("stranger workflow owner");
        vm.expectRevert(IRiparSentinel.BadWorkflowOwner.selector);
        _reportAs(stranger, address(vault), 4, B0 + 10);
        vm.expectRevert(IRiparSentinel.BadReport.selector);
        _closeLane(4, B0 + 11);
        assertTrue(sentinel.laneOpen(address(vault)));

        // a delayed close report older than the reopen is ignored
        vm.expectEmit(true, true, true, true, address(sentinel));
        emit ReportIgnored(address(vault), 4, B0 + 9);
        _closeLane(4, B0 + 9);
        _autoTransfer(mandate, payee, 1e6);

        // a fresh one closes again; the reopen nonce must increase
        _closeLane(5, B0 + 10);
        vm.expectRevert(IPulseCosignEnforcer.LaneClosed.selector);
        _autoTransfer(mandate, payee, 1e6);
        (bytes32 r, bytes32 s) = _reopenSig(1);
        vm.expectRevert(IRiparSentinel.NonceNotIncreasing.selector);
        sentinel.reopen(address(vault), 1, r, s);
        sentinel.reopen(address(vault), 2, r2, s2); // the reopen refused while the lane was open works now
        _autoTransfer(mandate, payee, 1e6);
        assertEq(musd.balanceOf(payee), 7e6);
    }

    // ================================================================== ERC-8004 reputation relay

    function test_relay_attestApproval_and_attestDenial() public {
        Delegation memory mandate = _m();
        bytes32 digest = _humanTransfer(mandate, payee, 10e6, 1);

        // v1.1: only the redeemer of the co-signed redemption may attest it (not a relayer, not the agent's owner)
        vm.expectRevert(IRiparReputationRelay.NotRedeemer.selector);
        vm.prank(relayer);
        relay.attestApproval(agentId, digest);
        vm.expectRevert(IRiparReputationRelay.NotRedeemer.selector);
        vm.prank(agentOwner);
        relay.attestApproval(agentId, digest);

        // +1 for the agent whose authorized EOA redeemed the co-signed delegation, filed by that EOA
        vm.expectEmit(true, true, true, true, address(relay));
        emit Verdict(agentId, keyId, digest, true);
        vm.prank(agent);
        relay.attestApproval(agentId, digest);
        assertTrue(relay.approvalAttested(digest));
        _checkFeedback(0, 1, "cosigned", digest);

        vm.expectRevert(IRiparReputationRelay.AlreadyAttested.selector);
        vm.prank(agent);
        relay.attestApproval(agentId, digest);

        // not an agent the redeemer acts for
        vm.prank(makeAddr("other agent owner"));
        uint256 otherAgent = identity.register("ipfs://other", new IERC8004Identity.MetadataEntry[](0));
        vm.expectRevert(IRiparReputationRelay.NotAgentRedeemer.selector);
        vm.prank(agent);
        relay.attestApproval(otherAgent, digest);
        // a digest that was never consumed
        vm.expectRevert(IRiparReputationRelay.NotConsumed.selector);
        vm.prank(agent);
        relay.attestApproval(agentId, keccak256("never co-signed"));

        // -1: the user denies the agent's next request (500 mUSD to payee2) on the co-sign review
        Cosign memory denied = _cosign(mandate, address(musd), 0, _transfer(payee2, 500e6), 2);
        denied.presenceHash = bytes32(0);
        bytes32 requestHash = _approvalStruct(denied);
        assertEq(
            requestHash,
            enforcer.approvalStructHash(
                denied.delegationHash,
                denied.delegator,
                denied.redeemer,
                denied.target,
                denied.value,
                keccak256(denied.callData),
                denied.nonce,
                denied.expiry,
                bytes32(0)
            ),
            "requestHash = hashStruct(HumanApproval) with presenceHash 0"
        );
        bytes32 presence = bytes32(0); // a deny's pulse evidence is optional
        bytes32 denyDigest = _digest(
            _domain("RiparReputationRelay", address(relay)),
            keccak256(abi.encode(DENY_TYPEHASH, agentId, requestHash, presence))
        );
        assertEq(denyDigest, relay.denyDigest(agentId, requestHash, presence));
        (bytes32 r, bytes32 s) = p256Sign(DEVICE_P1_PK, denyDigest);

        vm.expectEmit(true, true, true, true, address(relay));
        emit Verdict(agentId, keyId, requestHash, false);
        vm.prank(relayer);
        relay.attestDenial(agentId, requestHash, presence, px, py, r, s);
        assertTrue(relay.denialAttested(keyId, requestHash));
        _checkFeedback(1, -1, "denied", requestHash);

        vm.expectRevert(IRiparReputationRelay.AlreadyAttested.selector);
        relay.attestDenial(agentId, requestHash, presence, px, py, r, s);

        // the denied request never got a co-signature: the agent cannot push it through AUTO either
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(mandate, payee2, 500e6);
    }

    /// @dev SPEC v1.1 #4, end to end: another agent's owner authorizes the victim's redeemer for its own agent and tries
    ///      to take the credit for the victim's co-signed redemption first. Only the redeemer can attest, and it
    ///      chooses the agent that gets the credit.
    function test_relay_frontRunByOtherAgentOwner_fails() public {
        Delegation memory mandate = _m();
        bytes32 digest = _humanTransfer(mandate, payee, 10e6, 1);

        address attacker = makeAddr("other agent owner");
        vm.startPrank(attacker);
        uint256 otherAgent = identity.register("ipfs://other", new IERC8004Identity.MetadataEntry[](0));
        identity.setAuthorized(otherAgent, agent, true); // the victim's redeemer now "acts for" the attacker's agent
        vm.expectRevert(IRiparReputationRelay.NotRedeemer.selector);
        relay.attestApproval(otherAgent, digest);
        vm.stopPrank();
        assertFalse(relay.approvalAttested(digest));

        vm.prank(agent);
        relay.attestApproval(agentId, digest);
        _checkFeedback(0, 1, "cosigned", digest);
        // once, for one agent
        vm.expectRevert(IRiparReputationRelay.AlreadyAttested.selector);
        vm.prank(agent);
        relay.attestApproval(otherAgent, digest);
        assertEq(reputation.feedbackCount(), 1);
    }

    function _checkFeedback(uint256 i, int128 value, string memory tag2, bytes32 feedbackHash) internal view {
        IntegrationReputationStub.Feedback memory f = reputation.feedbackAt(i);
        assertEq(f.client, address(relay));
        assertEq(f.agentId, agentId);
        assertEq(f.value, value);
        assertEq(f.valueDecimals, 0);
        assertEq(f.tag1, "ripar");
        assertEq(f.tag2, tag2);
        assertEq(f.endpoint, "");
        assertEq(f.feedbackURI, "");
        assertEq(f.feedbackHash, feedbackHash);
    }

    // ================================================================== device kill switch

    function test_revoke_killsOneMandate() public {
        Delegation memory mandate = _m();
        _humanTransfer(mandate, payee, 1e6, 1);
        Delegation memory second = _mandate(_tokenTerms(), SALT + 1);

        vm.expectEmit(true, true, true, true, address(enforcer));
        emit Revoked(keyId, mandateHash);
        _revoke(mandateHash);
        assertTrue(enforcer.isRevoked(keyId, mandateHash));

        vm.expectRevert(IPulseCosignEnforcer.DelegationRevoked.selector);
        _autoTransfer(mandate, payee, 1e6);
        bytes memory data = _transfer(payee, 1e6);
        (bytes memory args,) = _signCosign(_cosign(mandate, address(musd), 0, data, 2));
        vm.expectRevert(IPulseCosignEnforcer.DelegationRevoked.selector);
        _redeem(mandate, args, address(musd), 0, data);

        // another mandate of the same vault lives on, with its own payee list (v1.1: known payees are per mandate): the
        // payee the human approved under the revoked mandate needs a human co-sign again
        bytes32 secondHash = _hash(second);
        assertTrue(enforcer.isKnownPayee(_dm(), mandateHash, payee));
        assertFalse(enforcer.isKnownPayee(_dm(), secondHash, payee));
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(second, payee, 1e6);
        _humanTransfer(second, payee, 1e6, 3);
        assertTrue(enforcer.isKnownPayee(_dm(), secondHash, payee));
        _autoTransfer(second, payee, 1e6);
        assertEq(musd.balanceOf(payee), 3e6);

        // a forged revoke fails
        vm.expectRevert(IPulseCosignEnforcer.BadSignature.selector);
        enforcer.revoke(px, py, _hash(second), bytes32(uint256(1)), bytes32(uint256(1)));
    }

    function test_panic_killsEpoch0_epoch1MandateWorks() public {
        Delegation memory mandate = _m();
        _humanTransfer(mandate, payee, 1e6, 1);
        _autoTransfer(mandate, payee, 20e6);

        vm.expectEmit(true, true, true, true, address(enforcer));
        emit Panicked(keyId, 1);
        _panic(1);
        assertEq(enforcer.minEpoch(keyId), 1);

        vm.expectRevert(IPulseCosignEnforcer.StaleEpoch.selector);
        _autoTransfer(mandate, payee, 1e6);
        bytes memory data = _transfer(payee2, 1e6);
        (bytes memory args,) = _signCosign(_cosign(mandate, address(musd), 0, data, 2));
        vm.expectRevert(IPulseCosignEnforcer.StaleEpoch.selector);
        _redeem(mandate, args, address(musd), 0, data);

        // a fresh epoch-1 mandate (the device signs epoch == its panic floor)
        IPulseCosignEnforcer.PulseTerms memory t1 = _tokenTerms();
        t1.epoch = 1;
        Delegation memory fresh = _mandate(t1, SALT + 1);
        bytes32 freshHash = _hash(fresh);
        // v1.1: the fresh mandate starts with an empty payee list, so the old mandate's payee needs the human again
        assertFalse(enforcer.isKnownPayee(_dm(), freshHash, payee));
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(fresh, payee, 1e6);
        _humanTransfer(fresh, payee, 1e6, 3);
        _assertBudget(fresh, 0, PERIOD_CAP, 0, 0);
        vm.expectEmit(true, true, true, true, address(enforcer));
        emit AutoSpend(freshHash, address(vault), agent, _dm(), payee, 25e6, 25e6); // fresh period budget
        _autoTransfer(fresh, payee, 25e6);
        _humanTransfer(fresh, payee2, 1e6, 4);
        assertEq(musd.balanceOf(payee), 1e6 + 20e6 + 1e6 + 25e6);
        assertEq(musd.balanceOf(payee2), 1e6);

        // panics only go up
        (bytes32 r, bytes32 s) = p256Sign(DEVICE_P1_PK, enforcer.panicDigest(1));
        vm.expectRevert(IPulseCosignEnforcer.EpochNotIncreasing.selector);
        enforcer.panic(px, py, 1, r, s);
        _panic(2);
        vm.expectRevert(IPulseCosignEnforcer.StaleEpoch.selector);
        _autoTransfer(fresh, payee, 1e6);
    }

    // ================================================================== native-coin mandate

    function test_nativeMandate_auto_and_human() public {
        Delegation memory native = _mandate(_nativeTerms(), SALT + 7);
        bytes32 nativeHash = _hash(native);

        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoNative(native, payee, 0.5 ether); // new payee

        // HUMAN: 1.5 ether (above the per-tx cap), empty calldata
        Cosign memory c = _cosign(native, payee, 1.5 ether, "", 1);
        (bytes memory args, bytes32 digest) = _signCosign(c);
        vm.expectEmit(true, true, true, true, address(enforcer));
        emit HumanCosigned(nativeHash, address(vault), agent, _dm(), payee, 1.5 ether, keyId, digest, c.presenceHash);
        _redeem(native, args, payee, 1.5 ether, "");
        assertEq(payee.balance, 1.5 ether);
        assertTrue(enforcer.isKnownPayee(_dm(), nativeHash, payee), "a native-send target becomes a known payee");

        vm.expectEmit(true, true, true, true, address(enforcer));
        emit AutoSpend(nativeHash, address(vault), agent, _dm(), payee, 1 ether, 1 ether);
        _autoNative(native, payee, 1 ether);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoNative(native, payee, 1 ether + 1); // per-tx cap
        _autoNative(native, payee, 1 ether); // period: 2 of 2
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoNative(native, payee, 1);
        assertEq(payee.balance, 3.5 ether);
        assertEq(address(vault).balance, VAULT_NATIVE - 3.5 ether);

        // a native mandate never auto-meters an ERC-20 call or a zero-value send
        vm.warp(T0 + PERIOD);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(native, payee, 1e6);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoNative(native, payee, 0);
        _autoNative(native, payee, 0.25 ether);
        assertEq(payee.balance, 3.75 ether);
    }

    // ================================================================== the framework's own controls

    function test_frameworkDisableDelegation_stillWorks() public {
        Delegation memory mandate = _m();
        _humanTransfer(mandate, payee, 1e6, 1);
        _autoTransfer(mandate, payee, 1e6);

        // only the vault itself (here: a K1-signed UserOp through the EntryPoint) can disable its delegation
        vm.expectRevert(IDelegationManager.InvalidDelegator.selector);
        vm.prank(agent);
        delegationManager.disableDelegation(mandate);

        _vaultUserOp(abi.encodeCall(DeleGatorCore.disableDelegation, (mandate)));
        assertTrue(delegationManager.disabledDelegations(mandateHash));

        vm.expectRevert(IDelegationManager.CannotUseADisabledDelegation.selector);
        _autoTransfer(mandate, payee, 1e6);
        bytes memory data = _transfer(payee, 1e6);
        (bytes memory args,) = _signCosign(_cosign(mandate, address(musd), 0, data, 2));
        vm.expectRevert(IDelegationManager.CannotUseADisabledDelegation.selector);
        _redeem(mandate, args, address(musd), 0, data);

        _vaultUserOp(abi.encodeCall(DeleGatorCore.enableDelegation, (mandate)));
        _redeem(mandate, args, address(musd), 0, data); // the unused co-sign still works
        _autoTransfer(mandate, payee, 1e6);
        assertEq(musd.balanceOf(payee), 4e6);
    }

    // ================================================================== re-delegation (agent -> sub-agent)

    function test_redelegation_sharesCaps_and_cosignNamesTheRedeemer() public {
        Delegation memory mandate = _m();
        (address subAgent,) = makeAddrAndKey("sub-agent");
        Delegation memory leaf = Delegation({
            delegate: subAgent,
            delegator: agent, // an EOA: the DelegationManager checks its ECDSA signature
            authority: mandateHash,
            caveats: new Caveat[](0),
            salt: 0,
            signature: ""
        });
        leaf.signature = _k1Sign(agentPk, _digest(delegationManager.getDomainHash(), _hash(leaf)));

        _humanTransfer(mandate, payee, 1e6, 1); // payee known for (DelegationManager, root mandate)
        _autoTransfer(mandate, payee, 25e6); // the agent spends half of the period

        Delegation[] memory chain = new Delegation[](2);
        chain[0] = leaf;
        chain[1] = mandate;
        bytes memory data = _transfer(payee, 25e6);
        vm.expectEmit(true, true, true, true, address(enforcer));
        emit AutoSpend(mandateHash, address(vault), subAgent, _dm(), payee, 25e6, 50e6); // same budget
        _redeemChain(subAgent, chain, singleMode, ExecutionLib.encodeSingle(address(musd), 0, data));
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _redeemChain(subAgent, chain, singleMode, ExecutionLib.encodeSingle(address(musd), 0, _transfer(payee, 1)));

        // a co-sign names the redeemer: the agent's co-sign does not work for the sub-agent
        bytes memory big = _transfer(payee2, 100e6);
        (bytes memory agentArgs,) = _signCosign(_cosign(mandate, address(musd), 0, big, 2));
        chain[1] = _withArgs(mandate, agentArgs);
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _redeemChain(subAgent, chain, singleMode, ExecutionLib.encodeSingle(address(musd), 0, big));

        (bytes memory subArgs, bytes32 digest) = _signCosign(_cosignFor(mandate, subAgent, address(musd), 0, big, 2));
        chain[1] = _withArgs(mandate, subArgs);
        _redeemChain(subAgent, chain, singleMode, ExecutionLib.encodeSingle(address(musd), 0, big));
        assertEq(musd.balanceOf(payee2), 100e6);
        assertEq(enforcer.approvalOf(_dm(), digest).redeemer, subAgent);

        // the approval belongs to the sub-agent: the root delegate cannot attest it, and the sub-agent only for an
        // agent it is authorized for
        vm.expectRevert(IRiparReputationRelay.NotRedeemer.selector);
        vm.prank(agent);
        relay.attestApproval(agentId, digest);
        vm.expectRevert(IRiparReputationRelay.NotAgentRedeemer.selector);
        vm.prank(subAgent);
        relay.attestApproval(agentId, digest);
    }

    // ================================================================== co-sign burning (fixed in v1.1), end to end

    /// @dev SPEC v1.1 #1 (was a known issue in v1): whoever sees the caveat args of a pending HUMAN redemption can
    ///      still call beforeHook directly with them, but that consumes the co-sign only under the caller's own
    ///      address. Burning it for the real DelegationManager is IMPOSSIBLE: through the DelegationManager only the
    ///      delegate can redeem, and the co-sign names the redeemer. The burnt record earns no reputation; the real
    ///      redemption goes through, and only it can be credited.
    function test_directBeforeHook_cannotBurnCosign_norBeCredited() public {
        Delegation memory mandate = _m();
        bytes memory data = _transfer(payee, 30e6);
        Cosign memory c = _cosign(mandate, address(musd), 0, data, 1);
        (bytes memory args, bytes32 digest) = _signCosign(c);
        address griefer = makeAddr("griefer");
        bytes memory execution = ExecutionLib.encodeSingle(address(musd), 0, data);

        // 1. the direct call passes, but only writes the griefer's own state
        vm.prank(griefer);
        enforcer.beforeHook(mandate.caveats[0].terms, args, singleMode, execution, mandateHash, address(vault), agent);
        assertTrue(enforcer.consumed(griefer, digest), "consumed for the caller only");
        assertFalse(enforcer.consumed(_dm(), digest), "not for the real DelegationManager");
        assertEq(enforcer.approvalOf(_dm(), digest).keyId, bytes32(0), "no record under the DelegationManager");
        assertEq(enforcer.approvalOf(griefer, digest).redeemer, agent);
        assertTrue(enforcer.isKnownPayee(griefer, mandateHash, payee));
        assertFalse(enforcer.isKnownPayee(_dm(), mandateHash, payee), "no payee for the real DelegationManager");
        assertEq(musd.balanceOf(payee), 0, "no funds moved");
        // doing it again only hits the griefer's own replay protection
        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
        vm.prank(griefer);
        enforcer.beforeHook(mandate.caveats[0].terms, args, singleMode, execution, mandateHash, address(vault), agent);

        // 2. the relay cannot credit the direct-call record, whoever asks
        vm.expectRevert(IRiparReputationRelay.NotConsumed.selector);
        vm.prank(agent);
        relay.attestApproval(agentId, digest);
        vm.expectRevert(IRiparReputationRelay.NotConsumed.selector);
        vm.prank(griefer);
        relay.attestApproval(agentId, digest);

        // 3. through the real DelegationManager the griefer cannot use the co-sign: the agent's mandate is not its to
        //    redeem (see the next test for a mandate anyone may redeem)
        vm.expectRevert(IDelegationManager.InvalidDelegate.selector);
        _redeemAs(griefer, mandate, args, address(musd), 0, data);

        // 4. the real redemption goes through (no CosignReplayed) and only it can be credited, by the redeemer
        vm.expectEmit(true, true, true, true, address(enforcer));
        emit HumanCosigned(mandateHash, address(vault), agent, _dm(), payee, 30e6, keyId, digest, c.presenceHash);
        _redeem(mandate, args, address(musd), 0, data);
        assertEq(musd.balanceOf(payee), 30e6);
        assertTrue(enforcer.consumed(_dm(), digest));
        assertTrue(enforcer.isKnownPayee(_dm(), mandateHash, payee));
        vm.expectEmit(true, true, true, true, address(relay));
        emit Verdict(agentId, keyId, digest, true);
        vm.prank(agent);
        relay.attestApproval(agentId, digest);
        assertEq(reputation.feedbackCount(), 1);
        // single use for the DelegationManager
        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
        _redeem(mandate, args, address(musd), 0, data);
    }

    /// @dev SPEC v1.1 #1, the other way in: under a mandate ANY delegate may redeem, a griefer can call the real
    ///      DelegationManager with a pending co-sign, but the co-sign names the agent as the redeemer, so the whole
    ///      redemption reverts BadCosign and nothing is consumed; the agent's own redemption then goes through.
    function test_anyDelegateMandate_cosignCannotBeBurntThroughDelegationManager() public {
        Delegation memory open = _mandateFor(address(0xa11), _tokenTerms(), SALT + 2); // ANY_DELEGATE
        bytes memory data = _transfer(payee, 30e6);
        (bytes memory args, bytes32 digest) = _signCosign(_cosignFor(open, agent, address(musd), 0, data, 1));

        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _redeemAs(makeAddr("griefer"), open, args, address(musd), 0, data);
        assertFalse(enforcer.consumed(_dm(), digest), "nothing consumed");

        _redeemAs(agent, open, args, address(musd), 0, data);
        assertEq(musd.balanceOf(payee), 30e6);
        assertEq(enforcer.approvalOf(_dm(), digest).redeemer, agent);
        vm.prank(agent);
        relay.attestApproval(agentId, digest);
        assertTrue(relay.approvalAttested(digest));
    }

    // ================================================================== v1.2 (after the adversarial review)

    /// @dev SPEC v1.2 nonce (PROTOCOL-1), end to end: the device signing the very same request twice (same nonce, a
    ///      fresh presence salt, so another digest) pays once. The nonce is single-use per (DelegationManager, mandate),
    ///      marked only by a co-sign that verified, and free under every other mandate.
    function test_v12_cosignNonce_singleUsePerMandate() public {
        Delegation memory mandate = _m();
        bytes memory data = _transfer(payee, 400e6); // far above the AUTO caps: a human-only payment
        Cosign memory first = _cosign(mandate, address(musd), 0, data, 7);
        Cosign memory again = _cosign(mandate, address(musd), 0, data, 7);
        again.presenceHash = _presence(1_007); // the device's fresh salt16
        (bytes memory args1, bytes32 d1) = _signCosign(first);
        (bytes memory args2, bytes32 d2) = _signCosign(again);
        assertTrue(d1 != d2, "two digests for one request");

        // a refused co-sign (the malleable twin) marks nothing
        bytes memory twin = _highSArgs(args1);
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _redeem(mandate, twin, address(musd), 0, data);
        assertFalse(enforcer.nonceUsed(_dm(), mandateHash, 7));

        _redeem(mandate, args1, address(musd), 0, data);
        assertTrue(enforcer.nonceUsed(_dm(), mandateHash, 7));
        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
        _redeem(mandate, args2, address(musd), 0, data);
        // any other request with nonce 7 under this mandate as well
        bytes memory other = _transfer(payee2, 1e6);
        (bytes memory args3,) = _signCosign(_cosign(mandate, address(musd), 0, other, 7));
        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
        _redeem(mandate, args3, address(musd), 0, other);
        assertEq(musd.balanceOf(payee), 400e6, "paid once");
        assertFalse(enforcer.consumed(_dm(), d2));

        // nonce 7 under another mandate of the same vault is a different nonce
        Delegation memory second = _mandate(_tokenTerms(), SALT + 1);
        _humanTransfer(second, payee2, 1e6, 7);
        assertTrue(enforcer.nonceUsed(_dm(), _hash(second), 7));
        assertEq(musd.balanceOf(payee2), 1e6);
        // the one approval is credited
        vm.prank(agent);
        relay.attestApproval(agentId, d1);
        assertEq(reputation.feedbackCount(), 1);
    }

    /// @dev SPEC v1.2 known-payee predicate (ENF-1, PROTOCOL-2, INTEGRATION-3, ATTACKER-1), end to end: a co-sign
    ///      whitelists its payee only when the AUTO path could meter the call under the mandate (a native send with
    ///      value > 0 under a native mandate; a `transfer` of the mandate's token with value 0) and it moves a non-zero
    ///      amount. The co-signed calls themselves all execute.
    function test_v12_knownPayee_onlyMeterableCallsWithAmount() public {
        Delegation memory mandate = _m(); // the mUSD mandate
        MockUSD otherToken = new MockUSD();
        otherToken.faucet(address(vault), 10e6);

        vm.recordLogs();
        _humanCall(mandate, payee2, 0.1 ether, "", 1); // a native send under the mUSD mandate
        _humanCall(mandate, address(musd), 0, _transfer(payee2, 0), 2); // a 0-amount mUSD transfer
        _humanCall(mandate, address(otherToken), 0, _transfer(payee2, 1e6), 3); // a transfer of another ERC-20
        assertEq(_payeeApprovedCount(vm.getRecordedLogs()), 0, "no whitelisting");
        assertEq(payee2.balance, 0.1 ether);
        assertEq(otherToken.balanceOf(payee2), 1e6);
        assertFalse(enforcer.isKnownPayee(_dm(), mandateHash, payee2));
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(mandate, payee2, 1e6);

        // a transfer of 1 base unit of the metered token whitelists
        vm.expectEmit(true, true, true, true, address(enforcer));
        emit PayeeApproved(_dm(), mandateHash, payee2);
        _humanTransfer(mandate, payee2, 1, 4);
        _autoTransfer(mandate, payee2, PER_TX);
        assertEq(musd.balanceOf(payee2), 1 + PER_TX);

        // a native mandate: an mUSD transfer and a 0-value send whitelist nobody, a 1-wei send does
        Delegation memory native = _mandate(_nativeTerms(), SALT + 7);
        bytes32 nativeHash = _hash(native);
        vm.recordLogs();
        _humanCall(native, address(musd), 0, _transfer(payee, 1e6), 1);
        _humanCall(native, payee, 0, "", 2);
        assertEq(_payeeApprovedCount(vm.getRecordedLogs()), 0, "no whitelisting under the native mandate");
        assertFalse(enforcer.isKnownPayee(_dm(), nativeHash, payee));
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoNative(native, payee, 0.1 ether);
        vm.expectEmit(true, true, true, true, address(enforcer));
        emit PayeeApproved(_dm(), nativeHash, payee);
        _humanCall(native, payee, 1, "", 3);
        _autoNative(native, payee, 0.1 ether);
        assertEq(payee.balance, 0.1 ether + 1);
    }

    /// @dev SPEC v1.2 relay device check, end to end with the real HybridDeleGator: an approval is credited only while
    ///      the co-signing key is registered to the vault's CURRENT owner(). Not while the vault belongs to someone
    ///      without that key, and not after K1 rotated to a new device key (the old key is retired for good).
    function test_v12_relay_creditsOnlyTheVaultOwnersRegisteredDevice() public {
        Delegation memory mandate = _m();
        bytes32 d1 = _humanTransfer(mandate, payee, 1e6, 1);
        bytes32 d2 = _humanTransfer(mandate, payee, 1e6, 2);

        // the vault changes hands (a K1-signed UserOp): the new owner has no registered device
        (address newOwner, uint256 newOwnerPk) = makeAddrAndKey("new vault owner");
        _vaultUserOp(abi.encodeCall(HybridDeleGator.transferOwnership, (newOwner)));
        assertEq(vault.owner(), newOwner);
        vm.expectRevert(IRiparReputationRelay.UnknownDevice.selector);
        vm.prank(agent);
        relay.attestApproval(agentId, d1);
        // ... and back to K1 (signed by the new owner): the device's approvals count again
        _vaultUserOpAs(newOwnerPk, abi.encodeCall(HybridDeleGator.transferOwnership, (k1)));
        assertEq(vault.owner(), k1);
        vm.prank(agent);
        relay.attestApproval(agentId, d1);

        // K1 rotates to a new device key: the old key is retired, so its approvals stop counting
        uint256 newP1 = 0xC0FFEE;
        bytes32 newKeyId = _bindToK1(newP1);
        assertTrue(registry.isRetired(keyId), "the old key is retired");
        assertEq(registry.keyIdOf(k1), newKeyId);
        vm.expectRevert(IRiparReputationRelay.UnknownDevice.selector);
        vm.prank(agent);
        relay.attestApproval(agentId, d2);
        // replaying the old (public) binding cannot bring it back
        bytes32 bindOld = registry.bindDigest(k1, px, py);
        (bytes32 oldR, bytes32 oldS) = p256Sign(DEVICE_P1_PK, bindOld);
        bytes memory oldK1Sig = _k1Sign(DEVICE_K1_PK, bindOld);
        vm.expectRevert(IRiparDeviceRegistry.KeyTaken.selector);
        registry.registerDevice(k1, px, py, oldR, oldS, oldK1Sig);

        // a mandate naming the new key: its co-signs are credited
        bytes32 d3 = _cosignedTransferWithKey(newP1);
        vm.expectEmit(true, true, true, true, address(relay));
        emit Verdict(agentId, newKeyId, d3, true);
        vm.prank(agent);
        relay.attestApproval(agentId, d3);
        assertEq(reputation.feedbackCount(), 2);
    }

    /// @dev Registers the P-256 key of `p1Pk` to K1 (a BindDevice signed by that key and K1): K1's previous key retires.
    function _bindToK1(uint256 p1Pk) internal returns (bytes32) {
        (bytes32 x, bytes32 y) = p256Key(p1Pk);
        bytes32 bind = registry.bindDigest(k1, x, y);
        (bytes32 r, bytes32 s) = p256Sign(p1Pk, bind);
        return registry.registerDevice(k1, x, y, r, s, _k1Sign(DEVICE_K1_PK, bind));
    }

    /// @dev A new mUSD mandate (salt SALT + 1) naming the key of `p1Pk`; that key co-signs a 1 mUSD transfer to `payee`,
    ///      redeemed by the agent. Returns the approval digest.
    function _cosignedTransferWithKey(uint256 p1Pk) internal returns (bytes32 digest) {
        IPulseCosignEnforcer.PulseTerms memory t = _tokenTerms();
        (t.px, t.py) = p256Key(p1Pk);
        Delegation memory fresh = _mandate(t, SALT + 1);
        bytes memory data = _transfer(payee, 1e6);
        Cosign memory c = _cosign(fresh, address(musd), 0, data, 1);
        digest = _approvalDigest(c);
        (bytes32 r, bytes32 s) = p256Sign(p1Pk, digest);
        _redeem(fresh, abi.encode(c.nonce, c.expiry, c.presenceHash, r, s), address(musd), 0, data);
    }

    /// @dev SPEC v1.2 shield (PERIPHERY-5), end to end: an agent owner who makes the relay an operator of its agent (so
    ///      ERC-8004 refuses the relay's feedback as self-feedback) cannot dodge denials. The denial is recorded without
    ///      feedback (Verdict + AgentShielded, shieldedDenials) and the agent collects no approval from then on, even
    ///      after the operator is lifted. Another agent the redeemer acts for is unaffected.
    function test_v12_relay_shieldedAgent() public {
        Delegation memory mandate = _m();
        bytes32 digest = _humanTransfer(mandate, payee, 1e6, 1);
        vm.prank(agentOwner);
        identity.setAuthorized(agentId, address(relay), true);

        bytes32 requestHash = keccak256("a request the user denied");
        (bytes32 r, bytes32 s) = p256Sign(DEVICE_P1_PK, relay.denyDigest(agentId, requestHash, bytes32(0)));
        vm.expectEmit(true, true, true, true, address(relay));
        emit Verdict(agentId, keyId, requestHash, false);
        vm.expectEmit(true, true, true, true, address(relay));
        emit IRiparReputationRelay.AgentShielded(agentId, keyId, requestHash);
        vm.prank(relayer);
        relay.attestDenial(agentId, requestHash, bytes32(0), px, py, r, s);
        assertTrue(relay.denialAttested(keyId, requestHash));
        assertEq(relay.shieldedDenials(agentId), 1);
        assertEq(reputation.feedbackCount(), 0, "no feedback call");

        // approvals: NotRedeemer comes first, then AgentIsShielded (the device check passes: K1's registered key)
        vm.expectRevert(IRiparReputationRelay.NotRedeemer.selector);
        vm.prank(relayer);
        relay.attestApproval(agentId, digest);
        vm.expectRevert(IRiparReputationRelay.AgentIsShielded.selector);
        vm.prank(agent);
        relay.attestApproval(agentId, digest);
        // lifting the operator does not lift the bar; a later denial is ordinary -1 feedback
        vm.prank(agentOwner);
        identity.setAuthorized(agentId, address(relay), false);
        vm.expectRevert(IRiparReputationRelay.AgentIsShielded.selector);
        vm.prank(agent);
        relay.attestApproval(agentId, digest);
        bytes32 requestHash2 = keccak256("another denied request");
        (r, s) = p256Sign(DEVICE_P1_PK, relay.denyDigest(agentId, requestHash2, bytes32(0)));
        relay.attestDenial(agentId, requestHash2, bytes32(0), px, py, r, s);
        assertEq(relay.shieldedDenials(agentId), 1);
        _checkFeedback(0, -1, "denied", requestHash2);

        // another agent the redeemer acts for can still be credited with the approval
        address otherOwner = makeAddr("other agent owner");
        vm.startPrank(otherOwner);
        uint256 otherAgent = identity.register("ipfs://other", new IERC8004Identity.MetadataEntry[](0));
        identity.setAuthorized(otherAgent, agent, true);
        vm.stopPrank();
        vm.prank(agent);
        relay.attestApproval(otherAgent, digest);
        assertEq(reputation.feedbackCount(), 2);
    }

    // ================================================================== the whole story

    function test_endToEnd_story() public {
        Delegation memory mandate = _m();
        // 1. the agent tries to pay a new merchant on its own: needs a human
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(mandate, payee, 12e6);
        // 2. the user approves it on the device (pulse + SIGN): paid, merchant remembered
        bytes32 digest = _humanTransfer(mandate, payee, 12e6, 1);
        // 3. the agent (the redeemer) files the approval with the reputation relay: +1 for its ERC-8004 identity
        vm.prank(agent);
        relay.attestApproval(agentId, digest);
        // 4. repeat purchases run on their own within the caps; the companion reads the budget left
        _autoTransfer(mandate, payee, 12e6);
        _autoTransfer(mandate, payee, 12e6);
        _assertBudget(mandate, 24e6, PERIOD_CAP - 24e6, T0, T0 + PERIOD);
        // 5. CRE flags risk: autonomous lane closed, humans still in control
        _closeLane(7, uint64(block.number));
        vm.expectRevert(IPulseCosignEnforcer.LaneClosed.selector);
        _autoTransfer(mandate, payee, 12e6);
        _humanTransfer(mandate, payee, 12e6, 2);
        // 6. the user reopens from the device
        vm.roll(block.number + 1);
        _reopen(1);
        _autoTransfer(mandate, payee, 12e6);
        // 7. panic: everything the device signed dies at once
        _panic(1);
        vm.expectRevert(IPulseCosignEnforcer.StaleEpoch.selector);
        _autoTransfer(mandate, payee, 1e6);
        assertEq(musd.balanceOf(payee), 5 * 12e6);
        assertEq(reputation.feedbackCount(), 1);
        // 8. a fresh epoch-1 mandate starts with an empty payee list: the merchant needs the human once more
        IPulseCosignEnforcer.PulseTerms memory t1 = _tokenTerms();
        t1.epoch = 1;
        Delegation memory fresh = _mandate(t1, SALT + 1);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(fresh, payee, 12e6);
        bytes32 digest2 = _humanTransfer(fresh, payee, 12e6, 3);
        _autoTransfer(fresh, payee, 12e6);
        vm.prank(agent);
        relay.attestApproval(agentId, digest2);
        assertEq(musd.balanceOf(payee), 7 * 12e6);
        assertEq(reputation.feedbackCount(), 2);
    }
}

/// @notice The same end-to-end suite with a P256VERIFY precompile at 0x0100 (like Monad): OpenZeppelin P256 takes
///         its native path.
contract IntegrationPrecompileTest is IntegrationTest {
    function setUp() public override {
        etchP256Precompile();
        super.setUp();
    }

    function _precompileExpected() internal pure override returns (bool) {
        return true;
    }
}

/// @notice OPT-IN: the same suite on a fork of Monad testnet (10143) against the CANONICAL MetaMask DelegationManager
///         v1.3.0 that the firmware pins (0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3); everything else is deployed
///         locally on top of the fork. Read-only RPC. Skipped unless MONAD_TESTNET_RPC_URL is set, e.g.
///           MONAD_TESTNET_RPC_URL=https://testnet-rpc.monad.xyz forge test --mc IntegrationMonadForkTest
///         (the local EVM has no P256VERIFY precompile even on a fork, so OZ P256 uses its Solidity fallback).
contract IntegrationMonadForkTest is IntegrationTest {
    address internal constant CANONICAL_DELEGATION_MANAGER = 0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3;

    function setUp() public override {
        string memory rpc = vm.envOr("MONAD_TESTNET_RPC_URL", string(""));
        if (bytes(rpc).length == 0) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(rpc);
        assertEq(block.chainid, 10_143, "Monad testnet");
        super.setUp();
        assertEq(relay.delegationManager(), CANONICAL_DELEGATION_MANAGER, "the relay credits the canonical manager");
    }

    function _delegationManager() internal view override returns (DelegationManager dm) {
        dm = DelegationManager(CANONICAL_DELEGATION_MANAGER);
        assertEq(dm.VERSION(), "1.3.0");
        assertFalse(dm.paused());
    }
}

/// @notice Gas of `DelegationManager.redeemDelegations` for the Ripar paths, measured with every touched account and
///         slot cold (vm.cool), as in a fresh transaction. `exec` is the gas used inside redeemDelegations; `tx` adds
///         the intrinsic 21,000 + calldata gas (4 / 16 per zero / non-zero byte). Run with -vv to see the table.
///         - "fallback": no code at 0x0100, OZ P256 verifies in Solidity (a chain without RIP-7212).
///         - "monad": a stand-in at 0x0100 that accepts and burns ~6,900 gas, the price of Monad's precompile
///           (kept warm, like a precompile). NOT a behaviour test: it accepts any signature.
contract IntegrationGasTest is IntegrationBase {
    bool internal monad;

    function _monad() internal {
        monad = true;
        vm.etch(P256_PRECOMPILE, address(new MonadP256GasStub()).code);
    }

    function _cold() internal {
        vm.cool(address(delegationManager));
        vm.cool(address(enforcer));
        vm.cool(address(vault));
        vm.cool(address(hybridImpl));
        vm.cool(address(musd));
        vm.cool(address(sentinel));
        vm.cool(address(registry));
        vm.cool(address(relay));
        vm.cool(address(identity));
        vm.cool(address(reputation));
        vm.cool(agent);
        vm.cool(payee);
        vm.cool(payee2);
        if (monad) {
            (bool ok,) = P256_PRECOMPILE.staticcall(""); // precompiles are always warm
            assertTrue(ok);
        } else {
            vm.cool(P256_PRECOMPILE);
        }
    }

    function _calldataGas(bytes memory data) internal pure returns (uint256 g) {
        for (uint256 i; i < data.length; ++i) {
            g += data[i] == 0 ? 4 : 16;
        }
    }

    function _label(string memory label) internal view returns (string memory) {
        return string.concat(monad ? "[monad]    " : "[fallback] ", label);
    }

    /// @dev Measures one redemption of `d` by the agent (cold state) and logs `label, exec, tx`.
    function _measure(
        string memory label,
        Delegation memory d,
        bytes memory args,
        address target,
        uint256 value,
        bytes memory data
    ) internal returns (uint256 exec) {
        Delegation[] memory chain = new Delegation[](1);
        chain[0] = _withArgs(d, args);
        bytes[] memory contexts = new bytes[](1);
        contexts[0] = abi.encode(chain);
        ModeCode[] memory modes = new ModeCode[](1);
        modes[0] = singleMode;
        bytes[] memory executions = new bytes[](1);
        executions[0] = ExecutionLib.encodeSingle(target, value, data);
        uint256 intrinsic =
            21_000 + _calldataGas(abi.encodeCall(delegationManager.redeemDelegations, (contexts, modes, executions)));

        _cold();
        vm.prank(agent);
        delegationManager.redeemDelegations(contexts, modes, executions);
        exec = vm.lastCallGas().gasTotalUsed;
        console2.log(_label(label), exec, exec + intrinsic);
    }

    function _human(Delegation memory d, address target, uint256 value, bytes memory data, uint256 nonce)
        internal
        view
        returns (bytes memory args)
    {
        (args,) = _signCosign(_cosign(d, target, value, data, nonce));
    }

    function _run() internal returns (uint256 humanNew, uint256 autoFirst, uint256 autoNext) {
        Delegation memory d = _mandate(_tokenTerms(), 1);
        Delegation memory n = _mandate(_nativeTerms(), 2);
        console2.log("label | exec gas | tx gas (exec + 21000 + calldata)");

        // framework baseline: the same kind of transfer under a delegation without any caveat (comparison only)
        Delegation memory plain = _mandate(_tokenTerms(), 3);
        plain.caveats = new Caveat[](0);
        plain.signature = _k1Sign(DEVICE_K1_PK, _digest(delegationManager.getDomainHash(), _hash(plain)));
        _measure("baseline: no caveat, ERC-20 transfer", plain, "", address(musd), 0, _transfer(payee2, 1e6));

        bytes memory t10 = _transfer(payee, 10e6);
        humanNew = _measure(
            "HUMAN ERC-20 transfer, new payee", d, _human(d, address(musd), 0, t10, 1), address(musd), 0, t10
        );
        _measure("HUMAN ERC-20 transfer, known payee", d, _human(d, address(musd), 0, t10, 2), address(musd), 0, t10);
        autoFirst = _measure("AUTO ERC-20 transfer, first in period", d, "", address(musd), 0, t10);
        autoNext = _measure("AUTO ERC-20 transfer, same period", d, "", address(musd), 0, t10);
        vm.warp(block.timestamp + PERIOD);
        _measure("AUTO ERC-20 transfer, period rolled over", d, "", address(musd), 0, t10);

        _measure("HUMAN native send, new payee", n, _human(n, payee2, 0.5 ether, "", 3), payee2, 0.5 ether, "");
        _measure("AUTO native send, first in period", n, "", payee2, 0.1 ether, "");
        _measure("AUTO native send, same period", n, "", payee2, 0.1 ether, "");
        assertEq(musd.balanceOf(payee), 50e6);
        assertEq(payee2.balance, 0.7 ether);
    }

    function _killSwitch() internal {
        bytes32 h = _hash(_mandate(_tokenTerms(), 1));
        (bytes32 r, bytes32 s) = p256Sign(DEVICE_P1_PK, enforcer.revokeDigest(h));
        _cold();
        vm.prank(relayer);
        enforcer.revoke(px, py, h, r, s);
        console2.log(_label("enforcer.revoke"), vm.lastCallGas().gasTotalUsed);

        (r, s) = p256Sign(DEVICE_P1_PK, enforcer.panicDigest(1));
        _cold();
        vm.prank(relayer);
        enforcer.panic(px, py, 1, r, s);
        console2.log(_label("enforcer.panic"), vm.lastCallGas().gasTotalUsed);

        _closeLane(1, uint64(block.number));
        vm.roll(block.number + 1);
        (r, s) = _reopenSig(1);
        _cold();
        vm.prank(relayer);
        sentinel.reopen(address(vault), 1, r, s);
        console2.log(_label("sentinel.reopen"), vm.lastCallGas().gasTotalUsed);
    }

    function test_gas_fallback() public {
        (uint256 humanNew, uint256 autoFirst, uint256 autoNext) = _run();
        _killSwitch();
        // loose regression bounds (the Solidity P-256 fallback dominates the HUMAN path)
        assertLt(humanNew, 600_000);
        assertLt(autoFirst, 150_000);
        assertLt(autoNext, 130_000);
    }

    function test_gas_monad() public {
        _monad();
        (uint256 humanNew, uint256 autoFirst, uint256 autoNext) = _run();
        _killSwitch();
        assertLt(humanNew, 250_000);
        assertLt(autoFirst, 150_000);
        assertLt(autoNext, 130_000);
    }
}

/// @notice script/Deploy.s.sol run in-process: predicted CREATE2 addresses equal the deployed ones, the deployment is
///         idempotent and wired to the per-chain config. SPEC v1.2: on Monad (10143, 143) the config requires the CRE
///         workflow owner (MissingWorkflowOwner otherwise) and the sentinel's CREATE2 address commits to it.
///         The Monad cases deploy through deployFor(configFor(...)) so that no test depends on (or sets) the process
///         environment.
contract DeployScriptTest is Test {
    address internal constant CANONICAL_DELEGATION_MANAGER = 0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3;
    address internal constant TESTNET_FORWARDER = 0xF8344CFd5c43616a4366C34E3EEE75af79a74482;
    bytes32 internal constant DEPLOY_SALT = keccak256("ripar-wallet v1");

    Deploy internal script;
    address internal workflowOwner;

    function setUp() public {
        script = new Deploy();
        workflowOwner = makeAddr("CRE workflow owner");
    }

    function _assertSame(Deploy.Deployment memory a, Deploy.Deployment memory b) internal pure {
        assertEq(a.registry, b.registry, "registry");
        assertEq(a.enforcer, b.enforcer, "enforcer");
        assertEq(a.sentinel, b.sentinel, "sentinel");
        assertEq(a.relay, b.relay, "relay");
        assertEq(a.mockUsd, b.mockUsd, "mockUSD");
    }

    function _testnet(address owner) internal view returns (DeployConfig.ChainConfig memory) {
        return script.configFor(10_143, address(0), owner, address(0), address(0), address(0));
    }

    function test_predict_equals_deploy_and_isIdempotent() public {
        assertGt(CREATE2_FACTORY.code.length, 0, "deterministic deployer present");
        Deploy.Deployment memory p = script.predict();
        assertEq(p.registry.code.length, 0);
        assertEq(p.enforcer.code.length, 0);
        assertEq(p.sentinel.code.length, 0);
        assertEq(p.relay.code.length, 0);
        assertEq(p.mockUsd.code.length, 0);

        Deploy.Deployment memory d = script.deploy();
        _assertSame(p, d);
        assertEq(
            p.enforcer,
            vm.computeCreate2Address(DEPLOY_SALT, keccak256(type(PulseCosignEnforcer).creationCode), CREATE2_FACTORY)
        );
        // the relay's CREATE2 address commits to its five constructor arguments (v1.1: + the DelegationManager)
        DeployConfig.ChainConfig memory c = script.chainConfig(block.chainid);
        assertEq(
            p.relay,
            vm.computeCreate2Address(
                DEPLOY_SALT,
                keccak256(
                    abi.encodePacked(
                        type(RiparReputationRelay).creationCode,
                        abi.encode(c.reputation, c.identity, p.enforcer, p.registry, c.delegationManager)
                    )
                ),
                CREATE2_FACTORY
            ),
            "relay CREATE2 address"
        );
        // the sentinel's commits to (forwarder, registry, expectedWorkflowOwner)
        assertEq(
            p.sentinel,
            vm.computeCreate2Address(
                DEPLOY_SALT,
                keccak256(
                    abi.encodePacked(
                        type(RiparSentinel).creationCode, abi.encode(c.forwarder, p.registry, c.expectedWorkflowOwner)
                    )
                ),
                CREATE2_FACTORY
            ),
            "sentinel CREATE2 address"
        );
        assertGt(d.registry.code.length, 0);
        assertGt(d.enforcer.code.length, 0);
        assertGt(d.sentinel.code.length, 0);
        assertGt(d.relay.code.length, 0);
        assertGt(d.mockUsd.code.length, 0);
        assertEq(MockUSD(d.mockUsd).decimals(), 6);
        assertEq(address(RiparSentinel(d.sentinel).registry()), d.registry);
        assertEq(address(RiparReputationRelay(d.relay).enforcer()), d.enforcer);
        assertEq(address(RiparReputationRelay(d.relay).registry()), d.registry);
        assertEq(RiparReputationRelay(d.relay).delegationManager(), c.delegationManager, "relay.delegationManager");

        // a second run deploys nothing and returns the same addresses
        _assertSame(script.deploy(), d);
    }

    function test_monadTestnet_config() public {
        vm.chainId(10_143);
        DeployConfig.ChainConfig memory c = _testnet(workflowOwner);
        assertEq(c.forwarder, TESTNET_FORWARDER);
        assertEq(c.expectedWorkflowOwner, workflowOwner, "v1.2: the CRE workflow owner is required and kept");
        assertEq(c.identity, 0x8004A818BFB912233c491871b3d84c89A494BD9e);
        assertEq(c.reputation, 0x8004B663056A597Dffe9eCcC1965A193B7388713);
        assertEq(c.delegationManager, CANONICAL_DELEGATION_MANAGER, "the canonical DelegationManager is pinned");
        assertTrue(c.deployMockUsd);

        Deploy.Deployment memory d = script.deployFor(c);
        _assertSame(script.predictFor(c), d);
        _assertSame(script.deployFor(c), d); // idempotent
        RiparSentinel sentinel = RiparSentinel(d.sentinel);
        assertEq(sentinel.forwarder(), c.forwarder);
        assertEq(sentinel.expectedWorkflowOwner(), workflowOwner);
        RiparReputationRelay relay = RiparReputationRelay(d.relay);
        assertEq(address(relay.identity()), c.identity);
        assertEq(address(relay.reputation()), c.reputation);
        assertEq(relay.delegationManager(), CANONICAL_DELEGATION_MANAGER, "the relay credits the canonical manager");
        // the EIP-712 domains carry this chain id
        assertEq(
            PulseCosignEnforcer(d.enforcer).domainSeparator(),
            keccak256(
                abi.encode(
                    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                    keccak256("RiparPulseCosign"),
                    keccak256("1"),
                    10_143,
                    d.enforcer
                )
            )
        );
    }

    function test_mainnet_config_requiresForwarder_noMockUSD() public {
        vm.expectRevert(DeployConfig.MissingForwarder.selector);
        script.configFor(143, address(0), address(0), address(0), address(0), address(0));

        address fwd = makeAddr("mainnet forwarder");
        DeployConfig.ChainConfig memory main =
            script.configFor(143, fwd, workflowOwner, address(1), address(2), address(3));
        assertEq(main.forwarder, fwd);
        assertEq(main.expectedWorkflowOwner, workflowOwner);
        assertEq(main.identity, 0x8004A169FB4a3325136EB29fA0ceB6D2e539a432, "env ignored on 143");
        assertEq(main.reputation, 0x8004BAa17C55a88189AE136b182e5fdA19dE9b63);
        assertEq(main.delegationManager, CANONICAL_DELEGATION_MANAGER, "env ignored on 143: canonical manager");
        assertFalse(main.deployMockUsd);

        DeployConfig.ChainConfig memory testnet =
            script.configFor(10_143, fwd, workflowOwner, address(1), address(2), address(3));
        assertEq(testnet.forwarder, TESTNET_FORWARDER, "testnet forwarder is pinned");
        assertEq(testnet.expectedWorkflowOwner, workflowOwner);
        assertEq(testnet.delegationManager, CANONICAL_DELEGATION_MANAGER, "env ignored on 10143: canonical manager");

        Deploy.Deployment memory pm = script.predictFor(main);
        Deploy.Deployment memory pt = script.predictFor(testnet);
        // no constructor arguments: the same address on every chain (what the firmware can pin)
        assertEq(pm.registry, pt.registry);
        assertEq(pm.enforcer, pt.enforcer);
        // chain-specific constructor arguments: different addresses
        assertTrue(pm.sentinel != pt.sentinel);
        assertTrue(pm.relay != pt.relay);
        assertEq(pm.mockUsd, address(0));
        assertTrue(pt.mockUsd != address(0));
    }

    /// @dev SPEC v1.2 (INTEGRATION-2 / PERIPHERY-4 / ATTACKER-4): Monad testnet and mainnet refuse a config without
    ///      the CRE workflow owner; the local chain still accepts 0 (no metadata check). On 143 the forwarder is
    ///      checked first.
    function test_workflowOwner_requiredOnMonad_optionalLocally() public {
        vm.expectRevert(DeployConfig.MissingWorkflowOwner.selector);
        script.configFor(10_143, address(0), address(0), address(0), address(0), address(0));
        vm.expectRevert(DeployConfig.MissingWorkflowOwner.selector);
        script.configFor(10_143, makeAddr("fwd"), address(0), address(1), address(2), address(3));
        vm.expectRevert(DeployConfig.MissingWorkflowOwner.selector);
        script.configFor(143, makeAddr("mainnet forwarder"), address(0), address(0), address(0), address(0));
        // order on 143: MissingForwarder before MissingWorkflowOwner
        vm.expectRevert(DeployConfig.MissingForwarder.selector);
        script.configFor(143, address(0), address(0), address(0), address(0), address(0));

        DeployConfig.ChainConfig memory local =
            script.configFor(31_337, address(0), address(0), address(0), address(0), address(0));
        assertEq(local.expectedWorkflowOwner, address(0), "31337: 0 = no metadata check");
        assertEq(
            script.configFor(31_337, address(0), workflowOwner, address(0), address(0), address(0))
            .expectedWorkflowOwner,
            workflowOwner
        );
    }

    /// @dev configFor reverts MissingWorkflowOwner exactly when the owner is 0 on a Monad chain.
    function testFuzz_configFor_workflowOwner(uint8 which, address owner) public {
        uint256 chainId = which % 3 == 0 ? 10_143 : (which % 3 == 1 ? 143 : 31_337);
        address fwd = makeAddr("forwarder");
        if (owner == address(0) && chainId != 31_337) {
            vm.expectRevert(DeployConfig.MissingWorkflowOwner.selector);
            script.configFor(chainId, fwd, owner, address(0), address(0), address(0));
        } else {
            assertEq(
                script.configFor(chainId, fwd, owner, address(0), address(0), address(0)).expectedWorkflowOwner, owner
            );
        }
    }

    /// @dev chainConfig / predict read RIPAR_WORKFLOW_OWNER: on 10143 they revert without it. (The branch taken depends
    ///      on the caller's environment; the test never sets it.)
    function test_chainConfig_readsWorkflowOwnerFromEnv() public {
        vm.chainId(10_143);
        address fromEnv = vm.envOr("RIPAR_WORKFLOW_OWNER", address(0));
        if (fromEnv == address(0)) {
            vm.expectRevert(DeployConfig.MissingWorkflowOwner.selector);
            script.chainConfig(10_143);
            vm.expectRevert(DeployConfig.MissingWorkflowOwner.selector);
            script.predict();
            vm.expectRevert(DeployConfig.MissingWorkflowOwner.selector);
            script.deploy();
        } else {
            assertEq(script.chainConfig(10_143).expectedWorkflowOwner, fromEnv);
            _assertSame(script.predict(), script.predictFor(_testnet(fromEnv)));
        }
    }

    /// @dev predict(): the sentinel's address depends on the workflow owner; the registry, the enforcer, MockUSD and
    ///      the relay do not (the relay commits to the ERC-8004 registries and the DelegationManager only).
    function test_predict_sentinelDependsOnWorkflowOwner_relayDoesNot() public view {
        Deploy.Deployment memory a = script.predictFor(_testnet(workflowOwner));
        Deploy.Deployment memory b = script.predictFor(_testnet(address(0xB0B)));
        assertTrue(a.sentinel != b.sentinel, "another workflow owner, another sentinel");
        assertEq(a.relay, b.relay, "the relay does not commit to the workflow owner");
        assertEq(a.registry, b.registry);
        assertEq(a.enforcer, b.enforcer);
        assertEq(a.mockUsd, b.mockUsd);
        // and the chain-independent three are the same as on the local chain
        Deploy.Deployment memory l =
            script.predictFor(script.configFor(31_337, address(0), address(0), address(0), address(0), address(0)));
        assertEq(l.registry, a.registry);
        assertEq(l.enforcer, a.enforcer);
        assertEq(l.mockUsd, a.mockUsd);
    }

    /// @dev Local chain: RIPAR_DELEGATION_MANAGER (an env var, passed here as the pure config's argument) picks the
    ///      DelegationManager the relay credits; unset (0) means the canonical one. It only moves the relay.
    function test_local_config_delegationManager() public {
        address fwd = makeAddr("local forwarder");
        DeployConfig.ChainConfig memory byDefault =
            script.configFor(31_337, fwd, address(0), address(1), address(2), address(0));
        assertEq(byDefault.delegationManager, CANONICAL_DELEGATION_MANAGER, "default: the canonical manager");
        assertEq(byDefault.forwarder, fwd);
        assertEq(byDefault.identity, address(1));
        assertEq(byDefault.reputation, address(2));
        assertTrue(byDefault.deployMockUsd);

        address localDm = makeAddr("local DelegationManager");
        DeployConfig.ChainConfig memory custom =
            script.configFor(31_337, fwd, address(0), address(1), address(2), localDm);
        assertEq(custom.delegationManager, localDm, "RIPAR_DELEGATION_MANAGER on 31337");

        Deploy.Deployment memory pd = script.predictFor(byDefault);
        Deploy.Deployment memory pc = script.predictFor(custom);
        assertEq(pd.registry, pc.registry);
        assertEq(pd.enforcer, pc.enforcer);
        assertEq(pd.sentinel, pc.sentinel);
        assertEq(pd.mockUsd, pc.mockUsd);
        assertTrue(pd.relay != pc.relay, "the relay commits to its DelegationManager");

        // chainConfig reads the env var with the canonical manager as its default
        address fromEnv = vm.envOr("RIPAR_DELEGATION_MANAGER", CANONICAL_DELEGATION_MANAGER);
        assertEq(
            script.chainConfig(31_337).delegationManager, fromEnv == address(0) ? CANONICAL_DELEGATION_MANAGER : fromEnv
        );
    }

    function test_unsupportedChain() public {
        vm.expectRevert(abi.encodeWithSelector(DeployConfig.UnsupportedChain.selector, uint256(1)));
        script.configFor(1, address(0), address(0), address(0), address(0), address(0));
        vm.chainId(1);
        vm.expectRevert(abi.encodeWithSelector(DeployConfig.UnsupportedChain.selector, uint256(1)));
        script.predict();
    }
}
