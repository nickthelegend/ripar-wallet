// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { ExecutionLib } from "@erc7579/lib/ExecutionLib.sol";
import { Delegation } from "@delegation-framework/utils/Types.sol";

import { MockUSD } from "../../src/MockUSD.sol";
import { IPulseCosignEnforcer } from "../../src/interfaces/IPulseCosignEnforcer.sol";
import { EnforcerRedeemBase } from "../utils/enforcer/EnforcerRedeemBase.sol";

/// @notice Attacker-deployed "token" (ATTACKER-1): `transfer` does nothing and returns true.
contract NoopToken {
    function transfer(address, uint256) external pure returns (bool) {
        return true;
    }
}

/// @notice Regression suite for the enforcer findings of the v1.1 adversarial review (SPEC.md "Changes in v1.2"),
///         through the REAL MetaMask DelegationManager v1.3.0 and a HybridDeleGator vault. Each PoC of
///         .work/snap-v11/poc/ that passed against v1.1 (the attack worked) is ported as a NEGATIVE test that passes
///         against v1.2 (the attack fails):
///         - ENF1 (EnforcerPoC): a 0-amount foreign-asset or 0-value native co-sign whitelisted an AUTO payee;
///         - PROTOCOL1 (ProtocolPoC): the same request (same nonce) signed twice paid twice;
///         - PROTOCOL2 (ProtocolPoC): 0-value native / 0-amount junk-token / 0-amount token-under-native co-signs
///           whitelisted a payee for the metered asset;
///         - INTEGRATION-3 (KnownPayeeCrossAsset) and ATTACKER-1 (AttackerPoC): cross-asset / dust co-signs whitelisted
///           a payee for the metered asset.
///         The positive tests check that the legitimate flows (a real payment of the metered asset whitelists; a
///         nonce is per mandate and per manager) keep working end to end.
contract EnforcerRegressionTest is EnforcerRedeemBase {
    // ================================================================== ENF1

    /// @notice ENF1 (was: test_ENF1_zeroAmountForeignTransferCosign_whitelistsAutoPayee). The device co-signs
    ///         "transfer 0 of an unknown token to <thief>" on a no-code address: the call still executes, but the
    ///         thief does not become an AUTO payee of the mUSD mandate.
    function test_ENF1_zeroAmountForeignTransferCosign_doesNotWhitelist() public {
        Delegation memory mandate = _mandate(_tokenTerms(), 1);
        address thief = makeAddr("thief");
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(mandate, thief, PER_TX);

        address notAToken = makeAddr("not a token");
        _redeemCosign(mandate, _cosign(mandate, notAToken, 0, _transfer(thief, 0), 42));
        assertFalse(_known(mandate, thief), "a 0-amount foreign co-sign whitelists nobody");

        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(mandate, thief, PER_TX);
        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(mandate, thief, PER_TX);
        assertEq(musd.balanceOf(thief), 0, "nothing drained");
    }

    /// @notice ENF1 (was: test_ENF1_zeroValueNativeCosign_whitelistsAutoPayeeForToken). "Send 0 MON to <thief>".
    function test_ENF1_zeroValueNativeCosign_doesNotWhitelistForToken() public {
        Delegation memory mandate = _mandate(_tokenTerms(), 2);
        address thief = makeAddr("thief");
        _redeemCosign(mandate, _cosign(mandate, thief, 0, "", 7));
        assertFalse(_known(mandate, thief));
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(mandate, thief, PER_TX);
        assertEq(musd.balanceOf(thief), 0);
    }

    // ================================================================== PROTOCOL1

    /// @notice PROTOCOL1 (was: test_PROTOCOL1_sameNonceSignedTwice_paysTwice). The device signs the very same request
    ///         (nonce 7) twice with fresh presence salts: two digests, but only the first co-sign pays.
    function test_PROTOCOL1_sameNonceSignedTwice_paysOnce() public {
        Delegation memory mandate = _mandate(_tokenTerms(), 1);
        bytes memory data = _transfer(payee, 400e6); // far above the AUTO caps: only a human may approve it
        Cosign memory first = _cosign(mandate, address(musd), 0, data, 7);
        Cosign memory second = _cosign(mandate, address(musd), 0, data, 7);
        first.presenceHash = _presence(1001);
        second.presenceHash = _presence(1002);

        bytes32 d1 = _redeemCosign(mandate, first);
        (bytes memory args2, bytes32 d2) = _signCosign(second);
        assertTrue(d1 != d2, "different digests");
        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
        _redeem(mandate, args2, address(musd), 0, data);

        assertEq(musd.balanceOf(payee), 400e6, "the nonce-7 payment executed once");
        assertTrue(enforcer.nonceUsed(address(delegationManager), _hash(mandate), 7));
        assertFalse(enforcer.consumed(address(delegationManager), d2));
    }

    /// @notice PROTOCOL1 variant: nonce 7 cannot be reused for another request either (other amount, other payee).
    function test_PROTOCOL1_sameNonceOtherRequest_replayed() public {
        Delegation memory mandate = _mandate(_tokenTerms(), 1);
        _redeemCosign(mandate, _cosign(mandate, address(musd), 0, _transfer(payee, 400e6), 7));
        Cosign memory other = _cosign(mandate, address(musd), 0, _transfer(payee2, 300e6), 7);
        other.presenceHash = _presence(99);
        (bytes memory args,) = _signCosign(other);
        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
        _redeem(mandate, args, address(musd), 0, other.callData);
        assertEq(musd.balanceOf(payee2), 0);
    }

    // ================================================================== PROTOCOL2

    /// @notice PROTOCOL2 (was: test_PROTOCOL2_zeroNativeCosign_whitelistsPayeeForMeteredToken).
    function test_PROTOCOL2_zeroNativeCosign_doesNotWhitelistPayeeForMeteredToken() public {
        Delegation memory mandate = _mandate(_tokenTerms(), 1);
        _redeemCosign(mandate, _cosign(mandate, payee2, 0, "", 1)); // "Send 0 MON to payee2"
        assertFalse(_known(mandate, payee2));
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(mandate, payee2, PER_TX);
        assertEq(musd.balanceOf(payee2), 0);
    }

    /// @notice PROTOCOL2 (was: test_PROTOCOL2_zeroJunkTokenCosign_whitelistsPayeeForMeteredToken).
    function test_PROTOCOL2_zeroJunkTokenCosign_doesNotWhitelistPayeeForMeteredToken() public {
        MockUSD junk = new MockUSD();
        Delegation memory mandate = _mandate(_tokenTerms(), 1);
        address x = makeAddr("x");
        _redeemCosign(mandate, _cosign(mandate, address(junk), 0, _transfer(x, 0), 1));
        assertFalse(_known(mandate, x));
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(mandate, x, PER_TX);
        assertEq(musd.balanceOf(x), 0);
    }

    /// @notice PROTOCOL2 (was: test_PROTOCOL2_zeroTokenCosign_whitelistsPayeeForNativeMandate).
    function test_PROTOCOL2_zeroTokenCosign_doesNotWhitelistPayeeForNativeMandate() public {
        Delegation memory mandate = _mandate(_nativeTerms(), 1);
        address x = makeAddr("x");
        _redeemCosign(mandate, _cosign(mandate, address(musd), 0, _transfer(x, 0), 1));
        assertFalse(_known(mandate, x));
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoNative(mandate, x, NATIVE_PER_TX);
        assertEq(x.balance, 0);
    }

    /// @notice PROTOCOL2 variant with a real amount: a non-zero mUSD transfer co-signed under a MON mandate is a real
    ///         payment, but of another asset, so it does not whitelist the payee for MON either.
    function test_PROTOCOL2_nonZeroTokenCosign_doesNotWhitelistPayeeForNativeMandate() public {
        Delegation memory mandate = _mandate(_nativeTerms(), 1);
        address x = makeAddr("x");
        _redeemCosign(mandate, _cosign(mandate, address(musd), 0, _transfer(x, 5e6), 1));
        assertEq(musd.balanceOf(x), 5e6, "the co-signed payment itself went through");
        assertFalse(_known(mandate, x));
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoNative(mandate, x, NATIVE_PER_TX);
    }

    // ================================================================== INTEGRATION-3

    /// @notice INTEGRATION-3 (was: KnownPayeeCrossAssetPoc.test_poc_zeroValueNativeCosign_whitelistsPayeeForTokenAuto).
    function test_INTEGRATION3_zeroValueNativeCosign_doesNotWhitelistForTokenAuto() public {
        Delegation memory d = _mandate(_tokenTerms(), 11);
        address attacker = makeAddr("attacker payee");
        _redeemCosign(d, _cosign(d, attacker, 0, "", 1));
        assertFalse(_known(d, attacker));
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(d, attacker, 25e6);
        assertEq(musd.balanceOf(attacker), 0);
    }

    /// @notice INTEGRATION-3 (was: KnownPayeeCrossAssetPoc.test_poc_junkTokenCosign_whitelistsPayeeForTokenAuto): a
    ///         1-base-unit payment of a worthless token is real, but not in the metered asset.
    function test_INTEGRATION3_junkTokenCosign_doesNotWhitelistForTokenAuto() public {
        Delegation memory d = _mandate(_tokenTerms(), 12);
        address attacker = makeAddr("attacker payee");
        MockUSD junk = new MockUSD();
        junk.faucet(address(vault), 1);
        _redeemCosign(d, _cosign(d, address(junk), 0, _transfer(attacker, 1), 1));
        assertEq(junk.balanceOf(attacker), 1);
        assertFalse(_known(d, attacker));
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(d, attacker, 25e6);
        assertEq(musd.balanceOf(attacker), 0);
    }

    /// @notice INTEGRATION-3 variant: a real, non-zero native payment co-signed under the mUSD mandate does not make
    ///         the payee an mUSD AUTO payee.
    function test_INTEGRATION3_nonZeroNativeCosign_doesNotWhitelistForTokenAuto() public {
        Delegation memory d = _mandate(_tokenTerms(), 13);
        address attacker = makeAddr("attacker payee");
        _redeemCosign(d, _cosign(d, attacker, 1, "", 1)); // 1 wei of MON
        assertEq(attacker.balance, 1);
        assertFalse(_known(d, attacker));
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(d, attacker, 25e6);
    }

    // ================================================================== ATTACKER-1

    /// @notice ATTACKER-1 (was: test_ATTACKER1_foreignJunkTokenCosign_whitelistsPayeeForMeteredToken).
    function test_ATTACKER1_foreignJunkTokenCosign_doesNotWhitelistPayeeForMeteredToken() public {
        Delegation memory m = _mandate(_tokenTerms(), 11);
        address evil = makeAddr("evil payee");
        NoopToken junk = new NoopToken();
        _redeemCosign(m, _cosign(m, address(junk), 0, _transfer(evil, 1), 1));
        assertFalse(_known(m, evil), "a junk-token transfer whitelists nobody");
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(m, evil, PER_TX);
        vm.warp(block.timestamp + PERIOD);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(m, evil, PER_TX);
        assertEq(musd.balanceOf(evil), 0);
    }

    /// @notice ATTACKER-1 (was: test_ATTACKER1_zeroValueNativePing_whitelistsAgentForMeteredToken).
    function test_ATTACKER1_zeroValueNativePing_doesNotWhitelistAgent() public {
        Delegation memory m = _mandate(_tokenTerms(), 12);
        _redeemCosign(m, _cosign(m, agent, 0, "", 1)); // "send 0 MON to my address"
        assertFalse(_known(m, agent));
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(m, agent, PER_TX);
        assertEq(musd.balanceOf(agent), 0);
    }

    // ================================================================== positive end-to-end flows

    /// @notice A co-signed `transfer` of the metered token with amount > 0 whitelists the recipient; the agent then
    ///         pays it on the AUTO path within the caps.
    function test_positive_meteredTokenTransferCosign_whitelists() public {
        Delegation memory m = _mandate(_tokenTerms(), 21);
        vm.expectEmit(address(enforcer));
        emit PayeeApproved(address(delegationManager), _hash(m), payee);
        _redeemCosign(m, _cosign(m, address(musd), 0, _transfer(payee, 1e6), 1));
        assertTrue(_known(m, payee));
        _autoTransfer(m, payee, PER_TX);
        _autoTransfer(m, payee, PER_TX);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(m, payee, 1); // the period cap still holds
        assertEq(musd.balanceOf(payee), 1e6 + PERIOD_CAP);
    }

    /// @notice A co-signed native send > 0 under a native mandate whitelists the target for MON AUTO payments.
    function test_positive_nativeSendCosign_underNativeMandate_whitelists() public {
        Delegation memory m = _mandate(_nativeTerms(), 22);
        _redeemCosign(m, _cosign(m, payee, 0.01 ether, "", 1));
        assertTrue(_known(m, payee));
        _autoNative(m, payee, NATIVE_PER_TX);
        assertEq(payee.balance, 0.01 ether + NATIVE_PER_TX);
    }

    /// @notice The same nonce under a different mandate is a different co-sign: both pay.
    function test_positive_sameNonceDifferentMandate_works() public {
        Delegation memory m1 = _mandate(_tokenTerms(), 31);
        Delegation memory m2 = _mandate(_tokenTerms(), 32);
        _redeemCosign(m1, _cosign(m1, address(musd), 0, _transfer(payee, 100e6), 7));
        _redeemCosign(m2, _cosign(m2, address(musd), 0, _transfer(payee, 100e6), 7));
        assertEq(musd.balanceOf(payee), 200e6);
        assertTrue(enforcer.nonceUsed(address(delegationManager), _hash(m1), 7));
        assertTrue(enforcer.nonceUsed(address(delegationManager), _hash(m2), 7));
    }

    /// @notice A third party that sees the pending redemption and calls beforeHook directly with its caveat args
    ///         burns the nonce only for itself: the real redemption through the DelegationManager still pays.
    function test_positive_directBeforeHookByThirdParty_doesNotBurnNonce() public {
        Delegation memory m = _mandate(_tokenTerms(), 41);
        bytes32 dh = _hash(m);
        Cosign memory c = _cosign(m, address(musd), 0, _transfer(payee, 400e6), 7);
        (bytes memory args, bytes32 digest) = _signCosign(c);

        address frontRunner = makeAddr("front-runner");
        vm.prank(frontRunner);
        enforcer.beforeHook(
            m.caveats[0].terms,
            args,
            singleMode,
            ExecutionLib.encodeSingle(address(musd), 0, c.callData),
            dh,
            address(vault),
            agent
        );
        assertTrue(enforcer.nonceUsed(frontRunner, dh, 7));
        assertFalse(enforcer.nonceUsed(address(delegationManager), dh, 7), "not burnt for the DelegationManager");

        _redeem(m, args, address(musd), 0, c.callData);
        assertEq(musd.balanceOf(payee), 400e6);
        assertTrue(enforcer.consumed(address(delegationManager), digest));
        assertTrue(enforcer.nonceUsed(address(delegationManager), dh, 7));
    }

    /// @notice A redemption whose execution fails reverts as a whole, so its nonce is not burnt: the device can re-sign
    ///         the corrected request with the same nonce.
    function test_positive_failedRedemption_doesNotBurnNonce() public {
        Delegation memory m = _mandate(_tokenTerms(), 51);
        Cosign memory tooMuch = _cosign(m, address(musd), 0, _transfer(payee, VAULT_MUSD + 1), 7);
        (bytes memory args,) = _signCosign(tooMuch);
        vm.expectRevert();
        _redeem(m, args, address(musd), 0, tooMuch.callData);
        assertFalse(enforcer.nonceUsed(address(delegationManager), _hash(m), 7));

        _redeemCosign(m, _cosign(m, address(musd), 0, _transfer(payee, 500e6), 7));
        assertEq(musd.balanceOf(payee), 500e6);
    }
}

/// @notice The regression suite again with the RIP-7212 / EIP-7951 precompile (mock) at 0x0100, as on Monad.
contract EnforcerRegressionPrecompileTest is EnforcerRegressionTest {
    function setUp() public override {
        etchP256Precompile();
        super.setUp();
    }
}
