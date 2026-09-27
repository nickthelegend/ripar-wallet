// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { Pausable } from "@openzeppelin/contracts/utils/Pausable.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { ExecutionLib } from "@erc7579/lib/ExecutionLib.sol";
import { ModeLib } from "@erc7579/lib/ModeLib.sol";
import { Execution } from "@erc7579/interfaces/IERC7579Account.sol";
import { DeleGatorCore } from "@delegation-framework/DeleGatorCore.sol";
import { DelegationManager } from "@delegation-framework/DelegationManager.sol";
import { HybridDeleGator } from "@delegation-framework/HybridDeleGator.sol";
import { IDelegationManager } from "@delegation-framework/interfaces/IDelegationManager.sol";
import { Delegation } from "@delegation-framework/utils/Types.sol";

import { PulseCosignEnforcer } from "../../src/PulseCosignEnforcer.sol";
import { RiparDeviceRegistry } from "../../src/RiparDeviceRegistry.sol";
import { RiparSentinel } from "../../src/RiparSentinel.sol";
import { IPulseCosignEnforcer } from "../../src/interfaces/IPulseCosignEnforcer.sol";
import { IRiparSentinel } from "../../src/interfaces/IRiparSentinel.sol";
import { IRiparDeviceRegistry } from "../../src/interfaces/IRiparDeviceRegistry.sol";
import { Deploy } from "../../script/Deploy.s.sol";
import { DeployConfig } from "../../script/DeployConfig.sol";
import { IntegrationBase } from "../utils/integration/IntegrationBase.sol";

/// @notice The "DelegationManager" a malicious companion bakes into the vault implementation it deploys (ATTACKER-6):
///         as the vault's immutable delegation manager it may call executeFromExecutor, with no delegation at all.
contract FakeDelegationManager {
    function drain(HybridDeleGator v, address token, address to, uint256 amount) external {
        v.executeFromExecutor(
            ModeLib.encodeSimpleSingle(),
            ExecutionLib.encodeSingle(token, 0, abi.encodeWithSelector(bytes4(0xa9059cbb), to, amount))
        );
    }
}

/// @notice Regression suite for the system-level findings of the v1.1 adversarial review that the enforcer and
///         periphery suites do not cover (SPEC "Changes in v1.2" / "Documented limitations after v1.2"). Each original
///         PoC (.work/snap-v11/poc/**) is ported against the REAL MetaMask delegation framework v1.3.0 and the real Ripar
///         contracts (IntegrationBase: DelegationManager, HybridDeleGator vault owned by the device's K1, EntryPoint).
///         - test_<FINDING>_*: a NEGATIVE test that passes on v1.2 (the attack no longer works).
///         - test_LIMITATION_<FINDING>_*: a limitation SPEC v1.2 documents and keeps by design; asserts today's behaviour
///           and what still protects the user.
///         - test_DOCUMENTED_<FINDING>_*: behaviour the contracts cannot prevent (a firmware-side fix); asserts today's
///           behaviour so a change is noticed.
///         Ported here: INTEGRATION-2, PERIPHERY-4 and ATTACKER-4 (sentinel without a workflow owner: the deploy config
///         now refuses it), INTEGRATION-4 (DelegationManager pause), ATTACKER-6 (companion vault with a fake
///         DelegationManager), PROTOCOL-5 (panic after a re-pair to another enforcer), PROTOCOL-4 (AUTO windows).
///         Throwaway test keys only.
contract SystemRegressionTest is IntegrationBase {
    address internal constant TESTNET_FORWARDER = 0xF8344CFd5c43616a4366C34E3EEE75af79a74482;
    uint256 internal constant SALT = 1;

    address internal stranger; // the owner of somebody else's CRE workflow

    function setUp() public virtual override {
        super.setUp();
        stranger = makeAddr("stranger workflow owner");
    }

    // ================================================================== helpers

    /// @dev the user co-signs a 1 mUSD transfer to `payee` on `d` (nonce `nonce`), which makes it a known AUTO payee
    function _approvePayee(Delegation memory d, uint256 nonce) internal returns (bytes32 digest) {
        bytes memory data = _transfer(payee, 1e6);
        bytes memory args;
        (args, digest) = _signCosign(_cosign(d, address(musd), 0, data, nonce));
        _redeem(d, args, address(musd), 0, data);
    }

    /// @dev a close report for `vault_` on sentinel `s`, from the CRE workflow of `owner_`, through `fwd`
    function _report(RiparSentinel s, address fwd, address owner_, address vault_, uint64 asOfBlock) internal {
        bytes memory metadata = abi.encodePacked(keccak256("some workflow"), WORKFLOW_NAME, owner_, hex"0001");
        vm.prank(fwd);
        s.onReport(metadata, abi.encode(vault_, false, uint8(9), asOfBlock));
    }

    /// @dev the device's reopen of `vault_` on sentinel `s` (P1 signature over s's own domain), relayed by anyone
    function _deviceReopen(RiparSentinel s, address vault_, uint256 nonce) internal {
        (bytes32 r, bytes32 sig) = p256Sign(DEVICE_P1_PK, s.reopenDigest(vault_, nonce));
        vm.prank(relayer);
        s.reopen(vault_, nonce, r, sig);
    }

    /// @dev pairs the device (P1 <-> K1) in registry `reg` with genuine signatures
    function _pairIn(RiparDeviceRegistry reg) internal {
        bytes32 bind = reg.bindDigest(k1, px, py);
        (bytes32 r, bytes32 s) = p256Sign(DEVICE_P1_PK, bind);
        reg.registerDevice(k1, px, py, r, s, _k1Sign(DEVICE_K1_PK, bind));
    }

    // ================================================================== INTEGRATION-2 / PERIPHERY-4 / ATTACKER-4
    // v1.1: DeployConfig built the sentinel with expectedWorkflowOwner = 0 when RIPAR_WORKFLOW_OWNER was unset, on
    // both Monad chains. Any CRE workflow the KeystoneForwarder delivers (any workflow owner) could then close any
    // vault's lane, with any asOfBlock, and close it again right after every device reopen (each reopen costs the user
    // a pulse + SIGN). v1.2: the config refuses owner 0 on 10143 and 143 (MissingWorkflowOwner), the sentinel it builds
    // refuses a stranger's workflow (BadWorkflowOwner) and a future asOfBlock (BadReport).

    /// @dev INTEGRATION-2: the Monad MAINNET config without a workflow owner.
    function test_INTEGRATION2_mainnetConfigWithoutWorkflowOwner_isRefused() public {
        Deploy script = new Deploy();
        vm.expectRevert(DeployConfig.MissingWorkflowOwner.selector);
        script.configFor(143, forwarder, address(0), address(0), address(0), address(0));

        // the config with the owner builds a sentinel that requires it
        DeployConfig.ChainConfig memory c =
            script.configFor(143, forwarder, workflowOwner, address(0), address(0), address(0));
        assertEq(c.expectedWorkflowOwner, workflowOwner);
        RiparSentinel s =
            new RiparSentinel(c.forwarder, IRiparDeviceRegistry(address(registry)), c.expectedWorkflowOwner);
        IPulseCosignEnforcer.PulseTerms memory t = _tokenTerms();
        t.sentinel = address(s);
        Delegation memory d = _mandate(t, 7);
        _approvePayee(d, 1);
        _autoTransfer(d, payee, 1e6);

        // the PoC's report: an unrelated workflow owner, asOfBlock = 2^64 - 1, for this vault and any other
        vm.expectRevert(IRiparSentinel.BadWorkflowOwner.selector);
        _report(s, c.forwarder, stranger, address(vault), type(uint64).max);
        vm.expectRevert(IRiparSentinel.BadWorkflowOwner.selector);
        _report(s, c.forwarder, stranger, makeAddr("any other vault"), uint64(block.number));
        // the genuine workflow cannot claim a future block either (it would out-rank every later reopen)
        vm.expectRevert(IRiparSentinel.BadReport.selector);
        _report(s, c.forwarder, workflowOwner, address(vault), type(uint64).max);
        assertTrue(s.laneOpen(address(vault)));
        _autoTransfer(d, payee, 1e6);

        // the genuine workflow closes; the device reopens (pulse + SIGN, once); the stranger cannot close it again
        _report(s, c.forwarder, workflowOwner, address(vault), uint64(block.number));
        vm.expectRevert(IPulseCosignEnforcer.LaneClosed.selector);
        _autoTransfer(d, payee, 1e6);
        vm.roll(block.number + 1);
        _deviceReopen(s, address(vault), 1);
        for (uint256 i; i < 3; ++i) {
            vm.roll(block.number + 1);
            vm.expectRevert(IRiparSentinel.BadWorkflowOwner.selector);
            _report(s, c.forwarder, stranger, address(vault), uint64(block.number));
        }
        _autoTransfer(d, payee, 1e6);
        assertEq(musd.balanceOf(payee), 4e6);
    }

    /// @dev PERIPHERY-4: the Monad TESTNET default config (RIPAR_WORKFLOW_OWNER unset), end to end through the deploy
    ///      script: refused without the owner; deployed with it, the sentinel at its CREATE2 address refuses the reports
    ///      of any other workflow the pinned KeystoneForwarder delivers.
    function test_PERIPHERY4_testnetConfigWithoutWorkflowOwner_isRefused() public {
        Deploy script = new Deploy();
        vm.expectRevert(DeployConfig.MissingWorkflowOwner.selector);
        script.configFor(10_143, address(0), address(0), address(0), address(0), address(0));
        vm.chainId(10_143);
        if (vm.envOr("RIPAR_WORKFLOW_OWNER", address(0)) == address(0)) {
            vm.expectRevert(DeployConfig.MissingWorkflowOwner.selector);
            script.deploy(); // the environment's config: nothing is deployed
        }

        DeployConfig.ChainConfig memory c =
            script.configFor(10_143, address(0), workflowOwner, address(0), address(0), address(0));
        Deploy.Deployment memory dep = script.deployFor(c);
        RiparSentinel s = RiparSentinel(dep.sentinel);
        assertEq(s.forwarder(), TESTNET_FORWARDER, "the pinned KeystoneForwarder");
        assertEq(s.expectedWorkflowOwner(), workflowOwner);
        _pairIn(RiparDeviceRegistry(dep.registry));

        for (uint256 i; i < 3; ++i) {
            vm.expectRevert(IRiparSentinel.BadWorkflowOwner.selector);
            _report(s, TESTNET_FORWARDER, stranger, address(vault), uint64(block.number));
            vm.roll(block.number + 1);
        }
        assertTrue(s.laneOpen(address(vault)), "a stranger's workflow cannot close the lane");

        // the genuine workflow closes once, the device reopens once, and the lane stays open
        _report(s, TESTNET_FORWARDER, workflowOwner, address(vault), uint64(block.number));
        assertFalse(s.laneOpen(address(vault)));
        vm.roll(block.number + 1);
        _deviceReopen(s, address(vault), 1);
        vm.expectRevert(IRiparSentinel.BadWorkflowOwner.selector);
        _report(s, TESTNET_FORWARDER, stranger, address(vault), uint64(block.number));
        assertTrue(s.laneOpen(address(vault)));
        assertEq(s.lastReopenNonce(address(vault)), 1, "one reopen was enough");
    }

    /// @dev ATTACKER-4: the default config on BOTH Monad chains is refused; the fixture's sentinel (built like the v1.2
    ///      config, with the workflow owner) lets no stranger's workflow close any lane. The local chain (31337) may
    ///      still omit the owner (no metadata check): a development setting only.
    function test_ATTACKER4_anyWorkflowOwner_cannotCloseAnyLane() public {
        Deploy script = new Deploy();
        vm.expectRevert(DeployConfig.MissingWorkflowOwner.selector);
        script.configFor(143, makeAddr("mainnet forwarder"), address(0), address(0), address(0), address(0));
        vm.expectRevert(DeployConfig.MissingWorkflowOwner.selector);
        script.configFor(10_143, address(0), address(0), address(0), address(0), address(0));
        assertEq(
            script.configFor(31_337, address(0), address(0), address(0), address(0), address(0)).expectedWorkflowOwner,
            address(0),
            "31337 only: no metadata check"
        );
        assertEq(sentinel.expectedWorkflowOwner(), workflowOwner, "the fixture sentinel = the v1.2 config");

        Delegation memory m = _mandate(_tokenTerms(), 15);
        _approvePayee(m, 1);
        _autoTransfer(m, payee, 1e6);
        address otherVault = makeAddr("any other vault");
        for (uint256 i; i < 3; ++i) {
            vm.expectRevert(IRiparSentinel.BadWorkflowOwner.selector);
            _reportAs(stranger, address(vault), 0, uint64(block.number));
            vm.expectRevert(IRiparSentinel.BadWorkflowOwner.selector);
            _reportAs(stranger, otherVault, 0, uint64(block.number));
            _autoTransfer(m, payee, 1e6); // no reopen (no pulse + SIGN) needed
            vm.roll(block.number + 1);
        }
        assertTrue(sentinel.laneOpen(address(vault)));
        assertTrue(sentinel.laneOpen(otherVault));
        assertEq(sentinel.lastReopenNonce(address(vault)), 0, "the device never had to reopen");
    }

    // ================================================================== INTEGRATION-4 (documented limitation)

    /// @dev INTEGRATION-4 (SPEC "DelegationManager pause"): every way a Ripar vault's funds move goes through
    ///      DelegationManager.redeemDelegations, and the canonical DelegationManager's owner (an EOA on Monad testnet)
    ///      can pause it. While paused every Ripar vault is FROZEN: no AUTO spend, no co-signed spend, no new mandate.
    ///      Funds cannot be STOLEN: the pauser is no delegate, cannot call the vault, and a paused manager redeems
    ///      nothing for anyone. The device's kill switch (revoke, panic) and the sentinel keep working, so whatever the
    ///      device kills during the pause is dead when the manager unpauses.
    function test_LIMITATION_INTEGRATION4_dmPause_freezesFunds_cannotSteal_killSwitchWorks() public {
        Delegation memory d = _mandate(_tokenTerms(), 21);
        Delegation memory d2 = _mandate(_tokenTerms(), 22);
        _approvePayee(d, 1);
        _autoTransfer(d, payee, 1e6);
        uint256 usdBefore = musd.balanceOf(address(vault));
        uint256 nativeBefore = address(vault).balance;

        address pauser = delegationManager.owner();
        vm.prank(pauser);
        delegationManager.pause();
        assertTrue(delegationManager.paused());

        // frozen: AUTO, a device co-sign, a brand-new mandate
        vm.expectRevert(Pausable.EnforcedPause.selector);
        _autoTransfer(d, payee, 1e6);
        bytes memory out = _transfer(k1, 100e6);
        (bytes memory args2,) = _signCosign(_cosign(d, address(musd), 0, out, 2));
        vm.expectRevert(Pausable.EnforcedPause.selector);
        _redeem(d, args2, address(musd), 0, out);
        (bytes memory args3,) = _signCosign(_cosign(d2, address(musd), 0, out, 1));
        vm.expectRevert(Pausable.EnforcedPause.selector);
        _redeem(d2, args3, address(musd), 0, out);

        // not stolen: the pauser has no path to the funds
        bytes memory steal = _transfer(pauser, VAULT_MUSD);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        _redeemAs(pauser, d, "", address(musd), 0, steal);
        vm.expectRevert(DeleGatorCore.NotEntryPoint.selector);
        vm.prank(pauser);
        vault.execute(Execution({ target: address(musd), value: 0, callData: steal }));
        vm.expectRevert(DeleGatorCore.NotDelegationManager.selector);
        vm.prank(pauser);
        vault.executeFromExecutor(ModeLib.encodeSimpleSingle(), ExecutionLib.encodeSingle(address(musd), 0, steal));
        vm.expectRevert(DeleGatorCore.NotEntryPointOrSelf.selector);
        vm.prank(pauser);
        vault.transferOwnership(pauser);

        // the device's kill switch and the sentinel still work while the manager is paused
        _revoke(_hash(d2));
        assertTrue(enforcer.isRevoked(keyId, _hash(d2)));
        _panic(1);
        assertEq(enforcer.minEpoch(keyId), 1);
        _closeLane(1, uint64(block.number));
        vm.roll(block.number + 1);
        _reopen(1);
        assertTrue(sentinel.laneOpen(address(vault)));
        assertEq(musd.balanceOf(address(vault)), usdBefore, "frozen, not stolen (mUSD)");
        assertEq(address(vault).balance, nativeBefore, "frozen, not stolen (MON)");

        // unpaused: what the device killed during the pause stays dead
        vm.prank(pauser);
        delegationManager.unpause();
        vm.expectRevert(IPulseCosignEnforcer.StaleEpoch.selector);
        _autoTransfer(d, payee, 1e6);
        vm.expectRevert(IPulseCosignEnforcer.DelegationRevoked.selector);
        _redeem(d2, args3, address(musd), 0, out);
        // and a fresh epoch-1 mandate moves the funds again, with the device
        IPulseCosignEnforcer.PulseTerms memory t1 = _tokenTerms();
        t1.epoch = 1;
        Delegation memory fresh = _mandate(t1, 23);
        (bytes memory args4,) = _signCosign(_cosign(fresh, address(musd), 0, out, 1));
        _redeem(fresh, args4, address(musd), 0, out);
        assertEq(musd.balanceOf(address(vault)), usdBefore - 100e6);
        assertEq(musd.balanceOf(k1), 100e6, "the owner withdrew with a device co-sign");
    }

    // ================================================================== ATTACKER-6 (documented)

    /// @dev ATTACKER-6: the vault is companion-supplied at pairing. A genuine HybridDeleGator implementation whose
    ///      immutable DelegationManager is an attacker's contract looks exactly like the user's vault to every Ripar
    ///      contract (owner() = K1; the registry maps that owner to the device; the device's reopen works on it), yet
    ///      the fake manager moves its funds with no mandate, no caveat and no co-sign. The contracts cannot prevent
    ///      this: a vault is only as trustworthy as its DelegationManager (SPEC "Vault choice"). PENDING FIRMWARE v1.2,
    ///      which derives the vault address from K1 (canonical SimpleFactory + HybridDeleGator implementation) and so
    ///      refuses to pair such a vault. This test pins today's contract behaviour, and that the fake manager has no
    ///      power over a vault of the canonical DelegationManager.
    function test_DOCUMENTED_ATTACKER6_companionVaultWithFakeDelegationManager() public {
        FakeDelegationManager fakeDm = new FakeDelegationManager();
        HybridDeleGator fakeImpl = new HybridDeleGator(IDelegationManager(address(fakeDm)), entryPoint);
        bytes memory init =
            abi.encodeCall(HybridDeleGator.initialize, (k1, new string[](0), new uint256[](0), new uint256[](0)));
        HybridDeleGator fakeVault = HybridDeleGator(payable(address(new ERC1967Proxy(address(fakeImpl), init))));
        assertEq(fakeVault.owner(), k1, "owned by the device's K1, like the real vault");
        assertEq(address(fakeVault.delegationManager()), address(fakeDm), "but bound to another DelegationManager");
        musd.faucet(address(fakeVault), 1_000e6); // the user funds the vault the companion paired

        // every Ripar surface accepts it: the registry maps its owner to this device, and the device reopens its lane
        assertEq(registry.keyIdOf(fakeVault.owner()), keyId);
        _reportAs(workflowOwner, address(fakeVault), 1, uint64(block.number));
        vm.roll(block.number + 1);
        _deviceReopen(sentinel, address(fakeVault), 1);
        assertTrue(sentinel.laneOpen(address(fakeVault)));

        // the fake manager drains it: no delegation, no Pulse caveat, no device co-sign
        address thief = makeAddr("thief");
        fakeDm.drain(fakeVault, address(musd), thief, 1_000e6);
        assertEq(musd.balanceOf(thief), 1_000e6, "CURRENT BEHAVIOUR: drained (firmware v1.2 refuses such a vault)");
        assertEq(musd.balanceOf(address(fakeVault)), 0);

        // it has no power over a vault of the canonical DelegationManager
        vm.expectRevert(DeleGatorCore.NotDelegationManager.selector);
        fakeDm.drain(vault, address(musd), thief, 1);
        assertEq(musd.balanceOf(address(vault)), VAULT_MUSD);
    }

    // ================================================================== PROTOCOL-5 (documented, firmware-side)

    /// @dev PROTOCOL-5: the device promises "every mandate the device signed is killed by its next panic". A panic is
    ///      per enforcer (its EIP-712 domain names the enforcer), so once the device re-paired to ANOTHER
    ///      PulseCosignEnforcer (allowed after a revoke of its last mandate), an older, never-revoked mandate on the
    ///      first enforcer survives every panic the device then signs. The second enforcer cannot see the first one's
    ///      mandates, so no contract change fixes this; firmware v1.2 pins the enforcer's CREATE2 address, so a re-pair
    ///      can no longer move the device to another enforcer. This test pins today's contract behaviour, and that a
    ///      panic signed for the enforcer holding the mandate still kills it.
    function test_DOCUMENTED_PROTOCOL5_panicOnOtherEnforcer_missesOlderMandate() public {
        Delegation memory m1 = _mandate(_tokenTerms(), SALT); // mandate #1 (the device forgets it when #2 is signed)
        Delegation memory m2 = _mandate(_tokenTerms(), SALT + 1); // mandate #2 = lastDelegationHash
        _approvePayee(m1, 1);
        _revoke(_hash(m2)); // device REVOKE of #2; lastDelegationHash = 0, so a re-pair is allowed

        // re-paired to a second enforcer E2: the device's next PANIC is signed for E2 only
        PulseCosignEnforcer e2 = new PulseCosignEnforcer();
        bytes32 digest =
            _digest(_domain("RiparPulseCosign", address(e2)), keccak256(abi.encode(PANIC_TYPEHASH, uint64(1))));
        assertEq(digest, e2.panicDigest(1));
        assertTrue(digest != enforcer.panicDigest(1), "a panic names its enforcer");
        (bytes32 r, bytes32 s) = p256Sign(DEVICE_P1_PK, digest);
        e2.panic(px, py, 1, r, s);
        assertEq(e2.minEpoch(keyId), 1);
        assertEq(enforcer.minEpoch(keyId), 0, "the first enforcer never saw the panic");
        vm.expectRevert(IPulseCosignEnforcer.BadSignature.selector);
        enforcer.panic(px, py, 1, r, s); // E2's panic signature means nothing to the first enforcer

        // CURRENT BEHAVIOUR: mandate #1 (epoch 0) still runs on the first enforcer
        _autoTransfer(m1, payee, PER_TX);
        assertEq(musd.balanceOf(payee), 1e6 + PER_TX);

        // a panic signed for the enforcer that holds the mandate kills it (what the pinned enforcer guarantees)
        _panic(1);
        vm.expectRevert(IPulseCosignEnforcer.StaleEpoch.selector);
        _autoTransfer(m1, payee, 1);
    }

    // ================================================================== PROTOCOL-4 (documented limitation)

    /// @dev PROTOCOL-4 (SPEC "AUTO windows"): "Period: 0" on the device is a lifetime cap on chain (it never resets).
    function test_LIMITATION_PROTOCOL4_periodZero_isLifetimeCap() public {
        IPulseCosignEnforcer.PulseTerms memory t = _tokenTerms();
        t.period = 0;
        Delegation memory mandate = _mandate(t, SALT);
        _approvePayee(mandate, 1);
        _autoTransfer(mandate, payee, PER_TX);
        _autoTransfer(mandate, payee, PER_TX);
        vm.warp(block.timestamp + 3650 days);
        (uint256 spent, uint256 remaining,, uint64 end) =
            enforcer.autoBudget(address(delegationManager), _hash(mandate), mandate.caveats[0].terms);
        assertEq(spent, PERIOD_CAP);
        assertEq(remaining, 0);
        assertEq(end, 0, "the window never ends");
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(mandate, payee, 1);
    }

    /// @dev PROTOCOL-4 (SPEC "AUTO windows"): windows are fixed and anchored at the first AUTO spend, so up to twice
    ///      periodAutoCap can leave within seconds across a window boundary; never more than the cap in one window.
    function test_LIMITATION_PROTOCOL4_fixedWindow_upToTwiceTheCapAcrossABoundary() public {
        Delegation memory mandate = _mandate(_tokenTerms(), SALT);
        _approvePayee(mandate, 1);
        _autoTransfer(mandate, payee, 1); // anchors the window at T0
        vm.warp(T0 + PERIOD - 1);
        uint256 before = musd.balanceOf(payee);
        _autoTransfer(mandate, payee, PER_TX);
        _autoTransfer(mandate, payee, PER_TX - 1); // the window's total is now exactly the cap
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(mandate, payee, 1);
        vm.warp(T0 + PERIOD); // one second later: a fresh window
        _autoTransfer(mandate, payee, PER_TX);
        _autoTransfer(mandate, payee, PER_TX);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoTransfer(mandate, payee, 1);
        assertEq(musd.balanceOf(payee) - before, 2 * PERIOD_CAP - 1, "~2x the per-period cap within 1 second");
    }
}

/// @notice The same suite with a P256VERIFY precompile at 0x0100 (like Monad): OpenZeppelin P256 takes its native path.
contract SystemRegressionPrecompileTest is SystemRegressionTest {
    function setUp() public override {
        etchP256Precompile();
        super.setUp();
    }

    function test_precompileIsUsed() public {
        vm.expectCall(P256_PRECOMPILE, bytes(""));
        _approvePayee(_mandate(_tokenTerms(), 99), 1);
    }
}

/// @notice OPT-IN: the same suite on a fork of Monad testnet (10143) against the CANONICAL MetaMask DelegationManager
///         v1.3.0 (0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3) and its REAL owner (INTEGRATION-4 pauses it on the local
///         fork only). Read-only RPC. Skipped unless MONAD_TESTNET_RPC_URL is set, e.g.
///           MONAD_TESTNET_RPC_URL=https://testnet-rpc.monad.xyz forge test --mc SystemRegressionForkTest
contract SystemRegressionForkTest is SystemRegressionTest {
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
    }

    function _delegationManager() internal view override returns (DelegationManager dm) {
        dm = DelegationManager(CANONICAL_DELEGATION_MANAGER);
        assertEq(dm.VERSION(), "1.3.0");
        assertFalse(dm.paused());
    }

    /// @dev SPEC "DelegationManager pause": the canonical manager's owner, read from the live chain, is an EOA (no code).
    function test_fork_INTEGRATION4_canonicalManagerOwner_isAnEOA() public view {
        address owner = delegationManager.owner();
        assertTrue(owner != address(0));
        assertEq(owner.code.length, 0, "an EOA can pause every Ripar vault (frozen, not stolen)");
    }
}
