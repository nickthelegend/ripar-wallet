// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import { Vm } from "forge-std/Vm.sol";
// imported only so that its artifact exists for deployCodeTo
// forge-lint: disable-next-line(unused-import)
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { IEntryPoint } from "@account-abstraction/interfaces/IEntryPoint.sol";
import { ModeLib, ModeCode } from "@erc7579/lib/ModeLib.sol";
import { ExecutionLib } from "@erc7579/lib/ExecutionLib.sol";
import { DelegationManager } from "@delegation-framework/DelegationManager.sol";
import { HybridDeleGator } from "@delegation-framework/HybridDeleGator.sol";
import { IDelegationManager } from "@delegation-framework/interfaces/IDelegationManager.sol";
import { ICaveatEnforcer } from "@delegation-framework/interfaces/ICaveatEnforcer.sol";
import { Delegation } from "@delegation-framework/utils/Types.sol";
import { TimestampEnforcer } from "@delegation-framework/enforcers/TimestampEnforcer.sol";

import { IPulseCosignEnforcer } from "../src/interfaces/IPulseCosignEnforcer.sol";
import { IRiparDeviceRegistry } from "../src/interfaces/IRiparDeviceRegistry.sol";
import { IRiparSentinel } from "../src/interfaces/IRiparSentinel.sol";
import { IRiparReputationRelay } from "../src/interfaces/IRiparReputationRelay.sol";
import { P256TestUtils } from "./utils/P256TestUtils.sol";
import { DeviceVectors } from "./utils/conformance/DeviceVectors.sol";
import { MockERC8004Identity, MockERC8004Reputation, MockOwnedVault } from "./utils/conformance/ConformanceMocks.sol";

/// @dev SPEC.md MockUSD: a public faucet, at most 1_000e6 per call.
interface IMockUSDFaucet {
    function faucet(address to, uint256 amount) external;
}

/// @title DeviceConformanceTest
/// @notice Checks the Ripar contracts against what the device firmware actually produces. The vectors
///         (test/vectors/device_vectors.json) come from test/vectors/gen_device_vectors.py, which drives the firmware's
///         own protocol reference firmware/tools/make_request.py (demo device, DEMO_SEED = sha256("ripar demo seed"))
///         through request -> CBOR/UR -> simulate -> parse. Every contract is deployed at the vector's fixed address on
///         chain 10143 (the real MetaMask DelegationManager v1.3.0 bytecode at its real address), so every EIP-712
///         domain matches the one the device signed under.
///         Every check runs twice: with OpenZeppelin P256's Solidity fallback (no precompile, as in a plain local EVM)
///         and with the RIP-7212 / EIP-7951 precompile at 0x0100 (mocked, as on Monad).
///         Covered: pairing, the mandate (one caveat, and pulse + MetaMask TimestampEnforcer after a lost-context
///         re-pair with the floors of pairing keys 10 / 11), co-signs of all four call shapes the device decodes (native,
///         transfer, approve, transferFrom), the firmware's ERC-20 decode table against the enforcer's decode, both deny
///         paths (from a co-sign review and ripar-deny-req), revoke, panic and reopen, end to end through the real
///         DelegationManager and a HybridDeleGator vault.
///         SPEC v1.1: every enforcer record is keyed by the DelegationManager that called beforeHook (A.dm, the
///         canonical v1.3.0 address the firmware pins), known payees are per mandate, and only an approval's redeemer
///         can attest it with the relay (built for A.dm).
///         SPEC v1.2: a co-sign whitelists its payee only when the call is meterable under the mandate (a native send
///         with value > 0 under a native mandate; a `transfer` of the mandate's token with value 0) with a non-zero
///         amount and payee, so the vectors' native co-sign under the mUSD mandate no longer whitelists; a co-sign
///         nonce is single-use per (DelegationManager, mandate); the relay credits an approval only when the device key
///         is registered to the vault's owner() (so the device is paired before every attestation) and records denials
///         of a shielded agent without feedback; the sentinel (deployed, like the v1.2 deploy config, with a CRE
///         workflow owner) reopens only a closed lane. The vectors are unchanged: the few v1.2 scenarios that need a
///         signature the device vectors do not carry (the same request re-signed with the same nonce, the decode table
///         under other terms) are signed in the test with the demo P1 key, like the existing decode table.
contract DeviceConformanceTest is P256TestUtils, DeviceVectors {
    bytes10 internal constant WORKFLOW_NAME = "ripar-risk";
    /// @dev firmware Erc20Call::Kind (erc20Decode.kinds in the vectors)
    uint256 internal constant KIND_NONE = 0;
    uint256 internal constant KIND_TRANSFER = 1;
    uint256 internal constant KIND_UNKNOWN = 4;

    Addrs internal A;
    Demo internal D;
    Domains internal doms;
    uint256 internal nowTs;
    uint256 internal agentId;

    IPulseCosignEnforcer internal enforcer;
    IRiparDeviceRegistry internal registry;
    IRiparSentinel internal sentinel;
    IRiparReputationRelay internal relay;
    DelegationManager internal dm;
    MockERC8004Identity internal identity;
    MockERC8004Reputation internal reputation;
    address internal forwarder;
    address internal agentOwner;

    function setUp() public {
        string memory j = _json();
        A = _loadAddrs(j);
        D = _loadDemo(j);
        doms = _loadDomains(j);
        nowTs = _u(j, ".now");
        agentId = _u(j, ".mandate.agentId");

        // chain id first: every EIP712 constructor caches block.chainid
        vm.chainId(_u(j, ".chainId"));
        vm.warp(nowTs);
        vm.roll(1_000);

        forwarder = makeAddr("creForwarder");
        agentOwner = makeAddr("agentOwner");
        identity = new MockERC8004Identity();
        reputation = new MockERC8004Reputation(identity);
        identity.setOwner(agentId, agentOwner);
        identity.setOperator(agentId, A.agent, true); // the agent's redeemer key acts for the agent

        deployCodeTo("DelegationManager.sol:DelegationManager", abi.encode(makeAddr("dmOwner")), A.dm);
        deployCodeTo("RiparDeviceRegistry.sol:RiparDeviceRegistry", A.registry);
        deployCodeTo("PulseCosignEnforcer.sol:PulseCosignEnforcer", A.enforcer);
        // v1.2 deploy config: the sentinel requires the CRE workflow owner (the EIP-712 domain only depends on the
        // address and the chain, so the vectors' reopen signatures stay valid)
        deployCodeTo(
            "RiparSentinel.sol:RiparSentinel", abi.encode(forwarder, A.registry, makeAddr("workflowOwner")), A.sentinel
        );
        deployCodeTo(
            "RiparReputationRelay.sol:RiparReputationRelay",
            abi.encode(address(reputation), address(identity), A.enforcer, A.registry, A.dm),
            A.relay
        );
        deployCodeTo("MockUSD.sol:MockUSD", A.token);
        deployCodeTo("ConformanceMocks.sol:MockOwnedVault", abi.encode(D.k1), A.vault);
        // the MetaMask v1.3.0 enforcer the re-paired mandate adds, at its real (pinned) address
        deployCodeTo("TimestampEnforcer.sol:TimestampEnforcer", A.timestampEnforcer);

        dm = DelegationManager(A.dm);
        enforcer = IPulseCosignEnforcer(A.enforcer);
        registry = IRiparDeviceRegistry(A.registry);
        sentinel = IRiparSentinel(A.sentinel);
        relay = IRiparReputationRelay(A.relay);

        vm.label(A.dm, "DelegationManager");
        vm.label(A.enforcer, "PulseCosignEnforcer");
        vm.label(A.registry, "RiparDeviceRegistry");
        vm.label(A.sentinel, "RiparSentinel");
        vm.label(A.relay, "RiparReputationRelay");
        vm.label(A.vault, "vault");
        vm.label(A.agent, "agent");
        vm.label(A.token, "MockUSD");
        vm.label(A.payee, "payee");
        vm.label(A.spender, "spender");
        vm.label(A.holder, "holder");
        vm.label(A.payee2, "payee2");
        vm.label(A.timestampEnforcer, "TimestampEnforcer");
    }

    // ================================================================================================ test matrix
    // *_Solidity: OZ P256 Solidity fallback (no code at 0x0100). *_Precompile: mocked precompile at 0x0100, and the
    // test also asserts the precompile was actually called.

    function test_DomainsAndKeys_Solidity() public view {
        _checkDomainsAndKeys();
    }

    function test_DomainsAndKeys_Precompile() public {
        etchP256Precompile();
        _checkDomainsAndKeys();
    }

    function test_Mandate_DelegationManager_Solidity() public view {
        _checkMandate();
    }

    function test_Mandate_DelegationManager_Precompile() public {
        etchP256Precompile();
        _checkMandate();
    }

    function test_Terms_Solidity() public view {
        _checkTerms();
    }

    function test_Terms_Precompile() public {
        etchP256Precompile();
        _checkTerms();
    }

    function test_Pair_Solidity() public {
        _checkPair();
    }

    function test_Pair_Precompile() public {
        _usePrecompile();
        _checkPair();
    }

    function test_CosignErc20_Solidity() public {
        _checkCosign(".cosignErc20");
    }

    function test_CosignErc20_Precompile() public {
        _usePrecompile();
        _checkCosign(".cosignErc20");
    }

    function test_CosignNative_Solidity() public {
        _checkCosign(".cosignNative");
    }

    function test_CosignNative_Precompile() public {
        _usePrecompile();
        _checkCosign(".cosignNative");
    }

    function test_CosignApprove_Solidity() public {
        _checkCosign(".cosignApprove");
    }

    function test_CosignApprove_Precompile() public {
        _usePrecompile();
        _checkCosign(".cosignApprove");
    }

    function test_CosignTransferFrom_Solidity() public {
        _checkCosign(".cosignTransferFrom");
    }

    function test_CosignTransferFrom_Precompile() public {
        _usePrecompile();
        _checkCosign(".cosignTransferFrom");
    }

    function test_Erc20DecodeTable_Solidity() public {
        _checkErc20DecodeTable();
    }

    function test_Erc20DecodeTable_Precompile() public {
        _usePrecompile();
        _checkErc20DecodeTable();
    }

    function test_Deny_Solidity() public {
        _checkDeny();
    }

    function test_Deny_Precompile() public {
        _usePrecompile();
        _checkDeny();
    }

    function test_DenyRequest_Solidity() public {
        _checkDenyRequest();
    }

    function test_DenyRequest_Precompile() public {
        _usePrecompile();
        _checkDenyRequest();
    }

    function test_DenyShielded_Solidity() public {
        _checkDenyShielded();
    }

    function test_DenyShielded_Precompile() public {
        _usePrecompile();
        _checkDenyShielded();
    }

    function test_Revoke_Solidity() public {
        _checkRevoke();
    }

    function test_Revoke_Precompile() public {
        _usePrecompile();
        _checkRevoke();
    }

    function test_Panic_Solidity() public {
        _checkPanic();
    }

    function test_Panic_Precompile() public {
        _usePrecompile();
        _checkPanic();
    }

    function test_Reopen_Solidity() public {
        _checkReopen();
    }

    function test_Reopen_Precompile() public {
        _usePrecompile();
        _checkReopen();
    }

    function test_RedeemHuman_Solidity() public {
        _checkRedeemHuman();
    }

    function test_RedeemHuman_Precompile() public {
        _usePrecompile();
        _checkRedeemHuman();
    }

    function test_RedeemAutoAndKillSwitch_Solidity() public {
        _checkRedeemAutoAndKillSwitch();
    }

    function test_RedeemAutoAndKillSwitch_Precompile() public {
        _usePrecompile();
        _checkRedeemAutoAndKillSwitch();
    }

    function test_RedeemApproveAndTransferFrom_Solidity() public {
        _checkRedeemApproveAndTransferFrom();
    }

    function test_RedeemApproveAndTransferFrom_Precompile() public {
        _usePrecompile();
        _checkRedeemApproveAndTransferFrom();
    }

    function test_LostContextRepair_Solidity() public {
        _checkLostContextRepair();
    }

    function test_LostContextRepair_Precompile() public {
        _usePrecompile();
        _checkLostContextRepair();
    }

    // ================================================================================================ checks
    /// @dev Demo keys (Foundry's secp256k1 / P-256 agree with the firmware derivation), keyId, every EIP-712 domain.
    function _checkDomainsAndKeys() internal view {
        assertEq(vm.addr(D.k1PrivateKey), D.k1, "demo K1 address");
        (bytes32 x, bytes32 y) = p256Key(D.p1PrivateKey);
        assertEq(x, D.px, "demo P1 x");
        assertEq(y, D.py, "demo P1 y");
        assertEq(p256KeyId(D.px, D.py), D.keyId, "keyId = keccak256(abi.encode(px, py))");
        assertEq(enforcer.keyIdOf(D.px, D.py), D.keyId, "enforcer.keyIdOf");

        assertEq(dm.getDomainHash(), doms.dm, "DelegationManager domain");
        assertEq(enforcer.domainSeparator(), doms.enforcer, "RiparPulseCosign domain");
        assertEq(registry.domainSeparator(), doms.registry, "RiparDeviceRegistry domain");
        assertEq(sentinel.domainSeparator(), doms.sentinel, "RiparSentinel domain");
        assertEq(relay.domainSeparator(), doms.relay, "RiparReputationRelay domain");
        assertEq(relay.delegationManager(), A.dm, "the relay credits the pinned DelegationManager only");

        // a key the device never signs with must not collide
        (bytes32 ox, bytes32 oy) = p256Key(0xA11CE);
        assertTrue(enforcer.keyIdOf(ox, oy) != D.keyId, "other key, other keyId");
    }

    /// @dev ripar-mandate-req -> eth-signature: the real DelegationManager hashes the mandate exactly like the device
    ///      and the K1 signature recovers the demo owner under the DelegationManager's own domain.
    function _checkMandate() internal view {
        MandateV memory m = _loadMandate(_json());
        assertEq(m.delegate, A.agent, "delegate");
        assertEq(m.delegator, A.vault, "delegator");
        assertEq(m.authority, bytes32(type(uint256).max), "ROOT authority");
        assertEq(m.enforcers.length, 1, "one caveat");
        assertEq(m.pulseIndex, 0, "the pulse caveat");
        assertEq(m.enforcers[0], A.enforcer, "caveat enforcer");
        assertEq(m.terms[0], m.termsHex, "caveat terms");

        bytes32 h = dm.getDelegationHash(_delegation(m, ""));
        assertEq(h, m.delegationHash, "DelegationManager.getDelegationHash == device delegationHash");
        // caveat args and the signature are not hashed (the relayer adds the co-sign args later)
        assertEq(dm.getDelegationHash(_delegation(m, hex"c0ffee")), h, "args not hashed");

        bytes32 digest = MessageHashUtils.toTypedDataHash(dm.getDomainHash(), h);
        assertEq(digest, m.digest, "mandate digest");
        assertEq(ECDSA.recover(m.digest, m.signature), D.k1, "mandate K1 signature recovers the demo owner");
        assertEq(m.signature.length, 65, "r||s||v");
        uint8 v = uint8(m.signature[64]);
        assertTrue(v == 27 || v == 28, "v = 27/28");
    }

    /// @dev The pulse caveat terms the device signed decode to exactly the fields it displayed.
    function _checkTerms() internal view {
        MandateV memory m = _loadMandate(_json());
        assertEq(m.termsHex.length, 288, "288 bytes");
        assertEq(abi.encode(m.t), m.termsHex, "abi.encode(PulseTerms) == device terms");

        IPulseCosignEnforcer.PulseTerms memory t = enforcer.getTermsInfo(m.termsHex);
        assertEq(t.px, m.t.px, "px");
        assertEq(t.py, m.t.py, "py");
        assertEq(t.token, m.t.token, "token");
        assertEq(t.perTxAutoCap, m.t.perTxAutoCap, "perTxAutoCap");
        assertEq(t.periodAutoCap, m.t.periodAutoCap, "periodAutoCap");
        assertEq(t.period, m.t.period, "period");
        assertEq(t.epoch, m.t.epoch, "epoch");
        assertEq(t.newPayeeNeedsHuman, m.t.newPayeeNeedsHuman, "newPayeeNeedsHuman");
        assertEq(t.sentinel, m.t.sentinel, "sentinel");

        // the scenario: the device's own P1 key, MockUSD, the pinned sentinel, epoch = a new device's floor (0)
        assertEq(t.px, D.px, "terms name the device P1 x");
        assertEq(t.py, D.py, "terms name the device P1 y");
        assertEq(t.token, A.token, "metered token = MockUSD");
        assertEq(t.sentinel, A.sentinel, "pinned sentinel");
        assertEq(t.epoch, 0, "epoch = device floor");
        assertTrue(t.newPayeeNeedsHuman, "new payees need a human");
    }

    /// @dev ripar-pair: the BindDevice P1 + K1 signatures register the device.
    function _checkPair() internal {
        PairV memory p = _loadPair(_json());
        assertEq(p.owner, D.k1, "owner = K1");
        assertEq(p.px, D.px, "px");
        assertEq(p.py, D.py, "py");
        assertEq(p.keyId, D.keyId, "keyId");
        assertEq(registry.bindDigest(p.owner, p.px, p.py), p.digest, "bindDigest == device digest");
        assertEq(ECDSA.recover(p.digest, p.k1Signature), p.owner, "K1 signature recovers the owner");

        // the malleable twin of the device's P1 signature is refused (the device always sends low-s)
        vm.expectRevert(IRiparDeviceRegistry.BadDeviceSignature.selector);
        registry.registerDevice(p.owner, p.px, p.py, p.r, p256HighS(p.s), p.k1Signature);

        vm.expectEmit(true, true, false, true, A.registry);
        emit IRiparDeviceRegistry.DeviceRegistered(p.owner, p.keyId, p.px, p.py);
        bytes32 keyId = registry.registerDevice(p.owner, p.px, p.py, p.r, p.s, p.k1Signature);
        assertEq(keyId, p.keyId, "registerDevice returns the keyId");
        assertEq(registry.keyIdOf(p.owner), p.keyId, "keyIdOf(owner)");
        (bytes32 x, bytes32 y, address o) = registry.keyOf(p.keyId);
        assertEq(x, p.px, "keyOf.px");
        assertEq(y, p.py, "keyOf.py");
        assertEq(o, p.owner, "keyOf.owner");

        // relaying the same pairing QR again is a no-op success
        assertEq(registry.registerDevice(p.owner, p.px, p.py, p.r, p.s, p.k1Signature), p.keyId, "idempotent");
    }

    /// @dev ripar-cosign: HumanApproval digest, caveat args layout and the enforcer's HUMAN path, then the ERC-8004
    ///      approval verdict for the consumed co-signature.
    function _checkCosign(string memory key) internal {
        string memory j = _json();
        MandateV memory m = _loadMandate(j);
        CosignV memory c = _loadCosign(j, key);

        assertEq(c.delegationHash, m.delegationHash, "co-sign names the signed mandate");
        assertEq(c.delegator, m.delegator, "delegator");
        assertEq(c.redeemer, m.delegate, "redeemer");
        assertEq(keccak256(c.callData), c.callDataHash, "callDataHash");
        assertEq(_structHash(c, c.presenceHash), c.structHash, "approvalStructHash");
        assertEq(_structHash(c, bytes32(0)), c.requestHash, "approvalStructHash(presence 0) == requestHash");
        assertEq(_approvalDigest(c), c.digest, "approvalDigest == device digest");
        assertEq(MessageHashUtils.toTypedDataHash(doms.enforcer, c.structHash), c.digest, "0x1901 || domain || struct");
        assertEq(c.args.length, 160, "HUMAN args are 160 bytes");
        assertEq(c.args, abi.encode(c.nonce, c.expiry, c.presenceHash, c.r, c.s), "args layout");

        // expired: block.timestamp > expiry
        vm.warp(uint256(c.expiry) + 1);
        vm.expectRevert(IPulseCosignEnforcer.CosignExpired.selector);
        _humanHook(m.termsHex, c.args, c);
        vm.warp(nowTs);

        // the malleable twin of the device signature is refused
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _humanHook(m.termsHex, abi.encode(c.nonce, c.expiry, c.presenceHash, c.r, p256HighS(c.s)), c);
        // a different presenceHash (evidence not bound) is refused
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _humanHook(m.termsHex, abi.encode(c.nonce, c.expiry, bytes32(0), c.r, c.s), c);

        // anyone who sees the device's args can call beforeHook directly, but that only consumes them (and their
        // nonce, v1.2) for the caller (v1.1): nothing the relay credits, nothing burnt for the DelegationManager
        address griefer = makeAddr("griefer");
        vm.prank(griefer);
        ICaveatEnforcer(A.enforcer)
            .beforeHook(
                m.termsHex,
                c.args,
                ModeLib.encodeSimpleSingle(),
                ExecutionLib.encodeSingle(c.target, c.value, c.callData),
                c.delegationHash,
                c.delegator,
                c.redeemer
            );
        assertTrue(enforcer.consumed(griefer, c.digest), "consumed for the direct caller only");
        assertFalse(enforcer.consumed(A.dm, c.digest), "not for the DelegationManager");
        assertTrue(enforcer.nonceUsed(griefer, c.delegationHash, c.nonce), "nonce used for the direct caller only");
        assertFalse(enforcer.nonceUsed(A.dm, c.delegationHash, c.nonce), "nonce still free for the DelegationManager");
        vm.expectRevert(IRiparReputationRelay.NotConsumed.selector);
        vm.prank(c.redeemer);
        relay.attestApproval(m.agentId, c.digest);

        // the device's co-signature passes for the DelegationManager
        bool whitelists = _v12Whitelists(m.t, c.target, c.value, c.callData, c.payee, c.amount);
        vm.recordLogs();
        vm.expectEmit(true, true, true, true, A.enforcer);
        emit IPulseCosignEnforcer.HumanCosigned(
            c.delegationHash, c.delegator, c.redeemer, A.dm, c.payee, c.amount, D.keyId, c.digest, c.presenceHash
        );
        _humanHook(m.termsHex, c.args, c);
        assertEq(_payeeApprovedCount(vm.getRecordedLogs()), whitelists ? 1 : 0, "PayeeApproved iff whitelisted");

        assertTrue(enforcer.consumed(A.dm, c.digest), "consumed");
        IPulseCosignEnforcer.Approval memory ap = enforcer.approvalOf(A.dm, c.digest);
        assertEq(ap.keyId, D.keyId, "approval.keyId");
        assertEq(ap.delegationHash, c.delegationHash, "approval.delegationHash");
        assertEq(ap.delegator, c.delegator, "approval.delegator");
        assertEq(ap.redeemer, c.redeemer, "approval.redeemer");
        assertEq(ap.payee, c.payee, "approval.payee");
        assertEq(ap.timestamp, block.timestamp, "approval.timestamp");
        // v1.2: only a call meterable under the mandate (here: a transfer of the mUSD it meters, value 0) with a
        // non-zero amount and payee whitelists its payee, for this mandate. The native co-sign under the mUSD
        // mandate, approve and transferFrom do not.
        assertEq(
            enforcer.isKnownPayee(A.dm, c.delegationHash, c.payee), whitelists, "known payee: meterable, amount > 0"
        );
        assertEq(whitelists, bytes4(c.callData) == IERC20.transfer.selector, "of the four shapes only transfer here");
        (uint256 spent,) = enforcer.periodSpent(A.dm, c.delegationHash);
        assertEq(spent, 0, "HUMAN spends do not count toward the AUTO period");
        assertTrue(enforcer.nonceUsed(A.dm, c.delegationHash, c.nonce), "v1.2: nonce used");

        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
        _humanHook(m.termsHex, c.args, c);

        // ERC-8004 approval verdict for the consumed digest: only its redeemer may file it (v1.1), for an agent it is
        // authorized for (the mandate's agentId)
        vm.expectRevert(IRiparReputationRelay.NotRedeemer.selector);
        relay.attestApproval(m.agentId, c.digest);
        vm.expectRevert(IRiparReputationRelay.NotRedeemer.selector);
        vm.prank(agentOwner);
        relay.attestApproval(m.agentId, c.digest);
        // v1.2: only once the device is paired (its P1 registered to K1, the vault's owner) does the approval count
        vm.expectRevert(IRiparReputationRelay.UnknownDevice.selector);
        vm.prank(c.redeemer);
        relay.attestApproval(m.agentId, c.digest);
        _registerDevice();
        assertEq(MockOwnedVault(A.vault).owner(), D.k1, "vault owner = the registered key's owner");
        vm.expectEmit(true, true, false, true, A.relay);
        emit IRiparReputationRelay.Verdict(m.agentId, D.keyId, c.digest, true);
        vm.prank(c.redeemer);
        relay.attestApproval(m.agentId, c.digest);
        assertTrue(relay.approvalAttested(c.digest), "approvalAttested");
        _assertLastFeedback(m.agentId, 1, "cosigned", c.digest);
        vm.expectRevert(IRiparReputationRelay.AlreadyAttested.selector);
        vm.prank(c.redeemer);
        relay.attestApproval(m.agentId, c.digest);
    }

    /// @dev The firmware's own ERC-20 decode known answers (firmware/test/host/vectors_eip712_abi.h ERC20S, the table the
    ///      C++ abi_decode_erc20 is host-tested against) against the enforcer's decode. For every calldata the device
    ///      decodes (native send, transfer, approve, transferFrom) the enforcer must record exactly the payee and the
    ///      amount the device showed; every calldata the device calls UNKNOWN CALLDATA must be unmetered for the enforcer
    ///      (payee 0, amount = the native value). The device never signs the UNKNOWN entries: the demo P1 key signs
    ///      every entry here only so that the HUMAN path runs and reports the enforcer's decode in HumanCosigned.
    ///      SPEC v1.2 known payees, three passes: (1) every entry under the vectors' mUSD mandate (ERC-20 calls on
    ///      mUSD, native sends of 1 MON): only transfers with a non-zero amount and `to` whitelist, native sends do
    ///      not; (2) the native send and every transfer entry again on a token the mandate does not meter: nothing
    ///      whitelists; (3) the same entries under a native mandate (terms token 0, same device key): only the native
    ///      send whitelists.
    function _checkErc20DecodeTable() internal {
        string memory j = _json();
        MandateV memory m = _loadMandate(j);
        Erc20DecodeV[] memory v = _loadErc20Decode(j);
        assertGt(v.length, 40, "firmware table loaded");
        DecodeRun memory run = DecodeRun({
            terms: m.t,
            termsHex: m.termsHex,
            delegationHash: m.delegationHash,
            erc20Target: A.token,
            expiry: _loadCosign(j, ".cosignErc20").expiry, // the device's one-hour co-sign window
            nonceBase: 1_000
        });
        uint256[5] memory seen;
        uint256 whitelisted;
        for (uint256 i; i < v.length; ++i) {
            seen[v[i].kind]++;
            if (_decodeEntry(run, v[i], i)) ++whitelisted;
        }
        for (uint256 k; k < 5; ++k) {
            assertGt(seen[k], 0, "every decode kind is covered");
        }
        assertGt(whitelisted, 0, "pass 1: the metered transfers whitelist");

        // pass 2: the same mandate, the transfers on a token it does not meter (and the native send again)
        run.erc20Target = makeAddr("foreign token");
        run.nonceBase = 2_000;
        for (uint256 i; i < v.length; ++i) {
            if (v[i].kind == KIND_TRANSFER || v[i].kind == KIND_NONE) {
                assertFalse(_decodeEntry(run, v[i], i), string.concat("pass 2: ", v[i].note));
            }
        }

        // pass 3: a native mandate of the same device key (synthetic delegation hash: beforeHook is called as the
        // DelegationManager, which checked the mandate's K1 signature in a real redemption)
        run.terms.token = address(0);
        run.termsHex = abi.encode(run.terms);
        run.delegationHash = keccak256("ripar conformance: native mandate");
        run.erc20Target = A.token;
        run.nonceBase = 3_000;
        for (uint256 i; i < v.length; ++i) {
            if (v[i].kind == KIND_TRANSFER || v[i].kind == KIND_NONE) {
                assertEq(_decodeEntry(run, v[i], i), v[i].kind == KIND_NONE, string.concat("pass 3: ", v[i].note));
            }
        }
    }

    /// @dev One decode-table pass: the terms, the mandate and where the ERC-20 entries are sent.
    struct DecodeRun {
        IPulseCosignEnforcer.PulseTerms terms;
        bytes termsHex;
        bytes32 delegationHash;
        address erc20Target;
        uint64 expiry;
        uint256 nonceBase;
    }

    /// @dev Co-signs entry `e` (index `i`) with the demo P1 key under `run`, runs the HUMAN path as the
    ///      DelegationManager and checks the decode and the SPEC v1.2 known-payee rule. Returns whether it whitelisted.
    function _decodeEntry(DecodeRun memory run, Erc20DecodeV memory e, uint256 i) internal returns (bool whitelists) {
        bool native = e.kind == KIND_NONE;
        CosignV memory c;
        c.delegationHash = run.delegationHash;
        c.delegator = A.vault;
        c.redeemer = A.agent;
        c.target = native ? A.payee : run.erc20Target;
        c.value = native ? 1 ether : 0;
        c.callData = e.callData;
        c.callDataHash = keccak256(e.callData);
        c.nonce = run.nonceBase + i;
        c.expiry = run.expiry;
        c.presenceHash = keccak256(abi.encode("erc20 decode table", run.nonceBase, i));
        c.digest = _approvalDigest(c);
        (c.r, c.s) = p256Sign(D.p1PrivateKey, c.digest);

        c.payee = native ? c.target : (e.kind == KIND_UNKNOWN ? address(0) : e.to);
        c.amount = (native || e.kind == KIND_UNKNOWN) ? c.value : e.amount;
        whitelists = _v12Whitelists(run.terms, c.target, c.value, c.callData, c.payee, c.amount);
        if (e.kind == KIND_UNKNOWN) assertFalse(whitelists, e.note); // the model agrees: unmetered never whitelists
        bool knownBefore = enforcer.isKnownPayee(A.dm, c.delegationHash, c.payee);
        vm.recordLogs();
        vm.expectEmit(true, true, true, true, A.enforcer);
        emit IPulseCosignEnforcer.HumanCosigned(
            c.delegationHash, c.delegator, c.redeemer, A.dm, c.payee, c.amount, D.keyId, c.digest, c.presenceHash
        );
        _humanHook(run.termsHex, abi.encode(c.nonce, c.expiry, c.presenceHash, c.r, c.s), c);
        uint256 approvedEvents = _payeeApprovedCount(vm.getRecordedLogs());
        assertEq(enforcer.approvalOf(A.dm, c.digest).payee, c.payee, e.note);
        if (whitelists) {
            assertTrue(enforcer.isKnownPayee(A.dm, c.delegationHash, c.payee), e.note);
            assertEq(approvedEvents, knownBefore ? 0 : 1, e.note);
        } else {
            assertEq(approvedEvents, 0, e.note);
            assertEq(enforcer.isKnownPayee(A.dm, c.delegationHash, c.payee), knownBefore, e.note);
        }
    }

    /// @dev ripar-deny built by the device from the ERC-20 co-sign review (hold SIGN 2 s): requestHash = hashStruct of
    ///      the reviewed HumanApproval with presenceHash 0; all-zero pulse evidence.
    function _checkDeny() internal {
        string memory j = _json();
        DenyV memory d = _loadDeny(j);
        CosignV memory c = _loadCosign(j, ".cosignErc20");
        MandateV memory m = _loadMandate(j);

        assertEq(d.relay, A.relay, "pinned relay");
        assertEq(d.agentId, m.agentId, "agentId of the signed mandate");
        assertEq(d.requestHash, c.requestHash, "requestHash of the reviewed co-sign");
        assertEq(d.requestHash, _structHash(c, bytes32(0)), "requestHash == enforcer.approvalStructHash(.., 0)");
        assertEq(relay.denyDigest(d.agentId, d.requestHash, d.presenceHash), d.digest, "denyDigest == device digest");

        // a device key nobody registered cannot file denials
        vm.expectRevert(IRiparReputationRelay.UnknownDevice.selector);
        relay.attestDenial(d.agentId, d.requestHash, d.presenceHash, D.px, D.py, d.r, d.s);

        _registerDevice();
        vm.expectRevert(IRiparReputationRelay.BadDenySignature.selector);
        relay.attestDenial(d.agentId, d.requestHash, d.presenceHash, D.px, D.py, d.r, p256HighS(d.s));

        vm.expectEmit(true, true, false, true, A.relay);
        emit IRiparReputationRelay.Verdict(d.agentId, D.keyId, d.requestHash, false);
        relay.attestDenial(d.agentId, d.requestHash, d.presenceHash, D.px, D.py, d.r, d.s);
        assertTrue(relay.denialAttested(D.keyId, d.requestHash), "denialAttested");
        _assertLastFeedback(d.agentId, -1, "denied", d.requestHash);

        vm.expectRevert(IRiparReputationRelay.AlreadyAttested.selector);
        relay.attestDenial(d.agentId, d.requestHash, d.presenceHash, D.px, D.py, d.r, d.s);
    }

    /// @dev ripar-deny-req from the companion (here naming the native co-sign request): the device signs it without the
    ///      pulse (all-zero evidence) and echoes agentId / requestHash. It counts separately from the co-sign-review
    ///      deny, and, being reputation only, it does not block a co-signature of the same request.
    function _checkDenyRequest() internal {
        string memory j = _json();
        DenyV memory d = _loadDeny(j, ".denyRequest");
        DenyV memory d0 = _loadDeny(j);
        CosignV memory cn = _loadCosign(j, ".cosignNative");
        MandateV memory m = _loadMandate(j);

        assertEq(d.relay, A.relay, "pinned relay");
        assertEq(d.agentId, m.agentId, "agentId of the signed mandate");
        assertEq(d.requestHash, cn.requestHash, "the companion named the native co-sign request");
        assertEq(d.requestHash, _structHash(cn, bytes32(0)), "requestHash == enforcer.approvalStructHash(.., 0)");
        assertEq(relay.denyDigest(d.agentId, d.requestHash, d.presenceHash), d.digest, "denyDigest == device digest");
        assertTrue(d.digest != d0.digest, "two different denials");

        _registerDevice();
        vm.expectRevert(IRiparReputationRelay.BadDenySignature.selector);
        relay.attestDenial(d.agentId, d.requestHash, d.presenceHash, D.px, D.py, d.r, p256HighS(d.s));

        relay.attestDenial(d0.agentId, d0.requestHash, d0.presenceHash, D.px, D.py, d0.r, d0.s);
        vm.expectEmit(true, true, false, true, A.relay);
        emit IRiparReputationRelay.Verdict(d.agentId, D.keyId, d.requestHash, false);
        relay.attestDenial(d.agentId, d.requestHash, d.presenceHash, D.px, D.py, d.r, d.s);
        assertTrue(relay.denialAttested(D.keyId, d.requestHash), "denialAttested");
        assertEq(reputation.feedbackCount(), 2, "both denials count");
        _assertLastFeedback(d.agentId, -1, "denied", d.requestHash);
        vm.expectRevert(IRiparReputationRelay.AlreadyAttested.selector);
        relay.attestDenial(d.agentId, d.requestHash, d.presenceHash, D.px, D.py, d.r, d.s);

        _humanHook(m.termsHex, cn.args, cn);
        assertTrue(enforcer.consumed(A.dm, cn.digest), "a denial is reputation only: the co-sign still passes");
    }

    /// @dev SPEC v1.2 shield: the agent's owner made the relay an operator of the agent (so ERC-8004 would refuse the
    ///      relay's feedback as self-feedback). The device's deny from the co-sign review is still recorded, without a
    ///      feedback call (Verdict + AgentShielded, shieldedDenials), and the agent can no longer collect the approval
    ///      of a co-sign the device made (AgentIsShielded, after NotRedeemer and UnknownDevice).
    function _checkDenyShielded() internal {
        string memory j = _json();
        DenyV memory d = _loadDeny(j);
        MandateV memory m = _loadMandate(j);
        CosignV memory c20 = _loadCosign(j, ".cosignErc20");
        _registerDevice();
        identity.setOperator(d.agentId, A.relay, true); // the agent's owner shields the agent

        vm.expectEmit(true, true, false, true, A.relay);
        emit IRiparReputationRelay.Verdict(d.agentId, D.keyId, d.requestHash, false);
        vm.expectEmit(true, true, false, true, A.relay);
        emit IRiparReputationRelay.AgentShielded(d.agentId, D.keyId, d.requestHash);
        relay.attestDenial(d.agentId, d.requestHash, d.presenceHash, D.px, D.py, d.r, d.s);
        assertTrue(relay.denialAttested(D.keyId, d.requestHash), "denialAttested");
        assertEq(relay.shieldedDenials(d.agentId), 1, "shieldedDenials");
        assertEq(reputation.feedbackCount(), 0, "no feedback call");
        vm.expectRevert(IRiparReputationRelay.AlreadyAttested.selector);
        relay.attestDenial(d.agentId, d.requestHash, d.presenceHash, D.px, D.py, d.r, d.s);

        // the device's co-sign is still consumed normally; its approval can no longer be credited to the agent
        _humanHook(m.termsHex, c20.args, c20);
        vm.expectRevert(IRiparReputationRelay.NotRedeemer.selector);
        relay.attestApproval(m.agentId, c20.digest);
        vm.expectRevert(IRiparReputationRelay.AgentIsShielded.selector);
        vm.prank(c20.redeemer);
        relay.attestApproval(m.agentId, c20.digest);
        identity.setOperator(d.agentId, A.relay, false); // lifting it does not help
        vm.expectRevert(IRiparReputationRelay.AgentIsShielded.selector);
        vm.prank(c20.redeemer);
        relay.attestApproval(m.agentId, c20.digest);
    }

    /// @dev ripar-revoke (device menu): Revoke(lastDelegationHash) under the pinned enforcer's domain.
    function _checkRevoke() internal {
        string memory j = _json();
        RevokeV memory v = _loadRevoke(j);
        MandateV memory m = _loadMandate(j);
        CosignV memory c = _loadCosign(j, ".cosignErc20");

        assertEq(v.delegationHash, m.delegationHash, "revokes the signed mandate");
        assertEq(enforcer.revokeDigest(v.delegationHash), v.digest, "revokeDigest == device digest");

        vm.expectRevert(IPulseCosignEnforcer.BadSignature.selector);
        enforcer.revoke(D.px, D.py, v.delegationHash, v.r, p256HighS(v.s));

        vm.expectEmit(true, true, false, true, A.enforcer);
        emit IPulseCosignEnforcer.Revoked(D.keyId, v.delegationHash);
        enforcer.revoke(D.px, D.py, v.delegationHash, v.r, v.s);
        assertTrue(enforcer.isRevoked(D.keyId, v.delegationHash), "isRevoked");
        enforcer.revoke(D.px, D.py, v.delegationHash, v.r, v.s); // idempotent: relaying the QR twice is fine

        vm.expectRevert(IPulseCosignEnforcer.DelegationRevoked.selector);
        _humanHook(m.termsHex, c.args, c);
    }

    /// @dev ripar-panic (hold 5 s): Panic(floor + 1) kills every mandate with epoch < 1, i.e. this one (epoch 0).
    function _checkPanic() internal {
        string memory j = _json();
        PanicV memory v = _loadPanic(j);
        MandateV memory m = _loadMandate(j);
        CosignV memory c = _loadCosign(j, ".cosignErc20");

        assertEq(v.minEpoch, m.t.epoch + 1, "panic epoch = mandate epoch (device floor) + 1");
        assertEq(enforcer.panicDigest(v.minEpoch), v.digest, "panicDigest == device digest");

        vm.expectRevert(IPulseCosignEnforcer.BadSignature.selector);
        enforcer.panic(D.px, D.py, v.minEpoch, v.r, p256HighS(v.s));

        vm.expectEmit(true, false, false, true, A.enforcer);
        emit IPulseCosignEnforcer.Panicked(D.keyId, v.minEpoch);
        enforcer.panic(D.px, D.py, v.minEpoch, v.r, v.s);
        assertEq(enforcer.minEpoch(D.keyId), v.minEpoch, "minEpoch");

        vm.expectRevert(IPulseCosignEnforcer.EpochNotIncreasing.selector);
        enforcer.panic(D.px, D.py, v.minEpoch, v.r, v.s);

        vm.expectRevert(IPulseCosignEnforcer.StaleEpoch.selector);
        _humanHook(m.termsHex, c.args, c);
    }

    /// @dev ripar-reopen (device menu): Reopen(vault, lastNonce + 1) under the pinned sentinel's domain, checked
    ///      against the registered device of the vault's owner().
    function _checkReopen() internal {
        ReopenV memory v = _loadReopen(_json());
        assertEq(v.vault, A.vault, "pinned vault");
        assertEq(v.nonce, 1, "first reopen of a new device");
        assertEq(sentinel.reopenDigest(v.vault, v.nonce), v.digest, "reopenDigest == device digest");
        assertEq(MockOwnedVault(v.vault).owner(), D.k1, "vault owner = K1");

        vm.expectRevert(IRiparSentinel.NoDeviceForVault.selector);
        sentinel.reopen(v.vault, v.nonce, v.r, v.s);

        _registerDevice();
        // v1.2: the lane is open, so there is nothing to reopen (checked before the nonce: nothing is burnt)
        vm.expectRevert(IRiparSentinel.LaneNotClosed.selector);
        sentinel.reopen(v.vault, v.nonce, v.r, v.s);
        assertEq(sentinel.lastReopenNonce(v.vault), 0, "no nonce burnt");

        _closeLane(v.vault);
        assertFalse(sentinel.laneOpen(v.vault), "CRE closed the lane");
        vm.roll(block.number + 1);

        vm.expectRevert(IRiparSentinel.BadReopenSignature.selector);
        sentinel.reopen(v.vault, v.nonce, v.r, p256HighS(v.s));

        vm.expectEmit(true, false, false, true, A.sentinel);
        emit IRiparSentinel.LaneChanged(v.vault, true, 0, uint64(block.number));
        sentinel.reopen(v.vault, v.nonce, v.r, v.s);
        assertTrue(sentinel.laneOpen(v.vault), "lane open again");
        assertEq(sentinel.lastReopenNonce(v.vault), v.nonce, "lastReopenNonce");

        // relaying the same QR again: LaneNotClosed while the lane is open (v1.2) ...
        vm.expectRevert(IRiparSentinel.LaneNotClosed.selector);
        sentinel.reopen(v.vault, v.nonce, v.r, v.s);
        // ... and NonceNotIncreasing once CRE closed it again
        vm.roll(block.number + 1);
        _closeLane(v.vault);
        assertFalse(sentinel.laneOpen(v.vault), "closed again");
        vm.expectRevert(IRiparSentinel.NonceNotIncreasing.selector);
        sentinel.reopen(v.vault, v.nonce, v.r, v.s);
    }

    /// @dev End to end through the real DelegationManager and a real HybridDeleGator vault owned by the demo K1: the
    ///      mandate signature is checked by ERC-1271, the co-sign args ride in the caveat args, the vault pays.
    function _checkRedeemHuman() internal {
        string memory j = _json();
        MandateV memory m = _loadMandate(j);
        CosignV memory c20 = _loadCosign(j, ".cosignErc20");
        CosignV memory cn = _loadCosign(j, ".cosignNative");
        _installHybridVault();
        _registerDevice(); // v1.2: the relay credits co-signs of the vault owner's registered device only
        assertEq(HybridDeleGator(payable(A.vault)).owner(), _loadPair(j).owner, "vault owner = registered owner");
        IERC20Metadata usd = IERC20Metadata(A.token);
        assertEq(usd.decimals(), _u(j, ".cosignErc20.tokenDecimalsClaim"), "MockUSD decimals == companion claim");
        assertEq(usd.symbol(), vm.parseJsonString(j, ".cosignErc20.tokenSymbolClaim"), "MockUSD symbol == claim");

        // a wrong co-signature fails the whole redemption
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _redeem(m, abi.encode(c20.nonce, c20.expiry, c20.presenceHash, c20.r, p256HighS(c20.s)), c20);

        vm.expectEmit(true, true, true, true, A.enforcer);
        emit IPulseCosignEnforcer.PayeeApproved(A.dm, m.delegationHash, c20.payee);
        vm.expectEmit(true, true, true, true, A.enforcer);
        emit IPulseCosignEnforcer.HumanCosigned(
            c20.delegationHash,
            c20.delegator,
            c20.redeemer,
            A.dm,
            c20.payee,
            c20.amount,
            D.keyId,
            c20.digest,
            c20.presenceHash
        );
        _redeem(m, c20.args, c20);
        assertEq(usd.balanceOf(A.payee), c20.amount, "payee got the co-signed mUSD");
        assertEq(usd.balanceOf(A.vault), 1_000e6 - c20.amount, "paid by the vault");

        vm.recordLogs();
        vm.expectEmit(true, true, true, true, A.enforcer);
        emit IPulseCosignEnforcer.HumanCosigned(
            cn.delegationHash, cn.delegator, cn.redeemer, A.dm, cn.payee, cn.amount, D.keyId, cn.digest, cn.presenceHash
        );
        _redeem(m, cn.args, cn);
        assertEq(_payeeApprovedCount(vm.getRecordedLogs()), 0, "v1.2: a native co-sign under the mUSD mandate");
        assertEq(A.payee.balance, cn.amount, "payee got the co-signed MON");
        assertEq(enforcer.approvalOf(A.dm, cn.digest).redeemer, A.agent, "recorded under the DelegationManager");

        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
        _redeem(m, c20.args, c20);
        // v1.2: the same request signed again (same nonce, a fresh presence salt, so another digest; signed here with
        // the demo P1 key) cannot pay twice
        CosignV memory again = _resign(c20, c20.delegationHash, c20.nonce);
        assertTrue(again.digest != c20.digest, "another digest");
        assertTrue(enforcer.nonceUsed(A.dm, m.delegationHash, c20.nonce), "nonce used");
        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
        _redeem(m, again.args, again);
        assertEq(usd.balanceOf(A.payee), c20.amount, "paid once");

        // the redeemer files both approvals with the relay
        vm.startPrank(A.agent);
        relay.attestApproval(m.agentId, c20.digest);
        relay.attestApproval(m.agentId, cn.digest);
        vm.stopPrank();
        assertEq(reputation.feedbackCount(), 2, "two approvals credited");
    }

    /// @dev After the human co-sign made the payee known: AUTO within the caps, CRE lane close, device reopen, device
    ///      panic and revoke, all with the vectors' signatures through the real DelegationManager.
    function _checkRedeemAutoAndKillSwitch() internal {
        string memory j = _json();
        MandateV memory m = _loadMandate(j);
        CosignV memory c20 = _loadCosign(j, ".cosignErc20");
        _installHybridVault();
        _registerDevice();
        uint256 cap = m.t.perTxAutoCap;

        // new payee: AUTO needs a human first
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _redeemTransfer(m, A.payee, cap);
        _redeem(m, c20.args, c20);

        // known payee, within the per-tx cap: AUTO
        vm.expectEmit(true, true, true, true, A.enforcer);
        emit IPulseCosignEnforcer.AutoSpend(m.delegationHash, A.vault, A.agent, A.dm, A.payee, cap, cap);
        _redeemTransfer(m, A.payee, cap);
        assertEq(IERC20(A.token).balanceOf(A.payee), c20.amount + cap, "AUTO paid");
        (uint256 spent, uint256 remaining, uint64 start, uint64 end) =
            enforcer.autoBudget(A.dm, m.delegationHash, m.termsHex);
        assertEq(spent, cap, "autoBudget.spent");
        assertEq(remaining, m.t.periodAutoCap - cap, "autoBudget.remaining");
        assertEq(start, nowTs, "autoBudget.periodStart");
        assertEq(end, nowTs + m.t.period, "autoBudget.periodEnd");
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _redeemTransfer(m, A.payee, cap + 1);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _redeemTransfer(m, makeAddr("stranger"), 1);

        // CRE closes the lane; the device's reopen QR opens it again
        _closeLane(A.vault);
        vm.expectRevert(IPulseCosignEnforcer.LaneClosed.selector);
        _redeemTransfer(m, A.payee, 1);
        vm.roll(block.number + 1);
        ReopenV memory ro = _loadReopen(j);
        assertEq(HybridDeleGator(payable(A.vault)).owner(), D.k1, "vault owner = K1");
        sentinel.reopen(ro.vault, ro.nonce, ro.r, ro.s);
        _redeemTransfer(m, A.payee, 1);

        // panic: the mandate (epoch 0) dies
        PanicV memory pn = _loadPanic(j);
        enforcer.panic(D.px, D.py, pn.minEpoch, pn.r, pn.s);
        vm.expectRevert(IPulseCosignEnforcer.StaleEpoch.selector);
        _redeemTransfer(m, A.payee, 1);

        // revoke: checked before the epoch
        RevokeV memory rv = _loadRevoke(j);
        enforcer.revoke(D.px, D.py, rv.delegationHash, rv.r, rv.s);
        vm.expectRevert(IPulseCosignEnforcer.DelegationRevoked.selector);
        _redeemTransfer(m, A.payee, 1);
    }

    /// @dev The two other ERC-20 calls the device decodes, end to end: approve (payee = spender) and transferFrom
    ///      (payee = to). Both need the device's co-sign; neither is ever AUTO, not even to a known payee within the caps.
    function _checkRedeemApproveAndTransferFrom() internal {
        string memory j = _json();
        MandateV memory m = _loadMandate(j);
        CosignV memory ca = _loadCosign(j, ".cosignApprove");
        CosignV memory ct = _loadCosign(j, ".cosignTransferFrom");
        _installHybridVault();
        IERC20 usd = IERC20(A.token);
        assertEq(ca.payee, A.spender, "approve: the payee the device showed is the spender");
        assertEq(ct.payee, A.payee2, "transferFrom: the payee the device showed is `to`");
        assertEq(_a(j, ".cosignTransferFrom.from"), A.holder, "transferFrom: from = holder");

        // without the co-sign: HumanRequired (approve / transferFrom are never meterable)
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _redeemCall(m, "", ca.target, ca.value, ca.callData);

        vm.recordLogs();
        vm.expectEmit(true, true, true, true, A.enforcer);
        emit IPulseCosignEnforcer.HumanCosigned(
            ca.delegationHash, ca.delegator, ca.redeemer, A.dm, ca.payee, ca.amount, D.keyId, ca.digest, ca.presenceHash
        );
        _redeem(m, ca.args, ca);
        assertEq(_payeeApprovedCount(vm.getRecordedLogs()), 0, "SPEC v1.1: an approve co-sign whitelists nobody");
        assertEq(usd.allowance(A.vault, A.spender), ca.amount, "the vault approved the co-signed allowance");
        assertFalse(
            enforcer.isKnownPayee(A.dm, m.delegationHash, A.spender), "SPEC v1.1: an approved spender is no known payee"
        );

        // transferFrom: the holder allowed the vault, the device co-signed holder -> payee2
        IMockUSDFaucet(A.token).faucet(A.holder, ct.amount);
        vm.prank(A.holder);
        usd.approve(A.vault, ct.amount);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _redeemCall(m, "", ct.target, ct.value, ct.callData);
        vm.recordLogs();
        vm.expectEmit(true, true, true, true, A.enforcer);
        emit IPulseCosignEnforcer.HumanCosigned(
            ct.delegationHash, ct.delegator, ct.redeemer, A.dm, ct.payee, ct.amount, D.keyId, ct.digest, ct.presenceHash
        );
        _redeem(m, ct.args, ct);
        assertEq(_payeeApprovedCount(vm.getRecordedLogs()), 0, "SPEC v1.1: a transferFrom co-sign whitelists nobody");
        assertEq(usd.balanceOf(A.payee2), ct.amount, "payee2 got the co-signed transferFrom");
        assertEq(usd.balanceOf(A.holder), 0, "pulled from the holder");
        assertFalse(
            enforcer.isKnownPayee(A.dm, m.delegationHash, A.payee2), "SPEC v1.1: a transferFrom `to` is no known payee"
        );
        assertEq(enforcer.approvalOf(A.dm, ca.digest).payee, A.spender, "the approve record keeps the spender");
        assertEq(enforcer.approvalOf(A.dm, ct.digest).payee, A.payee2, "the transferFrom record keeps `to`");

        // 1 base unit (within every cap): approve and transferFrom stay HUMAN only ...
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _redeemCall(m, "", A.token, 0, abi.encodeCall(IERC20.approve, (A.spender, 1)));
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _redeemCall(m, "", A.token, 0, abi.encodeCall(IERC20.transferFrom, (A.holder, A.payee2, 1)));
        // ... and neither the approved spender nor the transferFrom recipient is an AUTO payee (SPEC v1.1)
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _redeemTransfer(m, A.spender, 1);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _redeemTransfer(m, A.payee2, 1);

        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
        _redeem(m, ca.args, ca);
        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
        _redeem(m, ct.args, ct);
    }

    /// @dev docs/PROTOCOL.md section 4 (pairing keys 10 / 11): after panic(1) and reopen(1) were relayed the device lost
    ///      its context. Without the floors its counters restart and everything it signs is refused on-chain; paired
    ///      again with the on-chain floors it signs a mandate with epoch = floor (here with a MetaMask TimestampEnforcer
    ///      caveat before the pulse caveat), a reopen with floor + 1 and a panic with floor + 1, all accepted.
    function _checkLostContextRepair() internal {
        string memory j = _json();
        MandateV memory m1 = _loadMandate(j);
        MandateV memory m2 = _loadMandate(j, ".repair.mandate");
        CosignV memory c20 = _loadCosign(j, ".cosignErc20");
        PanicV memory p1 = _loadPanic(j);
        ReopenV memory r1 = _loadReopen(j);
        PanicV memory p2 = _loadPanic(j, ".repair.panic");
        ReopenV memory r2 = _loadReopen(j, ".repair.reopen");
        PairV memory pair2 = _loadPair(j, ".repair.pair");
        _installHybridVault();
        _registerDevice();
        uint256 cap = m2.t.perTxAutoCap;

        // life with the first mandate: the human co-sign makes the payee known; then panic(1), a CRE close, reopen(1)
        _redeem(m1, c20.args, c20);
        enforcer.panic(D.px, D.py, p1.minEpoch, p1.r, p1.s);
        vm.expectRevert(IPulseCosignEnforcer.StaleEpoch.selector);
        _redeemTransfer(m1, A.payee, 1);
        _closeLane(A.vault);
        vm.roll(block.number + 1);
        sentinel.reopen(r1.vault, r1.nonce, r1.r, r1.s);

        // context lost, no floors: the device's panic(1) / reopen(1) would be these very bytes (RFC 6979): refused
        // (the reopen with LaneNotClosed while the lane is open (v1.2), with NonceNotIncreasing once it is closed below)
        vm.expectRevert(IPulseCosignEnforcer.EpochNotIncreasing.selector);
        enforcer.panic(D.px, D.py, p1.minEpoch, p1.r, p1.s);
        vm.expectRevert(IRiparSentinel.LaneNotClosed.selector);
        sentinel.reopen(r1.vault, r1.nonce, r1.r, r1.s);

        // re-pair with the on-chain floors as keys 10 / 11; the BindDevice signatures are unchanged
        assertEq(_u(j, ".repair.pair.minEpochFloor"), enforcer.minEpoch(D.keyId), "key 10 = on-chain minEpoch");
        assertEq(_u(j, ".repair.pair.reopenNonceFloor"), sentinel.lastReopenNonce(A.vault), "key 11 = on-chain nonce");
        assertEq(registry.bindDigest(pair2.owner, pair2.px, pair2.py), pair2.digest, "re-pair bindDigest");
        assertEq(
            registry.registerDevice(pair2.owner, pair2.px, pair2.py, pair2.r, pair2.s, pair2.k1Signature),
            D.keyId,
            "relaying the re-pair QR is a no-op"
        );

        // the new mandate: TimestampEnforcer caveat, then the pulse caveat with epoch = floor = on-chain minEpoch
        assertEq(m2.t.epoch, enforcer.minEpoch(D.keyId), "mandate epoch = floor");
        assertEq(m2.enforcers.length, 2, "two caveats");
        assertEq(m2.pulseIndex, 1, "pulse caveat second");
        assertEq(m2.enforcers[0], A.timestampEnforcer, "MetaMask TimestampEnforcer first");
        assertEq(m2.enforcers[1], A.enforcer, "then the pulse caveat");
        assertEq(m2.terms[1], m2.termsHex, "pulse terms");
        assertEq(abi.encode(m2.t), m2.termsHex, "abi.encode(PulseTerms) == device terms");
        (uint128 notAfter, uint128 notBefore) = TimestampEnforcer(A.timestampEnforcer).getTermsInfo(m2.terms[0]);
        assertEq(notAfter, _u(j, ".repair.timestamp.after"), "TimestampEnforcer after (as the device shows it)");
        assertEq(notBefore, _u(j, ".repair.timestamp.before"), "TimestampEnforcer before (as the device shows it)");
        assertEq(dm.getDelegationHash(_delegation(m2, "")), m2.delegationHash, "DM hash of the 2-caveat mandate");
        assertEq(MessageHashUtils.toTypedDataHash(dm.getDomainHash(), m2.delegationHash), m2.digest, "mandate digest");
        assertEq(ECDSA.recover(m2.digest, m2.signature), D.k1, "K1 signature");

        // known payees are per mandate (SPEC v1.1): the payee co-signed under the dead first mandate is new for the
        // second one, so its first payment needs the device again (a co-sign of the same call under the new mandate,
        // signed here with the demo P1 key)
        assertTrue(enforcer.isKnownPayee(A.dm, m1.delegationHash, A.payee), "known under the first mandate");
        assertFalse(enforcer.isKnownPayee(A.dm, m2.delegationHash, A.payee), "not under the new mandate");
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _redeemTransfer(m2, A.payee, cap);
        CosignV memory c2 = _resign(c20, m2.delegationHash, c20.nonce + 1);
        vm.expectEmit(true, true, true, true, A.enforcer);
        emit IPulseCosignEnforcer.PayeeApproved(A.dm, m2.delegationHash, A.payee);
        _redeem(m2, c2.args, c2);
        vm.expectEmit(true, true, true, true, A.enforcer);
        emit IPulseCosignEnforcer.AutoSpend(m2.delegationHash, A.vault, A.agent, A.dm, A.payee, cap, cap);
        _redeemTransfer(m2, A.payee, cap);
        vm.expectRevert(IPulseCosignEnforcer.StaleEpoch.selector);
        _redeemTransfer(m1, A.payee, 1);

        // CRE closes the lane (a report as of a block after reopen(1); an older one is ignored); the device's next
        // reopen (floor + 1) opens it again
        vm.roll(block.number + 1);
        _closeLane(A.vault);
        assertFalse(sentinel.laneOpen(A.vault), "CRE closed the lane");
        vm.expectRevert(IPulseCosignEnforcer.LaneClosed.selector);
        _redeemTransfer(m2, A.payee, 1);
        vm.roll(block.number + 1);
        vm.expectRevert(IRiparSentinel.NonceNotIncreasing.selector);
        sentinel.reopen(r1.vault, r1.nonce, r1.r, r1.s); // the lost-context reopen(1) on the closed lane
        assertEq(r2.nonce, r1.nonce + 1, "reopen nonce = floor + 1");
        assertEq(sentinel.reopenDigest(r2.vault, r2.nonce), r2.digest, "reopenDigest == device digest");
        sentinel.reopen(r2.vault, r2.nonce, r2.r, r2.s);
        _redeemTransfer(m2, A.payee, 1);

        // the TimestampEnforcer bound the device displayed is enforced by the real MetaMask enforcer
        vm.warp(notBefore);
        vm.expectRevert(bytes("TimestampEnforcer:expired-delegation"));
        _redeemTransfer(m2, A.payee, 1);
        vm.warp(nowTs);

        // the device's next panic (floor + 1) kills the new mandate
        assertEq(p2.minEpoch, m2.t.epoch + 1, "panic epoch = floor + 1");
        assertEq(enforcer.panicDigest(p2.minEpoch), p2.digest, "panicDigest == device digest");
        vm.expectEmit(true, false, false, true, A.enforcer);
        emit IPulseCosignEnforcer.Panicked(D.keyId, p2.minEpoch);
        enforcer.panic(D.px, D.py, p2.minEpoch, p2.r, p2.s);
        vm.expectRevert(IPulseCosignEnforcer.StaleEpoch.selector);
        _redeemTransfer(m2, A.payee, 1);
    }

    // ================================================================================================ helpers
    /// @dev Precompile variant: etch the mock at 0x0100 and require that P256 verification actually used it.
    function _usePrecompile() internal {
        etchP256Precompile();
        vm.expectCall(P256_PRECOMPILE, bytes(""));
    }

    function _structHash(CosignV memory c, bytes32 presenceHash) internal view returns (bytes32) {
        return enforcer.approvalStructHash(
            c.delegationHash,
            c.delegator,
            c.redeemer,
            c.target,
            c.value,
            c.callDataHash,
            c.nonce,
            c.expiry,
            presenceHash
        );
    }

    function _approvalDigest(CosignV memory c) internal view returns (bytes32) {
        return enforcer.approvalDigest(
            c.delegationHash,
            c.delegator,
            c.redeemer,
            c.target,
            c.value,
            c.callDataHash,
            c.nonce,
            c.expiry,
            c.presenceHash
        );
    }

    /// @dev SPEC v1.2 known-payee predicate, written from the spec (independently of the enforcer): the call is meterable
    ///      under `t` (AUTO step 1: token 0 -> a native send with value > 0; otherwise a well-formed `transfer` on
    ///      t.token with value 0) and moves a non-zero amount to a non-zero payee.
    function _v12Whitelists(
        IPulseCosignEnforcer.PulseTerms memory t,
        address target,
        uint256 value,
        bytes memory callData,
        address payee,
        uint256 amount
    ) internal pure returns (bool) {
        bool meterable;
        if (t.token == address(0)) {
            meterable = callData.length == 0 && value > 0;
        } else {
            // the selector is the first 4 bytes of the (68-byte) call: the truncation is intended
            // forge-lint: disable-next-line(unsafe-typecast)
            bytes4 selector = bytes4(callData);
            meterable = target == t.token && value == 0 && callData.length == 68 && selector == IERC20.transfer.selector
                && uint256(_slice32(callData, 4)) >> 160 == 0;
        }
        return meterable && amount != 0 && payee != address(0);
    }

    /// @dev callData[offset:offset + 32]
    function _slice32(bytes memory data, uint256 offset) internal pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(data, 0x20), offset))
        }
    }

    /// @dev A copy of co-sign `c` for another mandate and nonce, signed with the demo P1 key (the device's P1).
    function _resign(CosignV memory c, bytes32 delegationHash, uint256 nonce) internal view returns (CosignV memory n) {
        n.delegationHash = delegationHash;
        n.delegator = c.delegator;
        n.redeemer = c.redeemer;
        n.target = c.target;
        n.value = c.value;
        n.callData = c.callData;
        n.callDataHash = c.callDataHash;
        n.nonce = nonce;
        n.expiry = c.expiry;
        n.payee = c.payee;
        n.amount = c.amount;
        n.presenceHash = keccak256(abi.encode("resigned co-sign", delegationHash, nonce));
        n.structHash = _structHash(n, n.presenceHash);
        n.requestHash = _structHash(n, bytes32(0));
        n.digest = _approvalDigest(n);
        (n.r, n.s) = p256Sign(D.p1PrivateKey, n.digest);
        n.args = abi.encode(n.nonce, n.expiry, n.presenceHash, n.r, n.s);
    }

    /// @dev Number of PayeeApproved events the enforcer emitted in `logs`.
    function _payeeApprovedCount(Vm.Log[] memory logs) internal view returns (uint256 k) {
        for (uint256 i; i < logs.length; ++i) {
            if (
                logs[i].emitter == A.enforcer && logs[i].topics.length != 0
                    && logs[i].topics[0] == IPulseCosignEnforcer.PayeeApproved.selector
            ) {
                ++k;
            }
        }
    }

    /// @dev beforeHook as the DelegationManager calls it for a single default-mode execution.
    function _humanHook(bytes memory terms, bytes memory args, CosignV memory c) internal {
        vm.prank(A.dm);
        ICaveatEnforcer(A.enforcer)
            .beforeHook(
                terms,
                args,
                ModeLib.encodeSimpleSingle(),
                ExecutionLib.encodeSingle(c.target, c.value, c.callData),
                c.delegationHash,
                c.delegator,
                c.redeemer
            );
    }

    function _registerDevice() internal returns (bytes32 keyId) {
        PairV memory p = _loadPair(_json());
        keyId = registry.registerDevice(p.owner, p.px, p.py, p.r, p.s, p.k1Signature);
        assertEq(keyId, D.keyId, "registered keyId");
    }

    /// @dev CRE report through the forwarder: close the vault's lane (reason 1) as of the previous block.
    function _closeLane(address vault) internal {
        bytes memory metadata = abi.encodePacked(bytes32(uint256(1)), WORKFLOW_NAME, makeAddr("workflowOwner"));
        vm.prank(forwarder);
        sentinel.onReport(metadata, abi.encode(vault, false, uint8(1), uint64(block.number - 1)));
    }

    /// @dev Replace the owner()-only mock at the vault address with a real HybridDeleGator proxy owned by the demo K1
    ///      (the pairing's "vault" key 8), funded with 1_000 mUSD and 1 MON.
    function _installHybridVault() internal {
        HybridDeleGator impl = new HybridDeleGator(IDelegationManager(A.dm), IEntryPoint(makeAddr("entryPoint")));
        bytes memory init =
            abi.encodeCall(HybridDeleGator.initialize, (D.k1, new string[](0), new uint256[](0), new uint256[](0)));
        deployCodeTo("ERC1967Proxy.sol:ERC1967Proxy", abi.encode(address(impl), init), A.vault);
        assertEq(HybridDeleGator(payable(A.vault)).owner(), D.k1, "HybridDeleGator owner = K1");
        IMockUSDFaucet(A.token).faucet(A.vault, 1_000e6);
        vm.deal(A.vault, 1 ether);
    }

    function _redeem(MandateV memory m, bytes memory args, CosignV memory c) internal {
        _redeemCall(m, args, c.target, c.value, c.callData);
    }

    function _redeemTransfer(MandateV memory m, address to, uint256 amount) internal {
        _redeemCall(m, "", A.token, 0, abi.encodeCall(IERC20.transfer, (to, amount)));
    }

    function _redeemCall(MandateV memory m, bytes memory args, address target, uint256 value, bytes memory callData)
        internal
    {
        Delegation[] memory chain = new Delegation[](1);
        chain[0] = _delegation(m, args);
        bytes[] memory contexts = new bytes[](1);
        contexts[0] = abi.encode(chain);
        ModeCode[] memory modes = new ModeCode[](1);
        modes[0] = ModeLib.encodeSimpleSingle();
        bytes[] memory executions = new bytes[](1);
        executions[0] = ExecutionLib.encodeSingle(target, value, callData);
        vm.prank(A.agent);
        dm.redeemDelegations(contexts, modes, executions);
    }

    function _assertLastFeedback(uint256 agent, int128 value, string memory tag2, bytes32 feedbackHash) internal view {
        uint256 n = reputation.feedbackCount();
        assertGt(n, 0, "feedback given");
        MockERC8004Reputation.Feedback memory f = reputation.feedbackAt(n - 1);
        assertEq(f.client, A.relay, "feedback from the relay");
        assertEq(f.agentId, agent, "feedback agentId");
        assertEq(f.value, value, "feedback value");
        assertEq(f.valueDecimals, 0, "feedback decimals");
        assertEq(f.tag1, "ripar", "tag1");
        assertEq(f.tag2, tag2, "tag2");
        assertEq(f.endpoint, "", "endpoint");
        assertEq(f.feedbackURI, "", "feedbackURI");
        assertEq(f.feedbackHash, feedbackHash, "feedbackHash");
    }
}
