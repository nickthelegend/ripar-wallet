// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { EntryPoint } from "@account-abstraction/core/EntryPoint.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { ExecutionLib } from "@erc7579/lib/ExecutionLib.sol";
import { ModeLib } from "@erc7579/lib/ModeLib.sol";
import { DelegationManager } from "@delegation-framework/DelegationManager.sol";
import { HybridDeleGator } from "@delegation-framework/HybridDeleGator.sol";
import { Delegation, Caveat, ModeCode, PackedUserOperation } from "@delegation-framework/utils/Types.sol";

import { P256TestUtils } from "../P256TestUtils.sol";
import { MockUSD } from "../../../src/MockUSD.sol";
import { PulseCosignEnforcer } from "../../../src/PulseCosignEnforcer.sol";
import { RiparDeviceRegistry } from "../../../src/RiparDeviceRegistry.sol";
import { RiparSentinel } from "../../../src/RiparSentinel.sol";
import { RiparReputationRelay } from "../../../src/RiparReputationRelay.sol";
import { IPulseCosignEnforcer } from "../../../src/interfaces/IPulseCosignEnforcer.sol";
import { IRiparDeviceRegistry } from "../../../src/interfaces/IRiparDeviceRegistry.sol";
import { IERC8004Identity, IERC8004Reputation } from "../../../src/interfaces/external/IERC8004.sol";
import { IntegrationIdentityStub, IntegrationReputationStub } from "./IntegrationMocks.sol";

/// @notice End-to-end fixture: the REAL MetaMask delegation framework v1.3.0 (EntryPoint v0.7, DelegationManager,
///         HybridDeleGator behind an ERC1967Proxy owned by the device's K1 key) plus every Ripar contract. The relay
///         credits only the redemptions of this fixture's DelegationManager (its `delegationManager` immutable).
///         Every digest the device signs is rebuilt here by hand from the type strings in docs/PROTOCOL.md §3 and
///         checked against the contracts' own helpers before it is signed.
///         v1.2: the sentinel requires the CRE workflow owner `workflowOwner` in every report's metadata, as the deploy
///         config now does on Monad (MissingWorkflowOwner otherwise); `_closeLane` reports as that owner. The vault's
///         owner (K1) has the device's P1 registered, so the relay credits the device's co-signs.
abstract contract IntegrationBase is P256TestUtils {
    // ------------------------------------------------------------------ events (same signatures as the contracts)
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
    event LaneChanged(address indexed vault, bool open, uint8 reason, uint64 asOfBlock);
    event ReportIgnored(address indexed vault, uint8 reason, uint64 asOfBlock);
    event Verdict(uint256 indexed agentId, bytes32 indexed keyId, bytes32 requestHash, bool approved);
    event DeviceRegistered(address indexed owner, bytes32 indexed keyId, bytes32 px, bytes32 py);

    // ------------------------------------------------------------------ type strings (docs/PROTOCOL.md §3)
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant DELEGATION_TYPEHASH = keccak256(
        "Delegation(address delegate,address delegator,bytes32 authority,Caveat[] caveats,uint256 salt)Caveat(address enforcer,bytes terms)"
    );
    bytes32 internal constant CAVEAT_TYPEHASH = keccak256("Caveat(address enforcer,bytes terms)");
    bytes32 internal constant HUMAN_APPROVAL_TYPEHASH = keccak256(
        "HumanApproval(bytes32 delegationHash,address delegator,address redeemer,address target,uint256 value,bytes32 callDataHash,uint256 nonce,uint64 expiry,bytes32 presenceHash)"
    );
    bytes32 internal constant REVOKE_TYPEHASH = keccak256("Revoke(bytes32 delegationHash)");
    bytes32 internal constant PANIC_TYPEHASH = keccak256("Panic(uint64 minEpoch)");
    bytes32 internal constant REOPEN_TYPEHASH = keccak256("Reopen(address vault,uint256 nonce)");
    bytes32 internal constant DENY_TYPEHASH =
        keccak256("Deny(uint256 agentId,bytes32 requestHash,bytes32 presenceHash)");
    bytes32 internal constant BIND_DEVICE_TYPEHASH = keccak256("BindDevice(address owner,bytes32 px,bytes32 py)");
    bytes32 internal constant ROOT_AUTHORITY = bytes32(type(uint256).max);
    bytes10 internal constant WORKFLOW_NAME = "ripar-risk";

    // ------------------------------------------------------------------ fixtures (throwaway test keys only)
    uint64 internal constant T0 = 1_790_000_000; // 2026-09-21 UTC
    uint64 internal constant B0 = 1000; // block number at setUp
    uint256 internal constant DEVICE_P1_PK = 0x5EED0000000000000000000000000000000000000000000000000000000000A1; // P-256
    uint256 internal constant DEVICE_K1_PK = 0x5EED0000000000000000000000000000000000000000000000000000000000B2; // k1

    uint128 internal constant PER_TX = 25e6; // 25 mUSD
    uint128 internal constant PERIOD_CAP = 50e6; // 50 mUSD per day
    uint32 internal constant PERIOD = 1 days;
    uint128 internal constant NATIVE_PER_TX = 1 ether;
    uint128 internal constant NATIVE_PERIOD_CAP = 2 ether;
    uint256 internal constant VAULT_MUSD = 3_000e6;
    uint256 internal constant VAULT_NATIVE = 10 ether;

    // ------------------------------------------------------------------ framework
    EntryPoint internal entryPoint;
    DelegationManager internal delegationManager;
    HybridDeleGator internal hybridImpl;
    HybridDeleGator internal vault; // ERC1967Proxy -> HybridDeleGator, owner = K1, no P-256 signers

    // ------------------------------------------------------------------ Ripar
    MockUSD internal musd;
    RiparDeviceRegistry internal registry;
    PulseCosignEnforcer internal enforcer;
    RiparSentinel internal sentinel;
    RiparReputationRelay internal relay;
    IntegrationIdentityStub internal identity;
    IntegrationReputationStub internal reputation;

    // ------------------------------------------------------------------ actors
    address internal k1; // vault owner (device K1)
    bytes32 internal px; // device P1
    bytes32 internal py;
    bytes32 internal keyId;
    address internal agent; // AI agent EOA = delegate / redeemer
    uint256 internal agentPk;
    address internal agentOwner; // owner of the agent's ERC-8004 identity
    uint256 internal agentId;
    address internal forwarder; // stands in for the CRE KeystoneForwarder
    address internal workflowOwner; // the Chainlink CRE workflow owner the sentinel requires (v1.2 deploy config)
    address internal relayer; // anyone relaying device messages
    address internal payee;
    address internal payee2;
    address internal bundler;

    ModeCode internal singleMode;

    function setUp() public virtual {
        vm.warp(T0);
        vm.roll(B0);
        singleMode = ModeLib.encodeSimpleSingle();

        // --- actors
        k1 = vm.addr(DEVICE_K1_PK);
        (px, py) = p256Key(DEVICE_P1_PK);
        keyId = p256KeyId(px, py);
        (agent, agentPk) = makeAddrAndKey("agent");
        agentOwner = makeAddr("agent owner");
        forwarder = makeAddr("CRE forwarder");
        workflowOwner = makeAddr("workflow owner");
        relayer = makeAddr("relayer");
        payee = makeAddr("payee");
        payee2 = makeAddr("payee2");
        bundler = makeAddr("bundler");
        vm.deal(bundler, 1 ether);

        // --- MetaMask delegation framework v1.3.0
        entryPoint = new EntryPoint();
        delegationManager = _delegationManager();
        hybridImpl = new HybridDeleGator(delegationManager, entryPoint);
        // the vault: owner = K1, no P-256 signers (the device's P1 is not a vault signer)
        bytes memory init =
            abi.encodeCall(HybridDeleGator.initialize, (k1, new string[](0), new uint256[](0), new uint256[](0)));
        vault = HybridDeleGator(payable(address(new ERC1967Proxy(address(hybridImpl), init))));
        vm.label(address(entryPoint), "EntryPoint");
        vm.label(address(delegationManager), "DelegationManager");
        vm.label(address(vault), "vault");

        // --- Ripar
        musd = new MockUSD();
        registry = new RiparDeviceRegistry();
        enforcer = new PulseCosignEnforcer();
        sentinel = new RiparSentinel(forwarder, IRiparDeviceRegistry(address(registry)), workflowOwner);
        identity = new IntegrationIdentityStub();
        reputation = new IntegrationReputationStub(IERC8004Identity(address(identity)));
        relay = new RiparReputationRelay(
            IERC8004Reputation(address(reputation)),
            IERC8004Identity(address(identity)),
            IPulseCosignEnforcer(address(enforcer)),
            IRiparDeviceRegistry(address(registry)),
            address(delegationManager)
        );
        vm.label(address(musd), "mUSD");
        vm.label(address(enforcer), "PulseCosignEnforcer");
        vm.label(address(sentinel), "RiparSentinel");
        vm.label(address(relay), "RiparReputationRelay");

        // --- fund the vault
        for (uint256 i; i < VAULT_MUSD / musd.FAUCET_MAX(); ++i) {
            musd.faucet(address(vault), musd.FAUCET_MAX());
        }
        vm.deal(address(vault), VAULT_NATIVE);

        // --- pair the device: BindDevice signed by P1 and K1, relayed by anyone
        bytes32 bind = _digest(_domain("RiparDeviceRegistry", address(registry)), _bindStruct(k1, px, py));
        assertEq(bind, registry.bindDigest(k1, px, py), "bindDigest: hand-rolled == contract");
        (bytes32 r, bytes32 s) = p256Sign(DEVICE_P1_PK, bind);
        vm.prank(relayer);
        assertEq(registry.registerDevice(k1, px, py, r, s, _k1Sign(DEVICE_K1_PK, bind)), keyId);

        // --- the agent's ERC-8004 identity: owned by agentOwner, the agent EOA is authorized
        vm.startPrank(agentOwner);
        agentId = identity.register("ipfs://ripar-demo-agent", new IERC8004Identity.MetadataEntry[](0));
        identity.setAuthorized(agentId, agent, true);
        vm.stopPrank();

        // sanity: the vault is the framework's HybridDeleGator owned by K1, with no P-256 signer
        assertEq(vault.owner(), k1);
        assertEq(vault.getKeyIdHashesCount(), 0);
        assertEq(musd.balanceOf(address(vault)), VAULT_MUSD);
    }

    /// @dev A fresh DelegationManager v1.3.0; the fork suite overrides this with the canonical deployment.
    function _delegationManager() internal virtual returns (DelegationManager) {
        return new DelegationManager(makeAddr("DelegationManager owner"));
    }

    // ================================================================== EIP-712 by hand

    function _domain(string memory name, address verifyingContract) internal view returns (bytes32) {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(name)), keccak256("1"), block.chainid, verifyingContract)
        );
    }

    function _digest(bytes32 domain, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", domain, structHash));
    }

    function _bindStruct(address owner, bytes32 x, bytes32 y) internal pure returns (bytes32) {
        return keccak256(abi.encode(BIND_DEVICE_TYPEHASH, owner, x, y));
    }

    /// @dev hashStruct(Delegation) as the firmware computes it (docs/PROTOCOL.md §3), independently of EncoderLib.
    function _delegationStruct(Delegation memory d) internal pure returns (bytes32) {
        bytes32[] memory caveatHashes = new bytes32[](d.caveats.length);
        for (uint256 i; i < d.caveats.length; ++i) {
            caveatHashes[i] =
                keccak256(abi.encode(CAVEAT_TYPEHASH, d.caveats[i].enforcer, keccak256(d.caveats[i].terms)));
        }
        return keccak256(
            abi.encode(
                DELEGATION_TYPEHASH,
                d.delegate,
                d.delegator,
                d.authority,
                keccak256(abi.encodePacked(caveatHashes)),
                d.salt
            )
        );
    }

    /// @notice What the device signs for a co-sign request (everything a HumanApproval binds).
    struct Cosign {
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

    function _approvalStruct(Cosign memory c) internal pure returns (bytes32) {
        bytes memory head = abi.encode(HUMAN_APPROVAL_TYPEHASH, c.delegationHash, c.delegator, c.redeemer, c.target);
        bytes memory tail = abi.encode(c.value, keccak256(c.callData), c.nonce, c.expiry, c.presenceHash);
        return keccak256(bytes.concat(head, tail));
    }

    // ================================================================== signatures

    function _k1Sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev presenceHash = sha256(evidence12 ‖ salt16) (docs/PROTOCOL.md §3, §5).
    function _presence(uint256 saltSeed) internal pure returns (bytes32) {
        bytes12 evidence = bytes12(0x0148070186a00186a0140320); // v1, 72 bpm, 7 beats, IR/red DC, jitter, 8.0 s
        return sha256(abi.encodePacked(evidence, bytes16(keccak256(abi.encode("salt", saltSeed)))));
    }

    // ================================================================== mandates

    function _tokenTerms() internal view returns (IPulseCosignEnforcer.PulseTerms memory) {
        return IPulseCosignEnforcer.PulseTerms({
            px: px,
            py: py,
            token: address(musd),
            perTxAutoCap: PER_TX,
            periodAutoCap: PERIOD_CAP,
            period: PERIOD,
            epoch: 0,
            newPayeeNeedsHuman: true,
            sentinel: address(sentinel)
        });
    }

    function _nativeTerms() internal view returns (IPulseCosignEnforcer.PulseTerms memory t) {
        t = _tokenTerms();
        t.token = address(0);
        t.perTxAutoCap = NATIVE_PER_TX;
        t.periodAutoCap = NATIVE_PERIOD_CAP;
    }

    /// @dev A root delegation vault -> `delegate` with the Pulse caveat as its only caveat, signed by K1 (the vault's
    ///      ERC-1271 isValidSignature checks its owner). Checks the hand-rolled hash against the framework's.
    function _mandateFor(address delegate, IPulseCosignEnforcer.PulseTerms memory t, uint256 salt)
        internal
        view
        returns (Delegation memory d)
    {
        Caveat[] memory caveats = new Caveat[](1);
        caveats[0] = Caveat({ enforcer: address(enforcer), terms: abi.encode(t), args: "" });
        d = Delegation({
            delegate: delegate,
            delegator: address(vault),
            authority: ROOT_AUTHORITY,
            caveats: caveats,
            salt: salt,
            signature: ""
        });
        bytes32 structHash = _delegationStruct(d);
        assertEq(structHash, delegationManager.getDelegationHash(d), "delegation hash: hand-rolled == framework");
        bytes32 domain = _domain("DelegationManager", address(delegationManager));
        assertEq(domain, delegationManager.getDomainHash(), "DelegationManager domain");
        d.signature = _k1Sign(DEVICE_K1_PK, _digest(domain, structHash));
    }

    function _mandate(IPulseCosignEnforcer.PulseTerms memory t, uint256 salt)
        internal
        view
        returns (Delegation memory)
    {
        return _mandateFor(agent, t, salt);
    }

    function _hash(Delegation memory d) internal pure returns (bytes32) {
        return _delegationStruct(d);
    }

    /// @dev Deep copy of `d` with `args` on every Pulse caveat (args are not part of the signed delegation).
    function _withArgs(Delegation memory d, bytes memory args) internal view returns (Delegation memory c) {
        Caveat[] memory caveats = new Caveat[](d.caveats.length);
        for (uint256 i; i < d.caveats.length; ++i) {
            caveats[i] = Caveat({
                enforcer: d.caveats[i].enforcer,
                terms: d.caveats[i].terms,
                args: d.caveats[i].enforcer == address(enforcer) ? args : d.caveats[i].args
            });
        }
        c = Delegation({
            delegate: d.delegate,
            delegator: d.delegator,
            authority: d.authority,
            caveats: caveats,
            salt: d.salt,
            signature: d.signature
        });
    }

    // ================================================================== redemption (no external call before the
    // redeemDelegations call itself, so vm.expectRevert / vm.expectEmit can be placed right before these helpers)

    function _redeemChain(address redeemer, Delegation[] memory chain, ModeCode mode, bytes memory execution) internal {
        bytes[] memory contexts = new bytes[](1);
        contexts[0] = abi.encode(chain);
        ModeCode[] memory modes = new ModeCode[](1);
        modes[0] = mode;
        bytes[] memory executions = new bytes[](1);
        executions[0] = execution;
        vm.prank(redeemer);
        delegationManager.redeemDelegations(contexts, modes, executions);
    }

    function _redeemAs(
        address redeemer,
        Delegation memory d,
        bytes memory args,
        address target,
        uint256 value,
        bytes memory callData
    ) internal {
        Delegation[] memory chain = new Delegation[](1);
        chain[0] = _withArgs(d, args);
        _redeemChain(redeemer, chain, singleMode, ExecutionLib.encodeSingle(target, value, callData));
    }

    function _redeem(Delegation memory d, bytes memory args, address target, uint256 value, bytes memory callData)
        internal
    {
        _redeemAs(agent, d, args, target, value, callData);
    }

    /// @dev AUTO path: empty caveat args.
    function _autoTransfer(Delegation memory d, address to, uint256 amount) internal {
        _redeem(d, "", address(musd), 0, _transfer(to, amount));
    }

    function _autoNative(Delegation memory d, address to, uint256 value) internal {
        _redeem(d, "", to, value, "");
    }

    function _transfer(address to, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(bytes4(0xa9059cbb), to, amount);
    }

    // ================================================================== device co-sign (HUMAN path)

    function _cosignFor(
        Delegation memory d,
        address redeemer,
        address target,
        uint256 value,
        bytes memory callData,
        uint256 nonce
    ) internal view returns (Cosign memory c) {
        c = Cosign({
            delegationHash: _hash(d),
            delegator: d.delegator,
            redeemer: redeemer,
            target: target,
            value: value,
            callData: callData,
            nonce: nonce,
            expiry: uint64(block.timestamp + 10 minutes),
            presenceHash: _presence(nonce)
        });
    }

    function _cosign(Delegation memory d, address target, uint256 value, bytes memory callData, uint256 nonce)
        internal
        view
        returns (Cosign memory)
    {
        return _cosignFor(d, agent, target, value, callData, nonce);
    }

    /// @dev The digest the device's P1 signs, rebuilt by hand and checked against the enforcer's helper.
    function _approvalDigest(Cosign memory c) internal view returns (bytes32 digest) {
        digest = _digest(_domain("RiparPulseCosign", address(enforcer)), _approvalStruct(c));
        assertEq(
            digest,
            enforcer.approvalDigest(
                c.delegationHash,
                c.delegator,
                c.redeemer,
                c.target,
                c.value,
                keccak256(c.callData),
                c.nonce,
                c.expiry,
                c.presenceHash
            ),
            "approvalDigest: hand-rolled == enforcer"
        );
    }

    /// @dev The caveat args the companion relays: abi.encode(nonce, expiry, presenceHash, r, s), 160 bytes.
    function _signCosign(Cosign memory c) internal view returns (bytes memory args, bytes32 digest) {
        digest = _approvalDigest(c);
        (bytes32 r, bytes32 s) = p256Sign(DEVICE_P1_PK, digest);
        args = abi.encode(c.nonce, c.expiry, c.presenceHash, r, s);
        assertEq(args.length, 160);
    }

    // ================================================================== device kill switch, sentinel, relay

    function _revoke(bytes32 delegationHash) internal {
        bytes32 digest = _digest(
            _domain("RiparPulseCosign", address(enforcer)), keccak256(abi.encode(REVOKE_TYPEHASH, delegationHash))
        );
        assertEq(digest, enforcer.revokeDigest(delegationHash), "revokeDigest");
        (bytes32 r, bytes32 s) = p256Sign(DEVICE_P1_PK, digest);
        vm.prank(relayer);
        enforcer.revoke(px, py, delegationHash, r, s);
    }

    function _panic(uint64 newMinEpoch) internal {
        bytes32 digest =
            _digest(_domain("RiparPulseCosign", address(enforcer)), keccak256(abi.encode(PANIC_TYPEHASH, newMinEpoch)));
        assertEq(digest, enforcer.panicDigest(newMinEpoch), "panicDigest");
        (bytes32 r, bytes32 s) = p256Sign(DEVICE_P1_PK, digest);
        vm.prank(relayer);
        enforcer.panic(px, py, newMinEpoch, r, s);
    }

    /// @dev CRE close report through the (stand-in) KeystoneForwarder: metadata = workflowId ‖ name ‖ owner ‖ reportId.
    function _closeLane(uint8 reason, uint64 asOfBlock) internal {
        _reportAs(workflowOwner, address(vault), reason, asOfBlock);
    }

    /// @dev A close report for `vault_` from the CRE workflow of `owner_` (metadata[42:62]), through the forwarder.
    function _reportAs(address owner_, address vault_, uint8 reason, uint64 asOfBlock) internal {
        bytes memory metadata = abi.encodePacked(keccak256("ripar-risk-workflow"), WORKFLOW_NAME, owner_, hex"0001");
        bytes memory report = abi.encode(vault_, false, reason, asOfBlock);
        vm.prank(forwarder);
        sentinel.onReport(metadata, report);
    }

    function _reopenSig(uint256 nonce) internal view returns (bytes32 r, bytes32 s) {
        bytes32 digest = _digest(
            _domain("RiparSentinel", address(sentinel)), keccak256(abi.encode(REOPEN_TYPEHASH, address(vault), nonce))
        );
        assertEq(digest, sentinel.reopenDigest(address(vault), nonce), "reopenDigest");
        (r, s) = p256Sign(DEVICE_P1_PK, digest);
    }

    function _reopen(uint256 nonce) internal {
        (bytes32 r, bytes32 s) = _reopenSig(nonce);
        vm.prank(relayer);
        sentinel.reopen(address(vault), nonce, r, s);
    }

    // ================================================================== vault owner actions (ERC-4337 UserOp by K1)

    /// @dev Runs `callData` on the vault through the real EntryPoint, signed by K1 (the vault owner).
    function _vaultUserOp(bytes memory callData) internal {
        _vaultUserOpAs(DEVICE_K1_PK, callData);
    }

    /// @dev Runs `callData` on the vault through the real EntryPoint, signed by `ownerPk` (the vault's current owner).
    function _vaultUserOpAs(uint256 ownerPk, bytes memory callData) internal {
        PackedUserOperation memory op = PackedUserOperation({
            sender: address(vault),
            nonce: entryPoint.getNonce(address(vault), 0),
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(1_000_000), uint128(1_000_000))),
            preVerificationGas: 100_000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: ""
        });
        op.signature = _k1Sign(ownerPk, vault.getPackedUserOperationTypedDataHash(op));
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.prank(bundler, bundler);
        entryPoint.handleOps(ops, payable(bundler));
    }
}
