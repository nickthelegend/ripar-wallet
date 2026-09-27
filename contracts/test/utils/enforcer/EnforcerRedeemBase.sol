// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { EntryPoint } from "@account-abstraction/core/EntryPoint.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { ExecutionLib } from "@erc7579/lib/ExecutionLib.sol";
import { ModeLib } from "@erc7579/lib/ModeLib.sol";
import { DelegationManager } from "@delegation-framework/DelegationManager.sol";
import { HybridDeleGator } from "@delegation-framework/HybridDeleGator.sol";
import { Delegation, Caveat, ModeCode } from "@delegation-framework/utils/Types.sol";

import { P256TestUtils } from "../P256TestUtils.sol";
import { MockUSD } from "../../../src/MockUSD.sol";
import { PulseCosignEnforcer } from "../../../src/PulseCosignEnforcer.sol";
import { IPulseCosignEnforcer } from "../../../src/interfaces/IPulseCosignEnforcer.sol";
import { MockSentinel } from "./MockSentinel.sol";

/// @notice End-to-end fixture for the enforcer alone: the REAL MetaMask delegation framework v1.3.0 (EntryPoint v0.7,
///         DelegationManager, HybridDeleGator vault behind an ERC1967Proxy owned by the device's K1 key), MockUSD and
///         PulseCosignEnforcer. The sentinel is MockSentinel (lanes open) so the enforcer's behaviour is tested
///         without the other Ripar contracts. Mirrors the helpers of test/utils/integration/IntegrationBase.sol that
///         the adversarial-review PoCs used (same caps: 25 mUSD per tx, 50 mUSD per day). Throwaway test keys only.
abstract contract EnforcerRedeemBase is P256TestUtils {
    event PayeeApproved(address indexed delegationManager, bytes32 indexed delegationHash, address indexed payee);

    bytes32 internal constant ROOT_AUTHORITY = bytes32(type(uint256).max);
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant HUMAN_APPROVAL_TYPEHASH = keccak256(
        "HumanApproval(bytes32 delegationHash,address delegator,address redeemer,address target,uint256 value,bytes32 callDataHash,uint256 nonce,uint64 expiry,bytes32 presenceHash)"
    );

    uint64 internal constant T0 = 1_790_000_000; // 2026-09-21 UTC
    uint256 internal constant DEVICE_P1_PK = 0x5EED0000000000000000000000000000000000000000000000000000000000A1; // P-256
    uint256 internal constant DEVICE_K1_PK = 0x5EED0000000000000000000000000000000000000000000000000000000000B2; // k1

    uint128 internal constant PER_TX = 25e6; // 25 mUSD
    uint128 internal constant PERIOD_CAP = 50e6; // 50 mUSD per day
    uint32 internal constant PERIOD = 1 days;
    uint128 internal constant NATIVE_PER_TX = 1 ether;
    uint128 internal constant NATIVE_PERIOD_CAP = 2 ether;
    uint256 internal constant VAULT_MUSD = 3_000e6;
    uint256 internal constant VAULT_NATIVE = 10 ether;

    EntryPoint internal entryPoint;
    DelegationManager internal delegationManager;
    HybridDeleGator internal vault; // owner = K1, no P-256 signers
    MockUSD internal musd;
    PulseCosignEnforcer internal enforcer;
    MockSentinel internal sentinel;

    address internal k1;
    bytes32 internal px; // device P1
    bytes32 internal py;
    address internal agent; // delegate / redeemer
    address internal payee;
    address internal payee2;
    ModeCode internal singleMode;

    function setUp() public virtual {
        vm.warp(T0);
        vm.roll(1000);
        singleMode = ModeLib.encodeSimpleSingle();
        k1 = vm.addr(DEVICE_K1_PK);
        (px, py) = p256Key(DEVICE_P1_PK);
        agent = makeAddr("agent");
        payee = makeAddr("payee");
        payee2 = makeAddr("payee2");

        entryPoint = new EntryPoint();
        delegationManager = new DelegationManager(makeAddr("DelegationManager owner"));
        HybridDeleGator impl = new HybridDeleGator(delegationManager, entryPoint);
        bytes memory init =
            abi.encodeCall(HybridDeleGator.initialize, (k1, new string[](0), new uint256[](0), new uint256[](0)));
        vault = HybridDeleGator(payable(address(new ERC1967Proxy(address(impl), init))));

        musd = new MockUSD();
        enforcer = new PulseCosignEnforcer();
        sentinel = new MockSentinel();
        for (uint256 i; i < VAULT_MUSD / musd.FAUCET_MAX(); ++i) {
            musd.faucet(address(vault), musd.FAUCET_MAX());
        }
        vm.deal(address(vault), VAULT_NATIVE);
        assertEq(vault.owner(), k1);
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

    /// @dev A root delegation vault -> agent with the Pulse caveat as its only caveat, signed by K1 (the vault's
    ///      ERC-1271 check accepts its owner's signature).
    function _mandate(IPulseCosignEnforcer.PulseTerms memory t, uint256 salt)
        internal
        view
        returns (Delegation memory d)
    {
        Caveat[] memory caveats = new Caveat[](1);
        caveats[0] = Caveat({ enforcer: address(enforcer), terms: abi.encode(t), args: "" });
        d = Delegation({
            delegate: agent,
            delegator: address(vault),
            authority: ROOT_AUTHORITY,
            caveats: caveats,
            salt: salt,
            signature: ""
        });
        bytes32 digest = keccak256(
            abi.encodePacked(hex"1901", delegationManager.getDomainHash(), delegationManager.getDelegationHash(d))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(DEVICE_K1_PK, digest);
        d.signature = abi.encodePacked(r, s, v);
    }

    function _hash(Delegation memory d) internal view returns (bytes32) {
        return delegationManager.getDelegationHash(d);
    }

    // ================================================================== redemption

    /// @dev Redeems `d` with `args` on its Pulse caveat through the real DelegationManager, as `agent`. No external
    ///      call precedes redeemDelegations, so vm.expectRevert can be placed right before this helper.
    function _redeem(Delegation memory d, bytes memory args, address target, uint256 value, bytes memory callData)
        internal
    {
        d.caveats[0].args = args; // args are not part of the signed delegation
        Delegation[] memory chain = new Delegation[](1);
        chain[0] = d;
        bytes[] memory contexts = new bytes[](1);
        contexts[0] = abi.encode(chain);
        ModeCode[] memory modes = new ModeCode[](1);
        modes[0] = singleMode;
        bytes[] memory executions = new bytes[](1);
        executions[0] = ExecutionLib.encodeSingle(target, value, callData);
        vm.prank(agent);
        delegationManager.redeemDelegations(contexts, modes, executions);
    }

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

    /// @notice What the device signs for a co-sign request.
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

    /// @dev presenceHash = sha256(evidence12 ‖ salt16): a fresh salt per signature (docs/PROTOCOL.md §3, §5).
    function _presence(uint256 saltSeed) internal pure returns (bytes32) {
        bytes12 evidence = bytes12(0x0148070186a00186a0140320);
        return sha256(abi.encodePacked(evidence, bytes16(keccak256(abi.encode("salt", saltSeed)))));
    }

    function _cosign(Delegation memory d, address target, uint256 value, bytes memory callData, uint256 nonce)
        internal
        view
        returns (Cosign memory)
    {
        return Cosign({
            delegationHash: _hash(d),
            delegator: d.delegator,
            redeemer: agent,
            target: target,
            value: value,
            callData: callData,
            nonce: nonce,
            expiry: uint64(block.timestamp + 10 minutes),
            presenceHash: _presence(nonce)
        });
    }

    /// @dev The digest the device's P1 signs, rebuilt by hand from the type string and checked against the enforcer.
    function _approvalDigest(Cosign memory c) internal view returns (bytes32 digest) {
        bytes32 domain = keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("RiparPulseCosign"), keccak256("1"), block.chainid, address(enforcer))
        );
        bytes32 structHash = keccak256(
            bytes.concat(
                abi.encode(HUMAN_APPROVAL_TYPEHASH, c.delegationHash, c.delegator, c.redeemer, c.target),
                abi.encode(c.value, keccak256(c.callData), c.nonce, c.expiry, c.presenceHash)
            )
        );
        digest = keccak256(abi.encodePacked(hex"1901", domain, structHash));
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
    }

    /// @dev Signs `c` and redeems it through the DelegationManager (HUMAN path).
    function _redeemCosign(Delegation memory d, Cosign memory c) internal returns (bytes32 digest) {
        bytes memory args;
        (args, digest) = _signCosign(c);
        _redeem(d, args, c.target, c.value, c.callData);
    }

    function _known(Delegation memory d, address who) internal view returns (bool) {
        return enforcer.isKnownPayee(address(delegationManager), _hash(d), who);
    }
}
