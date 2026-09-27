// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { Vm } from "forge-std/Vm.sol";
import { IERC173 } from "@delegation-framework/interfaces/IERC173.sol";

import { RiparReputationRelay } from "../src/RiparReputationRelay.sol";
import { RiparDeviceRegistry } from "../src/RiparDeviceRegistry.sol";
import { IRiparReputationRelay } from "../src/interfaces/IRiparReputationRelay.sol";
import { IRiparDeviceRegistry } from "../src/interfaces/IRiparDeviceRegistry.sol";
import { IPulseCosignEnforcer } from "../src/interfaces/IPulseCosignEnforcer.sol";
import { IERC8004Identity, IERC8004Reputation } from "../src/interfaces/external/IERC8004.sol";
import { PeripheryTestBase } from "./utils/periphery/PeripheryTestBase.sol";
import { MockERC8004Identity, MockERC8004Reputation, RevertingForIdentity } from "./utils/periphery/MockERC8004.sol";
import { MockEnforcer } from "./utils/periphery/MockEnforcer.sol";
import {
    MockVault,
    NoOwnerVault,
    RevertingOwnerVault,
    DirtyOwnerVault,
    ShortOwnerVault,
    StatefulOwnerVault
} from "./utils/periphery/MockVaults.sol";

abstract contract RiparReputationRelayTestBase is PeripheryTestBase {
    event Verdict(uint256 indexed agentId, bytes32 indexed keyId, bytes32 requestHash, bool approved);
    event AgentShielded(uint256 indexed agentId, bytes32 indexed keyId, bytes32 requestHash);

    uint256 internal constant P1 = 0xA11CE; // registered device (P-256) of the vault owner vm.addr(K1)
    uint256 internal constant K1 = 0xB0B;
    uint256 internal constant P1_B = 0xB1B1; // second registered device, of vm.addr(K1_B)
    uint256 internal constant K1_B = 0xB2B2;
    uint256 internal constant P1_C = 0xC1C1; // unregistered P-256 key

    uint256 internal constant AGENT = 42;
    uint256 internal constant OTHER_AGENT = 43;
    uint256 internal constant SHIELDED_AGENT = 44; // its owner made the relay an operator (v1.2 shield)

    RiparDeviceRegistry internal reg;
    MockERC8004Identity internal identity;
    MockERC8004Reputation internal reputation;
    MockEnforcer internal enforcer;
    RiparReputationRelay internal relay;

    address internal agentOwner;
    address internal redeemer; // an address the identity registry authorizes for AGENT (the agent's session key)
    address internal otherSessionKey; // another address authorized for AGENT, which did not redeem
    address internal otherAgentOwner; // owner of OTHER_AGENT
    address internal directCaller; // someone who calls enforcer.beforeHook directly (a non-canonical "manager")
    address internal owner; // vault owner (K1), whose registered device is P1
    address internal ownerB; // vault owner (K1_B), whose registered device is P1_B
    MockVault internal vault; // owner() == owner
    MockVault internal vaultB; // owner() == ownerB
    bytes32 internal px;
    bytes32 internal py;
    bytes32 internal keyId; // P1, registered to owner
    bytes32 internal keyIdB; // P1_B, registered to ownerB

    function setUp() public virtual {
        reg = new RiparDeviceRegistry();
        identity = new MockERC8004Identity();
        reputation = new MockERC8004Reputation(address(identity));
        enforcer = new MockEnforcer();
        relay = _newRelay(DELEGATION_MANAGER);

        agentOwner = makeAddr("agentOwner");
        redeemer = makeAddr("agentSessionKey");
        otherSessionKey = makeAddr("otherSessionKey");
        otherAgentOwner = makeAddr("otherAgentOwner");
        directCaller = makeAddr("directBeforeHookCaller");
        identity.setOwner(AGENT, agentOwner);
        identity.setAuthorized(AGENT, redeemer, true);
        identity.setAuthorized(AGENT, otherSessionKey, true);
        identity.setOwner(OTHER_AGENT, otherAgentOwner);
        identity.setOwner(SHIELDED_AGENT, makeAddr("shieldedAgentOwner"));
        identity.setAuthorized(SHIELDED_AGENT, address(relay), true);

        keyId = registerPair(reg, P1, K1);
        keyIdB = registerPair(reg, P1_B, K1_B);
        (px, py) = p256Key(P1);
        owner = vm.addr(K1);
        ownerB = vm.addr(K1_B);
        vault = new MockVault(owner);
        vaultB = new MockVault(ownerB);
    }

    // ------------------------------------------------------------------ helpers

    function _newRelay(address manager) internal returns (RiparReputationRelay) {
        return new RiparReputationRelay(
            IERC8004Reputation(address(reputation)),
            IERC8004Identity(address(identity)),
            IPulseCosignEnforcer(address(enforcer)),
            reg,
            manager
        );
    }

    /// @dev An approval record of the vault owner's registered device (keyId, vault) redeemed by `red`, unless the
    ///      test passes another key or delegator.
    function _approvalFor(bytes32 kid, address delegator, address red)
        internal
        pure
        returns (IPulseCosignEnforcer.Approval memory)
    {
        return IPulseCosignEnforcer.Approval({
            keyId: kid,
            delegationHash: keccak256("delegation"),
            delegator: delegator,
            redeemer: red,
            payee: makeAddrView("payee"),
            timestamp: 1
        });
    }

    function _approval(bytes32 kid, address red) internal view returns (IPulseCosignEnforcer.Approval memory) {
        return _approvalFor(kid, address(vault), red);
    }

    function makeAddrView(string memory name) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(name)))));
    }

    /// @dev The canonical DelegationManager's redemption consumed co-sign `digest` of the vault owner's device (P1 on
    ///      `vault`), redeemed by `red`.
    function _consume(bytes32 digest, address red) internal {
        enforcer.setApproval(DELEGATION_MANAGER, digest, _approval(keyId, red));
    }

    /// @dev Same, with the co-signing key `kid` and the delegator `delegator`.
    function _consumeWith(bytes32 digest, bytes32 kid, address delegator, address red) internal {
        enforcer.setApproval(DELEGATION_MANAGER, digest, _approvalFor(kid, delegator, red));
    }

    /// @dev `manager` called beforeHook (e.g. directly) and consumed `digest` for itself, naming `red` as redeemer.
    function _consumeVia(address manager, bytes32 digest, address red) internal {
        enforcer.setApproval(manager, digest, _approval(keyId, red));
    }

    function _attest(address caller, uint256 agentId, bytes32 digest) internal {
        vm.prank(caller);
        relay.attestApproval(agentId, digest);
    }

    function _expectAttestRevert(address caller, uint256 agentId, bytes32 digest, bytes4 err) internal {
        vm.expectRevert(err);
        vm.prank(caller);
        relay.attestApproval(agentId, digest);
    }

    function _denySig(uint256 p1Pk, uint256 agentId, bytes32 requestHash, bytes32 presenceHash)
        internal
        view
        returns (bytes32 r, bytes32 s)
    {
        return p256Sign(p1Pk, relay.denyDigest(agentId, requestHash, presenceHash));
    }

    function _deny(uint256 p1Pk, uint256 agentId, bytes32 requestHash, bytes32 presenceHash) internal {
        (bytes32 x, bytes32 y) = p256Key(p1Pk);
        (bytes32 r, bytes32 s) = _denySig(p1Pk, agentId, requestHash, presenceHash);
        relay.attestDenial(agentId, requestHash, presenceHash, x, y, r, s);
    }

    function _assertFeedback(uint256 i, uint256 agentId, int128 value, string memory tag2, bytes32 hash) internal view {
        MockERC8004Reputation.Feedback memory f = reputation.feedbackAt(i);
        assertEq(f.client, address(relay), "client");
        assertEq(f.agentId, agentId, "agentId");
        assertEq(int256(f.value), int256(value), "value");
        assertEq(f.valueDecimals, 0, "valueDecimals");
        assertEq(f.tag1, "ripar", "tag1");
        assertEq(f.tag2, tag2, "tag2");
        assertEq(f.endpoint, "", "endpoint");
        assertEq(f.feedbackURI, "", "feedbackURI");
        assertEq(f.feedbackHash, hash, "feedbackHash");
    }

    /// @dev presenceHash as the device builds it: sha256(evidence12 ‖ salt16) (SHA-256, not keccak)
    function _presence(bytes12 evidence, bytes16 salt) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(evidence, salt));
    }

    // ------------------------------------------------------------------ constructor / EIP-712

    function test_constructor() public view {
        assertEq(address(relay.reputation()), address(reputation));
        assertEq(address(relay.identity()), address(identity));
        assertEq(address(relay.enforcer()), address(enforcer));
        assertEq(address(relay.registry()), address(reg));
        assertEq(relay.delegationManager(), DELEGATION_MANAGER);
        // the MetaMask DelegationManager v1.3.0 the firmware pins (SPEC, docs/PROTOCOL.md)
        assertEq(relay.delegationManager(), 0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3);
        assertEq(IRiparReputationRelay(address(relay)).delegationManager(), DELEGATION_MANAGER);
        assertEq(relay.shieldedDenials(AGENT), 0);
        assertEq(relay.shieldedDenials(SHIELDED_AGENT), 0);
    }

    function testFuzz_constructor_delegationManager(address manager) public {
        assertEq(_newRelay(manager).delegationManager(), manager);
    }

    function test_domainSeparator_matchesHandRolled() public view {
        assertEq(relay.domainSeparator(), handDomain("RiparReputationRelay", block.chainid, address(relay)));
        (, string memory name, string memory version, uint256 chainId, address verifying,,) = relay.eip712Domain();
        assertEq(name, "RiparReputationRelay");
        assertEq(version, "1");
        assertEq(chainId, block.chainid);
        assertEq(verifying, address(relay));
    }

    function test_denyDigest_matchesHandRolled() public view {
        assertEq(relay.DENY_TYPEHASH(), keccak256("Deny(uint256 agentId,bytes32 requestHash,bytes32 presenceHash)"));
        bytes32 requestHash = keccak256("request");
        bytes32 presenceHash = _presence(bytes12(0), bytes16(0));
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Deny(uint256 agentId,bytes32 requestHash,bytes32 presenceHash)"),
                AGENT,
                requestHash,
                presenceHash
            )
        );
        bytes32 expected = keccak256(
            abi.encodePacked(hex"1901", handDomain("RiparReputationRelay", block.chainid, address(relay)), structHash)
        );
        assertEq(relay.denyDigest(AGENT, requestHash, presenceHash), expected);
    }

    function testFuzz_denyDigest_matchesHandRolled(uint256 agentId, bytes32 requestHash, bytes32 presenceHash)
        public
        view
    {
        bytes32 structHash = keccak256(abi.encode(relay.DENY_TYPEHASH(), agentId, requestHash, presenceHash));
        assertEq(
            relay.denyDigest(agentId, requestHash, presenceHash),
            handDigest(handDomain("RiparReputationRelay", block.chainid, address(relay)), structHash)
        );
    }

    /// @dev Vectors from firmware/test/host/vectors_eip712_abi.h (generated by the Python reference encoder).
    function test_firmwareVectors() public {
        // DOMAINS[3]: RiparReputationRelay v1, chainId 10143
        address at = hexAddr(hex"394a42c47decdc6fba97450dd2fe2a2701de327e");
        vm.etch(at, address(relay).code);
        vm.chainId(10_143);
        assertEq(
            RiparReputationRelay(at).domainSeparator(),
            hex"ea0165badfcc6c3e5dd7348c47ed659afca4a881b5c2a205d97e9e0d16d32eac"
        );
        // DENIES[0]: chainId 1
        at = hexAddr(hex"c686af958500ca1b7f7543ab6b71fd36bd1a65a3");
        vm.etch(at, address(relay).code);
        vm.chainId(1);
        uint256 agentId = 0x2fd6884e6fb9ca7e0b2ef74163f1ca406e4da82172d4a1c41700ecdf0a6e8a20;
        bytes32 requestHash = hex"a920ce541a3ed862a86e6f6ccb54b023a2302a5a16690b7e7a24a54f7a4a1afd";
        bytes32 presenceHash = hex"184a8094a405f50f1ea650382670bc93028df015e74dfc8a8fbb44ac357b335f";
        assertEq(
            keccak256(abi.encode(relay.DENY_TYPEHASH(), agentId, requestHash, presenceHash)),
            hex"42367ec53767ad11b4c95b542e910cddc6813e6da65e86da28dae4abcec69f99",
            "structHash"
        );
        assertEq(
            RiparReputationRelay(at).denyDigest(agentId, requestHash, presenceHash),
            hex"4fde173448e862bdd215ad8b49bab6d7de292c5ab21797907b1894de299258ac",
            "digest"
        );
        // DENIES[4]: chainId 143
        at = hexAddr(hex"37f4e70a17bfcfc3373febfc2efbaed8fd36df35");
        vm.etch(at, address(relay).code);
        vm.chainId(143);
        assertEq(
            RiparReputationRelay(at)
                .denyDigest(
                    0xeb0b607cd765660e,
                    hex"e3ee3cfefb3f8ec70c09a6e3479cf4f34b03ca5b9025b6a96e6c4db899d9f622",
                    hex"f28bb211e082eb5de327c84bc9ad50b88681d87e6acd61019f2c59713ec847d9"
                ),
            hex"12c9e822dc9ee784c44fe49514a87de516f2e316c06fb136c9938f74049d0860"
        );
    }

    // ------------------------------------------------------------------ attestApproval

    function test_attestApproval_happyPath() public {
        bytes32 d = keccak256("approval digest");
        _consume(d, redeemer);

        // the relay reads the enforcer's records for the canonical DelegationManager only
        vm.expectCall(address(enforcer), abi.encodeCall(IPulseCosignEnforcer.consumed, (DELEGATION_MANAGER, d)));
        vm.expectCall(address(enforcer), abi.encodeCall(IPulseCosignEnforcer.approvalOf, (DELEGATION_MANAGER, d)));
        // v1.2: the co-signing key must be the registered device of the vault's owner
        vm.expectCall(address(reg), abi.encodeCall(IRiparDeviceRegistry.keyOf, (keyId)));
        vm.expectCall(address(vault), abi.encodeCall(IERC173.owner, ()));
        vm.expectCall(address(identity), abi.encodeCall(IERC8004Identity.isAuthorizedOrOwner, (redeemer, AGENT)));
        vm.expectCall(
            address(reputation),
            abi.encodeCall(
                IERC8004Reputation.giveFeedback, (AGENT, int128(1), uint8(0), "ripar", "cosigned", "", "", d)
            )
        );
        vm.expectEmit(true, true, false, true, address(relay));
        emit Verdict(AGENT, keyId, d, true);
        _attest(redeemer, AGENT, d);

        assertTrue(relay.approvalAttested(d));
        assertEq(reputation.feedbackCount(), 1);
        _assertFeedback(0, AGENT, 1, "cosigned", d);
    }

    function test_attestApproval_redeemerIsAgentOwner() public {
        bytes32 d = keccak256("d-owner");
        _consume(d, agentOwner);
        _attest(agentOwner, AGENT, d);
        assertTrue(relay.approvalAttested(d));
        _assertFeedback(0, AGENT, 1, "cosigned", d);
    }

    function test_attestApproval_redeemerIsContract() public {
        // a smart-account redeemer attests through its own call (here: the test contract itself)
        bytes32 d = keccak256("d-contract");
        _consume(d, address(this));
        identity.setAuthorized(AGENT, address(this), true);
        relay.attestApproval(AGENT, d);
        _assertFeedback(0, AGENT, 1, "cosigned", d);
    }

    function test_attestApproval_verdictCarriesApprovalKeyId() public {
        // another vault owner's registered device (P1_B on vaultB): the Verdict names that device's keyId
        bytes32 d = keccak256("d-key");
        _consumeWith(d, keyIdB, address(vaultB), redeemer);
        vm.expectEmit(true, true, false, true, address(relay));
        emit Verdict(AGENT, keyIdB, d, true);
        _attest(redeemer, AGENT, d);
    }

    function test_revert_attestApproval_notConsumed() public {
        bytes32 d = keccak256("never consumed");
        _expectAttestRevert(redeemer, AGENT, d, IRiparReputationRelay.NotConsumed.selector);
        _expectAttestRevert(agentOwner, AGENT, d, IRiparReputationRelay.NotConsumed.selector);
        assertFalse(relay.approvalAttested(d));
        assertEq(reputation.feedbackCount(), 0);
    }

    /// @dev v1.1 finding 1: anyone may call beforeHook directly with a pending redemption's caveat args. The enforcer
    ///      keeps that record under the caller's address; the relay never trusts it, whoever it names as redeemer.
    function test_revert_attestApproval_nonCanonicalManager_isNotConsumed() public {
        bytes32 d = keccak256("d-direct");
        _consumeVia(directCaller, d, redeemer);
        assertTrue(enforcer.consumed(directCaller, d));
        assertFalse(enforcer.consumed(DELEGATION_MANAGER, d));
        _expectAttestRevert(redeemer, AGENT, d, IRiparReputationRelay.NotConsumed.selector);

        // a record naming the direct caller itself as redeemer (and authorized for its own agent) is ignored too
        bytes32 d2 = keccak256("d-direct-self");
        identity.setAuthorized(OTHER_AGENT, directCaller, true);
        _consumeVia(directCaller, d2, directCaller);
        _expectAttestRevert(directCaller, OTHER_AGENT, d2, IRiparReputationRelay.NotConsumed.selector);

        // records under other would-be managers: the enforcer itself, the relay, address(0), another deployment
        _consumeVia(address(enforcer), d, redeemer);
        _consumeVia(address(relay), d, redeemer);
        _consumeVia(address(0), d, redeemer);
        _consumeVia(makeAddr("otherDelegationManager"), d, redeemer);
        _expectAttestRevert(redeemer, AGENT, d, IRiparReputationRelay.NotConsumed.selector);
        assertEq(reputation.feedbackCount(), 0);
        assertFalse(relay.approvalAttested(d));

        // replay protection is per manager: the real redemption still consumes it, and then it counts once
        _consume(d, redeemer);
        _attest(redeemer, AGENT, d);
        _assertFeedback(0, AGENT, 1, "cosigned", d);
        assertEq(reputation.feedbackCount(), 1);
    }

    function testFuzz_revert_attestApproval_nonCanonicalManager(address manager, bytes32 d) public {
        vm.assume(manager != DELEGATION_MANAGER);
        _consumeVia(manager, d, redeemer);
        _expectAttestRevert(redeemer, AGENT, d, IRiparReputationRelay.NotConsumed.selector);
        assertFalse(relay.approvalAttested(d));
    }

    /// @dev With a direct-call record and the canonical record for the same digest, only the canonical one is read:
    ///      its redeemer attests, and the Verdict carries its keyId.
    function test_attestApproval_readsOnlyCanonicalRecord() public {
        bytes32 d = keccak256("d-both");
        address attacker = makeAddr("attacker");
        identity.setAuthorized(OTHER_AGENT, attacker, true);
        enforcer.setApproval(directCaller, d, _approval(keccak256("fake key"), attacker));
        _consume(d, redeemer);

        _expectAttestRevert(attacker, OTHER_AGENT, d, IRiparReputationRelay.NotRedeemer.selector);
        vm.expectEmit(true, true, false, true, address(relay));
        emit Verdict(AGENT, keyId, d, true);
        _attest(redeemer, AGENT, d);
        assertEq(reputation.feedbackCount(), 1);
        _assertFeedback(0, AGENT, 1, "cosigned", d);
    }

    /// @dev A relay deployed for another DelegationManager trusts that manager's records, and only those.
    function test_attestApproval_otherDeploymentTrustsItsOwnManager() public {
        address manager2 = makeAddr("delegationManager2");
        RiparReputationRelay relay2 = _newRelay(manager2);
        bytes32 d = keccak256("d-manager2");
        _consume(d, redeemer); // canonical record: not relay2's
        vm.expectRevert(IRiparReputationRelay.NotConsumed.selector);
        vm.prank(redeemer);
        relay2.attestApproval(AGENT, d);

        _consumeVia(manager2, d, redeemer);
        vm.prank(redeemer);
        relay2.attestApproval(AGENT, d);
        assertTrue(relay2.approvalAttested(d));
        assertFalse(relay.approvalAttested(d));
    }

    /// @dev v1.1 finding 4: only the approval's redeemer may attest it.
    function test_revert_attestApproval_notRedeemer() public {
        bytes32 d = keccak256("d-not-redeemer");
        _consume(d, redeemer);

        _expectAttestRevert(makeAddr("stranger"), AGENT, d, IRiparReputationRelay.NotRedeemer.selector);
        _expectAttestRevert(makeAddr("anyRelayer"), AGENT, d, IRiparReputationRelay.NotRedeemer.selector);
        // addresses the identity registry authorizes for AGENT, but which did not redeem
        _expectAttestRevert(agentOwner, AGENT, d, IRiparReputationRelay.NotRedeemer.selector);
        _expectAttestRevert(otherSessionKey, AGENT, d, IRiparReputationRelay.NotRedeemer.selector);
        // the delegator (vault), the DelegationManager, the enforcer and the device owner are not the redeemer either
        _expectAttestRevert(address(vault), AGENT, d, IRiparReputationRelay.NotRedeemer.selector);
        _expectAttestRevert(DELEGATION_MANAGER, AGENT, d, IRiparReputationRelay.NotRedeemer.selector);
        _expectAttestRevert(address(enforcer), AGENT, d, IRiparReputationRelay.NotRedeemer.selector);
        _expectAttestRevert(owner, AGENT, d, IRiparReputationRelay.NotRedeemer.selector);
        // not even for another agent the caller owns
        _expectAttestRevert(otherAgentOwner, OTHER_AGENT, d, IRiparReputationRelay.NotRedeemer.selector);

        assertEq(reputation.feedbackCount(), 0);
        assertFalse(relay.approvalAttested(d));

        // the redeemer still can
        _attest(redeemer, AGENT, d);
        _assertFeedback(0, AGENT, 1, "cosigned", d);
    }

    function testFuzz_revert_attestApproval_notRedeemer(address caller, bytes32 d) public {
        vm.assume(caller != redeemer);
        _consume(d, redeemer);
        // being authorized for the agent does not help
        if (caller != address(0) && caller != address(relay)) identity.setAuthorized(AGENT, caller, true);
        _expectAttestRevert(caller, AGENT, d, IRiparReputationRelay.NotRedeemer.selector);
        assertFalse(relay.approvalAttested(d));
    }

    function test_revert_attestApproval_recordWithoutRedeemer() public {
        // a consumed record with no redeemer (not something the real enforcer stores) cannot be attested by anyone
        bytes32 d = keccak256("d-no-redeemer");
        _consume(d, address(0));
        _expectAttestRevert(agentOwner, AGENT, d, IRiparReputationRelay.NotRedeemer.selector);
        _expectAttestRevert(redeemer, AGENT, d, IRiparReputationRelay.NotRedeemer.selector);
    }

    /// @dev v1.1 finding 4, the front-running scenario: OTHER_AGENT's owner authorizes the victim redeemer for its own
    ///      agent (unilaterally, like an ERC-721 approve) and races to attest the victim's approval to OTHER_AGENT.
    ///      In v1 the first attester won; now only the redeemer can attest, and it credits its own agent.
    function test_frontRun_otherAgentOwnerCannotTakeCredit() public {
        bytes32 d = keccak256("d-contested");
        _consume(d, redeemer); // the victim's session key (works for AGENT) redeemed the co-signed delegation
        identity.setAuthorized(OTHER_AGENT, redeemer, true); // the attacker's agent "authorizes" the victim redeemer
        address attackerKey = makeAddr("attackerSessionKey");
        identity.setAuthorized(OTHER_AGENT, attackerKey, true);

        // the attacker, its session key and any relayer the attacker pays cannot attest, for either agent
        _expectAttestRevert(otherAgentOwner, OTHER_AGENT, d, IRiparReputationRelay.NotRedeemer.selector);
        _expectAttestRevert(attackerKey, OTHER_AGENT, d, IRiparReputationRelay.NotRedeemer.selector);
        _expectAttestRevert(makeAddr("mevRelayer"), OTHER_AGENT, d, IRiparReputationRelay.NotRedeemer.selector);
        _expectAttestRevert(otherAgentOwner, AGENT, d, IRiparReputationRelay.NotRedeemer.selector);
        assertFalse(relay.approvalAttested(d));
        assertEq(reputation.feedbackCount(), 0);

        // the victim credits its own agent
        _attest(redeemer, AGENT, d);
        _assertFeedback(0, AGENT, 1, "cosigned", d);

        // and nothing moves afterwards
        _expectAttestRevert(otherAgentOwner, OTHER_AGENT, d, IRiparReputationRelay.NotRedeemer.selector);
        _expectAttestRevert(redeemer, OTHER_AGENT, d, IRiparReputationRelay.AlreadyAttested.selector);
        assertEq(reputation.feedbackCount(), 1);
    }

    /// @dev The v1 front-run combined with finding 1: the attacker first calls beforeHook directly with the victim's
    ///      pending caveat args, naming its own session key as redeemer. That record is not the canonical one.
    function test_frontRun_directBeforeHookRecordIsIgnored() public {
        bytes32 d = keccak256("d-front-run-direct");
        address attackerKey = makeAddr("attackerSessionKey");
        identity.setAuthorized(OTHER_AGENT, attackerKey, true);
        _consumeVia(attackerKey, d, attackerKey); // attackerKey called beforeHook itself

        _expectAttestRevert(attackerKey, OTHER_AGENT, d, IRiparReputationRelay.NotConsumed.selector);

        _consume(d, redeemer); // the real redemption still goes through (per-manager replay protection)
        _expectAttestRevert(attackerKey, OTHER_AGENT, d, IRiparReputationRelay.NotRedeemer.selector);
        _attest(redeemer, AGENT, d);
        assertEq(reputation.feedbackCount(), 1);
        _assertFeedback(0, AGENT, 1, "cosigned", d);
    }

    /// @dev The one choice left: a redeemer authorized for several agents picks which one it credits (once).
    function test_attestApproval_redeemerChoosesAmongItsAgents() public {
        bytes32 d = keccak256("d-choice");
        _consume(d, redeemer);
        identity.setAuthorized(OTHER_AGENT, redeemer, true);
        _attest(redeemer, OTHER_AGENT, d);
        _expectAttestRevert(redeemer, AGENT, d, IRiparReputationRelay.AlreadyAttested.selector);
        _assertFeedback(0, OTHER_AGENT, 1, "cosigned", d);
        assertEq(reputation.feedbackCount(), 1);
    }

    function test_revert_attestApproval_notAgentRedeemer() public {
        bytes32 d = keccak256("d-stranger");
        address stranger = makeAddr("stranger");
        _consume(d, stranger); // the redeemer does not act for AGENT
        _expectAttestRevert(stranger, AGENT, d, IRiparReputationRelay.NotAgentRedeemer.selector);

        // the redeemer acts for AGENT, not for OTHER_AGENT: no feedback can be steered to another agent
        bytes32 d2 = keccak256("d-redeemer");
        _consume(d2, redeemer);
        _expectAttestRevert(redeemer, OTHER_AGENT, d2, IRiparReputationRelay.NotAgentRedeemer.selector);
        assertEq(reputation.feedbackCount(), 0);

        // once the identity registry authorizes it, the same digest can be attested
        identity.setAuthorized(OTHER_AGENT, redeemer, true);
        _attest(redeemer, OTHER_AGENT, d2);
        _assertFeedback(0, OTHER_AGENT, 1, "cosigned", d2);
    }

    function test_revert_attestApproval_revokedAuthorization() public {
        bytes32 d = keccak256("d-revoked");
        _consume(d, redeemer);
        identity.setAuthorized(AGENT, redeemer, false);
        _expectAttestRevert(redeemer, AGENT, d, IRiparReputationRelay.NotAgentRedeemer.selector);
    }

    function test_revert_attestApproval_once() public {
        bytes32 d = keccak256("d-once");
        _consume(d, redeemer);
        _attest(redeemer, AGENT, d);
        _expectAttestRevert(redeemer, AGENT, d, IRiparReputationRelay.AlreadyAttested.selector);

        // not even for another agent the redeemer also acts for
        identity.setAuthorized(OTHER_AGENT, redeemer, true);
        _expectAttestRevert(redeemer, OTHER_AGENT, d, IRiparReputationRelay.AlreadyAttested.selector);
        assertEq(reputation.feedbackCount(), 1);
    }

    /// @dev NotConsumed, NotRedeemer, UnknownDevice (v1.2), AgentIsShielded (v1.2), NotAgentRedeemer, AlreadyAttested.
    function test_attestApproval_checkOrder() public {
        bytes32 d = keccak256("d-order");
        address stranger = makeAddr("stranger");
        // SHIELDED_AGENT gets a shielded denial, so attestApproval refuses it
        _deny(P1_B, SHIELDED_AGENT, keccak256("denied request"), bytes32(0));
        assertEq(relay.shieldedDenials(SHIELDED_AGENT), 1);

        // not consumed (canonically), wrong caller, unauthorized / shielded agent -> NotConsumed
        _expectAttestRevert(stranger, OTHER_AGENT, d, IRiparReputationRelay.NotConsumed.selector);
        _expectAttestRevert(stranger, SHIELDED_AGENT, d, IRiparReputationRelay.NotConsumed.selector);
        _consumeVia(directCaller, d, stranger);
        _expectAttestRevert(stranger, OTHER_AGENT, d, IRiparReputationRelay.NotConsumed.selector);

        // consumed with an unregistered key: wrong caller -> NotRedeemer; redeemer -> UnknownDevice, whatever the agent
        _consumeWith(d, keccak256("software key"), address(vault), redeemer);
        _expectAttestRevert(stranger, OTHER_AGENT, d, IRiparReputationRelay.NotRedeemer.selector);
        _expectAttestRevert(redeemer, SHIELDED_AGENT, d, IRiparReputationRelay.UnknownDevice.selector);
        _expectAttestRevert(redeemer, OTHER_AGENT, d, IRiparReputationRelay.UnknownDevice.selector);
        _expectAttestRevert(redeemer, 999_999, d, IRiparReputationRelay.UnknownDevice.selector);

        // consumed with the vault owner's device: shielded agent -> AgentIsShielded (before NotAgentRedeemer)
        _consume(d, redeemer);
        _expectAttestRevert(stranger, SHIELDED_AGENT, d, IRiparReputationRelay.NotRedeemer.selector);
        _expectAttestRevert(redeemer, SHIELDED_AGENT, d, IRiparReputationRelay.AgentIsShielded.selector);
        // unauthorized / unknown agent -> NotAgentRedeemer
        _expectAttestRevert(redeemer, OTHER_AGENT, d, IRiparReputationRelay.NotAgentRedeemer.selector);
        _expectAttestRevert(redeemer, 999_999, d, IRiparReputationRelay.NotAgentRedeemer.selector);

        _attest(redeemer, AGENT, d);

        // attested, wrong caller -> NotRedeemer (before AlreadyAttested)
        _expectAttestRevert(stranger, AGENT, d, IRiparReputationRelay.NotRedeemer.selector);
        _expectAttestRevert(agentOwner, AGENT, d, IRiparReputationRelay.NotRedeemer.selector);
        // attested, redeemer, shielded agent -> AgentIsShielded; unauthorized / unknown agent -> NotAgentRedeemer
        _expectAttestRevert(redeemer, SHIELDED_AGENT, d, IRiparReputationRelay.AgentIsShielded.selector);
        _expectAttestRevert(redeemer, OTHER_AGENT, d, IRiparReputationRelay.NotAgentRedeemer.selector);
        _expectAttestRevert(redeemer, 999_999, d, IRiparReputationRelay.NotAgentRedeemer.selector);
        // attested, redeemer, authorized agent -> AlreadyAttested
        _expectAttestRevert(redeemer, AGENT, d, IRiparReputationRelay.AlreadyAttested.selector);
        // attested, but the vault owner rotated its device since -> UnknownDevice (before AlreadyAttested)
        registerPair(reg, P1_C, K1);
        _expectAttestRevert(redeemer, AGENT, d, IRiparReputationRelay.UnknownDevice.selector);
        assertEq(reputation.feedbackCount(), 1);
    }

    function testFuzz_attestApproval(bytes32 d, uint256 agentId, address red) public {
        vm.assume(red != address(0) && red != address(relay));
        vm.assume(agentId != SHIELDED_AGENT);
        if (identity.owners(agentId) == address(0)) identity.setOwner(agentId, makeAddr("fuzzAgentOwner"));
        identity.setAuthorized(agentId, red, true);
        enforcer.setApproval(DELEGATION_MANAGER, d, _approval(keyId, red));
        _attest(red, agentId, d);
        assertTrue(relay.approvalAttested(d));
        _assertFeedback(0, agentId, 1, "cosigned", d);
    }

    // ------------------------------------------------------------------ attestApproval: the vault owner's device (v1.2)

    /// @dev PERIPHERY-1 / ENF-2 / ATTACKER-2 at unit level: a co-sign made by a key the registry does not know (a
    ///      software P-256 key) is never credited, whatever vault it names.
    function test_revert_attestApproval_unregisteredKey() public {
        (bytes32 cx, bytes32 cy) = p256Key(P1_C);
        bytes32[3] memory keys = [p256KeyId(cx, cy), keccak256("software key"), bytes32(0)];
        for (uint256 i; i < keys.length; ++i) {
            bytes32 d = keccak256(abi.encode("d-unregistered", i));
            _consumeWith(d, keys[i], address(vault), redeemer);
            _expectAttestRevert(redeemer, AGENT, d, IRiparReputationRelay.UnknownDevice.selector);
            // not with a vault owned by nobody either (an unregistered key has owner 0: 0 == 0 must not pass)
            bytes32 d0 = keccak256(abi.encode("d-unregistered-zero-owner", i));
            _consumeWith(d0, keys[i], address(new MockVault(address(0))), redeemer);
            _expectAttestRevert(redeemer, AGENT, d0, IRiparReputationRelay.UnknownDevice.selector);
        }
        assertEq(reputation.feedbackCount(), 0);
    }

    function testFuzz_revert_attestApproval_unregisteredKey(bytes32 kid, bytes32 d) public {
        vm.assume(kid != keyId && kid != keyIdB);
        _consumeWith(d, kid, address(vault), redeemer);
        _expectAttestRevert(redeemer, AGENT, d, IRiparReputationRelay.UnknownDevice.selector);
        assertFalse(relay.approvalAttested(d));
    }

    /// @dev A registered key only counts for vaults its own owner owns.
    function test_revert_attestApproval_keyOfAnotherOwner() public {
        bytes32 d = keccak256("d-foreign-key");
        _consumeWith(d, keyIdB, address(vault), redeemer); // P1_B (ownerB's device) on owner's vault
        _expectAttestRevert(redeemer, AGENT, d, IRiparReputationRelay.UnknownDevice.selector);
        bytes32 d2 = keccak256("d-foreign-vault");
        _consumeWith(d2, keyId, address(vaultB), redeemer); // P1 (owner's device) on ownerB's vault
        _expectAttestRevert(redeemer, AGENT, d2, IRiparReputationRelay.UnknownDevice.selector);
        assertEq(reputation.feedbackCount(), 0);
    }

    /// @dev The vault's owner is read at attest time: a vault that changed owner no longer credits the old device.
    function test_revert_attestApproval_vaultOwnerChanged() public {
        bytes32 d = keccak256("d-owner-changed");
        _consume(d, redeemer);
        vault.setOwner(ownerB);
        _expectAttestRevert(redeemer, AGENT, d, IRiparReputationRelay.UnknownDevice.selector);
        vault.setOwner(makeAddr("owner without device"));
        _expectAttestRevert(redeemer, AGENT, d, IRiparReputationRelay.UnknownDevice.selector);
        vault.setOwner(address(0));
        _expectAttestRevert(redeemer, AGENT, d, IRiparReputationRelay.UnknownDevice.selector);
        vault.setOwner(owner);
        _attest(redeemer, AGENT, d);
        assertTrue(relay.approvalAttested(d));
    }

    function testFuzz_revert_attestApproval_foreignVaultOwner(address o, bytes32 d) public {
        vm.assume(o != owner);
        _consume(d, redeemer);
        vault.setOwner(o);
        _expectAttestRevert(redeemer, AGENT, d, IRiparReputationRelay.UnknownDevice.selector);
    }

    /// @dev The owner re-pairs with a new device: co-signs of the retired key no longer count, the new key's do.
    function test_revert_attestApproval_rotatedKey() public {
        bytes32 d = keccak256("d-old-key");
        _consume(d, redeemer);
        bytes32 newKeyId = registerPair(reg, P1_C, K1);
        assertTrue(reg.isRetired(keyId));
        _expectAttestRevert(redeemer, AGENT, d, IRiparReputationRelay.UnknownDevice.selector);

        bytes32 d2 = keccak256("d-new-key");
        _consumeWith(d2, newKeyId, address(vault), redeemer);
        vm.expectEmit(true, true, false, true, address(relay));
        emit Verdict(AGENT, newKeyId, d2, true);
        _attest(redeemer, AGENT, d2);
        assertEq(reputation.feedbackCount(), 1);
    }

    /// @dev The delegator's owner() is read like RiparSentinel does: no code, a revert, short or dirty return data,
    ///      or a state-changing owner() all read as "no owner" (UnknownDevice), never as a revert that bubbles up.
    function test_revert_attestApproval_vaultWithoutReadableOwner() public {
        address[8] memory vaults = [
            makeAddr("eoaVault"), // no code: the call succeeds with no return data
            address(0),
            address(new NoOwnerVault()), // no owner(), no fallback
            address(new RevertingOwnerVault()), // owner() reverts with a reason
            address(new ShortOwnerVault()), // 20 bytes of return data
            address(new DirtyOwnerVault(uint256(uint160(owner)) | (1 << 160))), // not an address
            address(reg), // a contract without owner()
            address(new StatefulOwnerVault(owner)) // owner() writes state: fails under STATICCALL
        ];
        for (uint256 i; i < vaults.length; ++i) {
            bytes32 d = keccak256(abi.encode("d-no-owner", i));
            _consumeWith(d, keyId, vaults[i], redeemer);
            _expectAttestRevert(redeemer, AGENT, d, IRiparReputationRelay.UnknownDevice.selector);
        }
        assertEq(reputation.feedbackCount(), 0);
    }

    function test_attestApproval_rawOwnerWordIsEnough() public {
        // a raw fallback returning exactly the owner word is accepted (only the ABI word matters)
        bytes32 d = keccak256("d-raw-owner");
        _consumeWith(d, keyId, address(new DirtyOwnerVault(uint256(uint160(owner)))), redeemer);
        _attest(redeemer, AGENT, d);
        assertTrue(relay.approvalAttested(d));
    }

    // ------------------------------------------------------------------ attestDenial

    function test_attestDenial_happyPath() public {
        bytes32 requestHash = keccak256("HumanApproval struct hash with presenceHash = 0");
        bytes32 presenceHash = _presence(bytes12(0), bytes16(keccak256("salt"))); // deny: all-zero evidence
        (bytes32 r, bytes32 s) = _denySig(P1, AGENT, requestHash, presenceHash);

        // v1.2: the shield pre-check asks whether the relay itself acts for the agent (it does not)
        vm.expectCall(address(identity), abi.encodeCall(IERC8004Identity.isAuthorizedOrOwner, (address(relay), AGENT)));
        vm.expectCall(
            address(reputation),
            abi.encodeCall(
                IERC8004Reputation.giveFeedback, (AGENT, int128(-1), uint8(0), "ripar", "denied", "", "", requestHash)
            )
        );
        vm.expectEmit(true, true, false, true, address(relay));
        emit Verdict(AGENT, keyId, requestHash, false);
        vm.recordLogs();
        vm.prank(makeAddr("anyRelayer"));
        relay.attestDenial(AGENT, requestHash, presenceHash, px, py, r, s);

        assertEq(_relayLogs(vm.getRecordedLogs()), 1, "Verdict only, no AgentShielded");
        assertTrue(relay.denialAttested(keyId, requestHash));
        assertEq(relay.shieldedDenials(AGENT), 0);
        assertEq(reputation.feedbackCount(), 1);
        _assertFeedback(0, AGENT, -1, "denied", requestHash);
    }

    function _relayLogs(Vm.Log[] memory logs) internal view returns (uint256 n) {
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter == address(relay)) ++n;
        }
    }

    function test_revert_attestDenial_unknownDevice() public {
        bytes32 requestHash = keccak256("req");
        (bytes32 cx, bytes32 cy) = p256Key(P1_C);
        (bytes32 r, bytes32 s) = _denySig(P1_C, AGENT, requestHash, bytes32(0)); // valid sig, unregistered key
        vm.expectRevert(IRiparReputationRelay.UnknownDevice.selector);
        relay.attestDenial(AGENT, requestHash, bytes32(0), cx, cy, r, s);

        vm.expectRevert(IRiparReputationRelay.UnknownDevice.selector);
        relay.attestDenial(AGENT, requestHash, bytes32(0), bytes32(0), bytes32(0), r, s);
        assertEq(reputation.feedbackCount(), 0);
    }

    function test_revert_attestDenial_unlinkedKey() public {
        // the owner re-pairs with a new key: the old (retired) key no longer counts, the new one does
        registerPair(reg, P1_C, K1);
        assertTrue(reg.isRetired(keyId));
        bytes32 requestHash = keccak256("req");
        (bytes32 r, bytes32 s) = _denySig(P1, AGENT, requestHash, bytes32(0));
        vm.expectRevert(IRiparReputationRelay.UnknownDevice.selector);
        relay.attestDenial(AGENT, requestHash, bytes32(0), px, py, r, s);
        _deny(P1_C, AGENT, requestHash, bytes32(0));
        assertEq(reputation.feedbackCount(), 1);
    }

    function test_revert_attestDenial_badSignature() public {
        bytes32 requestHash = keccak256("req");
        bytes32 presenceHash = keccak256("presence");
        (bytes32 r, bytes32 s) = _denySig(P1, AGENT, requestHash, presenceHash);

        // the signature binds agentId, requestHash and presenceHash
        vm.expectRevert(IRiparReputationRelay.BadDenySignature.selector);
        relay.attestDenial(OTHER_AGENT, requestHash, presenceHash, px, py, r, s);
        vm.expectRevert(IRiparReputationRelay.BadDenySignature.selector);
        relay.attestDenial(AGENT, keccak256("other req"), presenceHash, px, py, r, s);
        vm.expectRevert(IRiparReputationRelay.BadDenySignature.selector);
        relay.attestDenial(AGENT, requestHash, bytes32(0), px, py, r, s);

        // another registered device's signature presented with this device's key
        (bytes32 rb, bytes32 sb) = _denySig(P1_B, AGENT, requestHash, presenceHash);
        vm.expectRevert(IRiparReputationRelay.BadDenySignature.selector);
        relay.attestDenial(AGENT, requestHash, presenceHash, px, py, rb, sb);

        // high-s twin
        vm.expectRevert(IRiparReputationRelay.BadDenySignature.selector);
        relay.attestDenial(AGENT, requestHash, presenceHash, px, py, r, p256HighS(s));

        // zero signature
        vm.expectRevert(IRiparReputationRelay.BadDenySignature.selector);
        relay.attestDenial(AGENT, requestHash, presenceHash, px, py, bytes32(0), bytes32(0));

        assertEq(reputation.feedbackCount(), 0);
        assertFalse(relay.denialAttested(keyId, requestHash));

        // the genuine one still works
        relay.attestDenial(AGENT, requestHash, presenceHash, px, py, r, s);
        assertTrue(relay.denialAttested(keyId, requestHash));
    }

    function test_revert_attestDenial_otherDomain() public {
        RiparReputationRelay relay2 = _newRelay(DELEGATION_MANAGER);
        bytes32 requestHash = keccak256("req");
        (bytes32 r, bytes32 s) = p256Sign(P1, relay2.denyDigest(AGENT, requestHash, bytes32(0)));
        vm.expectRevert(IRiparReputationRelay.BadDenySignature.selector);
        relay.attestDenial(AGENT, requestHash, bytes32(0), px, py, r, s);
    }

    function testFuzz_revert_attestDenial_garbageSig(bytes32 r, bytes32 s) public {
        bytes32 requestHash = keccak256("req");
        (bytes32 gr, bytes32 gs) = _denySig(P1, AGENT, requestHash, bytes32(0));
        vm.assume(r != gr || s != gs);
        vm.expectRevert(IRiparReputationRelay.BadDenySignature.selector);
        relay.attestDenial(AGENT, requestHash, bytes32(0), px, py, r, s);
    }

    function test_revert_attestDenial_oncePerKeyAndRequest() public {
        bytes32 requestHash = keccak256("req");
        _deny(P1, AGENT, requestHash, bytes32(0));

        // replay
        (bytes32 r, bytes32 s) = _denySig(P1, AGENT, requestHash, bytes32(0));
        vm.expectRevert(IRiparReputationRelay.AlreadyAttested.selector);
        relay.attestDenial(AGENT, requestHash, bytes32(0), px, py, r, s);

        // a fresh signature with another presenceHash (new salt) for the same request
        bytes32 presence2 = _presence(bytes12(0), bytes16(uint128(2)));
        (r, s) = _denySig(P1, AGENT, requestHash, presence2);
        vm.expectRevert(IRiparReputationRelay.AlreadyAttested.selector);
        relay.attestDenial(AGENT, requestHash, presence2, px, py, r, s);

        // the same request hash filed against another agent still counts once per (keyId, requestHash)
        (r, s) = _denySig(P1, OTHER_AGENT, requestHash, bytes32(0));
        vm.expectRevert(IRiparReputationRelay.AlreadyAttested.selector);
        relay.attestDenial(OTHER_AGENT, requestHash, bytes32(0), px, py, r, s);

        assertEq(reputation.feedbackCount(), 1);

        // another request by the same device, and the same request by another device, both count
        _deny(P1, AGENT, keccak256("req 2"), bytes32(0));
        _deny(P1_B, AGENT, requestHash, bytes32(0));
        assertEq(reputation.feedbackCount(), 3);
        assertTrue(relay.denialAttested(keyIdB, requestHash));
        assertTrue(relay.denialAttested(keyId, keccak256("req 2")));
        _assertFeedback(2, AGENT, -1, "denied", requestHash);
    }

    function test_attestDenial_checkOrder() public {
        bytes32 requestHash = keccak256("req");
        // UnknownDevice before the signature check
        (bytes32 cx, bytes32 cy) = p256Key(P1_C);
        vm.expectRevert(IRiparReputationRelay.UnknownDevice.selector);
        relay.attestDenial(AGENT, requestHash, bytes32(0), cx, cy, bytes32(0), bytes32(0));
        // BadDenySignature before AlreadyAttested
        _deny(P1, AGENT, requestHash, bytes32(0));
        vm.expectRevert(IRiparReputationRelay.BadDenySignature.selector);
        relay.attestDenial(AGENT, requestHash, bytes32(0), px, py, bytes32(0), bytes32(0));
    }

    function test_attestDenial_doesNotReadEnforcer() public {
        // a denial does not depend on the enforcer or the DelegationManager (anyone may relay it)
        bytes32 requestHash = keccak256("req");
        (bytes32 r, bytes32 s) = _denySig(P1, AGENT, requestHash, bytes32(0));
        vm.etch(address(enforcer), hex"fe"); // any call to the enforcer would now revert
        vm.prank(makeAddr("anyRelayer"));
        relay.attestDenial(AGENT, requestHash, bytes32(0), px, py, r, s);
        assertTrue(relay.denialAttested(keyId, requestHash));
    }

    function test_attestDenial_andApproval_independent() public {
        // the same bytes32 used as an approval digest and as a request hash are tracked separately
        bytes32 h = keccak256("shared");
        _consume(h, redeemer);
        _attest(redeemer, AGENT, h);
        _deny(P1, AGENT, h, bytes32(0));
        assertTrue(relay.approvalAttested(h));
        assertTrue(relay.denialAttested(keyId, h));
        _assertFeedback(0, AGENT, 1, "cosigned", h);
        _assertFeedback(1, AGENT, -1, "denied", h);
    }

    // ------------------------------------------------------------------ live ERC-8004 behaviour

    function test_revert_attestApproval_unknownAgent_isNotAgentRedeemer() public {
        // the live IdentityRegistry reverts ERC721NonexistentToken; the relay maps that to NotAgentRedeemer
        bytes32 d = keccak256("d-unknown-agent");
        _consume(d, redeemer);
        _expectAttestRevert(redeemer, 999_999, d, IRiparReputationRelay.NotAgentRedeemer.selector);
    }

    function test_revert_attestDenial_unknownAgent_bubbles() public {
        // a denial names an agent the registries do not know: the shield pre-check reads the identity revert as
        // "not authorized", so the ReputationRegistry is called and its revert bubbles up; nothing is recorded
        bytes32 requestHash = keccak256("req");
        (bytes32 r, bytes32 s) = _denySig(P1, 999_999, requestHash, bytes32(0));
        vm.expectRevert(abi.encodeWithSelector(MockERC8004Identity.ERC721NonexistentToken.selector, 999_999));
        relay.attestDenial(999_999, requestHash, bytes32(0), px, py, r, s);
        assertFalse(relay.denialAttested(keyId, requestHash));
        assertEq(relay.shieldedDenials(999_999), 0);
    }

    // ------------------------------------------------------------------ shield (v1.2)

    /// @dev The agent's owner made the relay an operator of its agent: ERC-8004 would refuse the feedback as
    ///      self-feedback, so the relay records the denial itself and does not call giveFeedback.
    function test_attestDenial_shielded_recordsWithoutFeedback() public {
        bytes32 requestHash = keccak256("denied while shielded");
        bytes32 presenceHash = _presence(bytes12(0), bytes16(keccak256("salt")));
        (bytes32 r, bytes32 s) = _denySig(P1, SHIELDED_AGENT, requestHash, presenceHash);
        assertTrue(identity.isAuthorizedOrOwner(address(relay), SHIELDED_AGENT));

        vm.expectCall(
            address(identity), abi.encodeCall(IERC8004Identity.isAuthorizedOrOwner, (address(relay), SHIELDED_AGENT))
        );
        vm.expectCall(address(reputation), abi.encodeWithSelector(IERC8004Reputation.giveFeedback.selector), 0);
        vm.expectEmit(true, true, false, true, address(relay));
        emit Verdict(SHIELDED_AGENT, keyId, requestHash, false);
        vm.expectEmit(true, true, false, true, address(relay));
        emit AgentShielded(SHIELDED_AGENT, keyId, requestHash);
        vm.recordLogs();
        vm.prank(makeAddr("anyRelayer"));
        relay.attestDenial(SHIELDED_AGENT, requestHash, presenceHash, px, py, r, s);

        assertEq(_relayLogs(vm.getRecordedLogs()), 2, "Verdict then AgentShielded");
        assertTrue(relay.denialAttested(keyId, requestHash));
        assertEq(relay.shieldedDenials(SHIELDED_AGENT), 1);
        assertEq(relay.shieldedDenials(AGENT), 0);
        assertEq(reputation.feedbackCount(), 0);
    }

    /// @dev The relay is authorized when it OWNS the agent, too (isAuthorizedOrOwner).
    function test_attestDenial_shielded_relayOwnsAgent() public {
        identity.setOwner(OTHER_AGENT, address(relay));
        vm.expectEmit(true, true, false, true, address(relay));
        emit AgentShielded(OTHER_AGENT, keyId, keccak256("req"));
        _deny(P1, OTHER_AGENT, keccak256("req"), bytes32(0));
        assertEq(relay.shieldedDenials(OTHER_AGENT), 1);
        assertEq(reputation.feedbackCount(), 0);
    }

    function test_attestDenial_shielded_countsEachDenialOnce() public {
        _deny(P1, SHIELDED_AGENT, keccak256("req 1"), bytes32(0));
        _deny(P1, SHIELDED_AGENT, keccak256("req 2"), bytes32(0));
        _deny(P1_B, SHIELDED_AGENT, keccak256("req 1"), bytes32(0));
        assertEq(relay.shieldedDenials(SHIELDED_AGENT), 3);

        // a replay, even with a fresh presenceHash or against another agent, counts nothing
        (bytes32 r, bytes32 s) = _denySig(P1, SHIELDED_AGENT, keccak256("req 1"), keccak256("salt 2"));
        vm.expectRevert(IRiparReputationRelay.AlreadyAttested.selector);
        relay.attestDenial(SHIELDED_AGENT, keccak256("req 1"), keccak256("salt 2"), px, py, r, s);
        (r, s) = _denySig(P1, AGENT, keccak256("req 2"), bytes32(0));
        vm.expectRevert(IRiparReputationRelay.AlreadyAttested.selector);
        relay.attestDenial(AGENT, keccak256("req 2"), bytes32(0), px, py, r, s);

        assertEq(relay.shieldedDenials(SHIELDED_AGENT), 3);
        assertEq(relay.shieldedDenials(AGENT), 0);
        assertEq(reputation.feedbackCount(), 0);
    }

    /// @dev The shield only diverts the feedback: UnknownDevice, BadDenySignature and AlreadyAttested still come first.
    function test_attestDenial_shielded_checkOrder() public {
        bytes32 requestHash = keccak256("req");
        (bytes32 cx, bytes32 cy) = p256Key(P1_C);
        (bytes32 r, bytes32 s) = _denySig(P1_C, SHIELDED_AGENT, requestHash, bytes32(0));
        vm.expectRevert(IRiparReputationRelay.UnknownDevice.selector);
        relay.attestDenial(SHIELDED_AGENT, requestHash, bytes32(0), cx, cy, r, s);
        vm.expectRevert(IRiparReputationRelay.BadDenySignature.selector);
        relay.attestDenial(SHIELDED_AGENT, requestHash, bytes32(0), px, py, r, s);
        _deny(P1, SHIELDED_AGENT, requestHash, bytes32(0));
        (r, s) = _denySig(P1, SHIELDED_AGENT, requestHash, bytes32(0));
        vm.expectRevert(IRiparReputationRelay.AlreadyAttested.selector);
        relay.attestDenial(SHIELDED_AGENT, requestHash, bytes32(0), px, py, r, s);
        assertEq(relay.shieldedDenials(SHIELDED_AGENT), 1);
    }

    /// @dev PERIPHERY-5 at unit level. Before v1.2 an agent that authorized the relay made every denial revert
    ///      ("Self-feedback not allowed") and lifted the authorization only inside its own attestApproval.
    function test_shield_cannotBlockDenials_andBarsApprovals() public {
        address shieldedRedeemer = makeAddr("shieldedAgentSessionKey");
        identity.setAuthorized(SHIELDED_AGENT, shieldedRedeemer, true);
        bytes32 d1 = keccak256("d-before-denial");
        bytes32 d2 = keccak256("d-after-denial");
        _consume(d1, shieldedRedeemer);
        _consume(d2, shieldedRedeemer);

        // with the shield up the ReputationRegistry refuses approvals (self-feedback) ...
        vm.expectRevert(bytes("Self-feedback not allowed"));
        vm.prank(shieldedRedeemer);
        relay.attestApproval(SHIELDED_AGENT, d1);
        // ... so the agent lifts it just for its own approval: allowed while no denial was recorded
        identity.setAuthorized(SHIELDED_AGENT, address(relay), false);
        _attest(shieldedRedeemer, SHIELDED_AGENT, d1);
        identity.setAuthorized(SHIELDED_AGENT, address(relay), true);
        assertEq(reputation.feedbackCount(), 1);

        // a device denies the agent while the shield is up: recorded, not reverted
        bytes32 requestHash = keccak256("a request the user denied");
        _deny(P1, SHIELDED_AGENT, requestHash, bytes32(0));
        assertTrue(relay.denialAttested(keyId, requestHash));
        assertEq(relay.shieldedDenials(SHIELDED_AGENT), 1);

        // from now on the agent collects no approval, shield up or lifted
        _expectAttestRevert(shieldedRedeemer, SHIELDED_AGENT, d2, IRiparReputationRelay.AgentIsShielded.selector);
        identity.setAuthorized(SHIELDED_AGENT, address(relay), false);
        _expectAttestRevert(shieldedRedeemer, SHIELDED_AGENT, d2, IRiparReputationRelay.AgentIsShielded.selector);
        assertFalse(relay.approvalAttested(d2));

        // with the shield lifted, later denials reach the ReputationRegistry again; the shielded count stays
        _deny(P1_B, SHIELDED_AGENT, requestHash, bytes32(0));
        assertEq(relay.shieldedDenials(SHIELDED_AGENT), 1);
        assertEq(reputation.feedbackCount(), 2);
        _assertFeedback(1, SHIELDED_AGENT, -1, "denied", requestHash);
        _expectAttestRevert(shieldedRedeemer, SHIELDED_AGENT, d2, IRiparReputationRelay.AgentIsShielded.selector);
    }

    /// @dev AgentIsShielded is per agent: the same redeemer and digest can still credit another agent it works for.
    function test_shield_isPerAgent() public {
        _deny(P1, SHIELDED_AGENT, keccak256("req"), bytes32(0));
        bytes32 d = keccak256("d-per-agent");
        _consume(d, redeemer);
        identity.setAuthorized(SHIELDED_AGENT, redeemer, true);
        _expectAttestRevert(redeemer, SHIELDED_AGENT, d, IRiparReputationRelay.AgentIsShielded.selector);
        _attest(redeemer, AGENT, d);
        _assertFeedback(0, AGENT, 1, "cosigned", d);
    }

    /// @dev The pre-check reads a reverting isAuthorizedOrOwner as "not authorized": the denial goes to giveFeedback.
    function test_attestDenial_shieldPrecheckRevert_countsAsNotAuthorized() public {
        RevertingForIdentity reverting = new RevertingForIdentity();
        MockERC8004Identity plain = new MockERC8004Identity();
        plain.setOwner(AGENT, agentOwner);
        MockERC8004Reputation rep2 = new MockERC8004Reputation(address(plain));
        RiparReputationRelay relay2 = new RiparReputationRelay(
            IERC8004Reputation(address(rep2)),
            IERC8004Identity(address(reverting)),
            IPulseCosignEnforcer(address(enforcer)),
            reg,
            DELEGATION_MANAGER
        );
        reverting.setRevertFor(address(relay2));
        bytes32 requestHash = keccak256("req");
        (bytes32 r, bytes32 s) = p256Sign(P1, relay2.denyDigest(AGENT, requestHash, bytes32(0)));
        relay2.attestDenial(AGENT, requestHash, bytes32(0), px, py, r, s);
        assertEq(relay2.shieldedDenials(AGENT), 0);
        assertTrue(relay2.denialAttested(keyId, requestHash));
        assertEq(rep2.feedbackCount(), 1);
    }

    function testFuzz_attestDenial_shielded(uint256 agentId, bytes32 requestHash, bytes32 presenceHash) public {
        if (identity.owners(agentId) == address(0)) identity.setOwner(agentId, makeAddr("fuzzAgentOwner"));
        identity.setAuthorized(agentId, address(relay), true);
        uint256 before = relay.shieldedDenials(agentId);
        (bytes32 r, bytes32 s) = _denySig(P1, agentId, requestHash, presenceHash);
        vm.expectEmit(true, true, false, true, address(relay));
        emit AgentShielded(agentId, keyId, requestHash);
        relay.attestDenial(agentId, requestHash, presenceHash, px, py, r, s);
        assertEq(relay.shieldedDenials(agentId), before + 1);
        assertTrue(relay.denialAttested(keyId, requestHash));
        assertEq(reputation.feedbackCount(), 0);
    }

    function testFuzz_attestDenial(uint256 agentId, bytes32 requestHash, bytes32 presenceHash) public {
        vm.assume(agentId != SHIELDED_AGENT);
        if (identity.owners(agentId) == address(0)) identity.setOwner(agentId, makeAddr("fuzzAgentOwner"));
        (bytes32 r, bytes32 s) = _denySig(P1, agentId, requestHash, presenceHash);
        vm.expectEmit(true, true, false, true, address(relay));
        emit Verdict(agentId, keyId, requestHash, false);
        relay.attestDenial(agentId, requestHash, presenceHash, px, py, r, s);
        assertTrue(relay.denialAttested(keyId, requestHash));
        assertEq(relay.shieldedDenials(agentId), 0);
        _assertFeedback(0, agentId, -1, "denied", requestHash);
    }
}

/// @notice OZ P256 Solidity fallback (no code at 0x0100, like a local EVM).
contract RiparReputationRelayTest is RiparReputationRelayTestBase {
    function setUp() public override {
        super.setUp();
        _setUpP256Path(false);
    }
}

/// @notice P256VERIFY precompile at 0x0100 (like Monad).
contract RiparReputationRelayPrecompileTest is RiparReputationRelayTestBase {
    function setUp() public override {
        super.setUp();
        _setUpP256Path(true);
    }

    function test_attestDenial_usesPrecompile() public {
        bytes32 requestHash = keccak256("req");
        bytes32 d = relay.denyDigest(AGENT, requestHash, bytes32(0));
        (bytes32 r, bytes32 s) = p256Sign(P1, d);
        vm.expectCall(P256_PRECOMPILE, abi.encode(d, r, s, px, py));
        relay.attestDenial(AGENT, requestHash, bytes32(0), px, py, r, s);
    }
}
