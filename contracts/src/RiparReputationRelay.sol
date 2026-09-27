// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { P256 } from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import { IERC173 } from "@delegation-framework/interfaces/IERC173.sol";

import { IRiparReputationRelay } from "./interfaces/IRiparReputationRelay.sol";
import { IPulseCosignEnforcer } from "./interfaces/IPulseCosignEnforcer.sol";
import { IRiparDeviceRegistry } from "./interfaces/IRiparDeviceRegistry.sol";
import { IERC8004Identity, IERC8004Reputation } from "./interfaces/external/IERC8004.sol";

/// @title RiparReputationRelay
/// @notice Turns human verdicts into ERC-8004 reputation feedback for an agent. No admin, no upgradability.
///         - Approval: a human co-signature the PulseCosignEnforcer consumed in a redemption through the canonical
///           DelegationManager (`delegationManager`, an immutable), made by the registered Ripar device of the
///           vault's owner (v1.2), attested by that redemption's redeemer (msg.sender) for an agentId the ERC-8004
///           IdentityRegistry authorizes the redeemer for
///           -> giveFeedback(agentId, +1, 0, "ripar", "cosigned", "", "", approvalDigest).
///         - Denial: `Deny(uint256 agentId,bytes32 requestHash,bytes32 presenceHash)` signed by a registered Ripar
///           device's P-256 key under the EIP-712 domain name "RiparReputationRelay", version "1"
///           (docs/PROTOCOL.md §3, `ripar-deny`); anyone may relay it
///           -> giveFeedback(agentId, -1, 0, "ripar", "denied", "", "", requestHash).
///         Each approval digest, and each (keyId, requestHash), counts once.
/// @dev    DEVICE (v1.2): an approval counts only when the co-signing key (approval.keyId) is registered in the
///         RiparDeviceRegistry to the current owner of the vault (IERC173(approval.delegator).owner(), read with a
///         safe staticcall). Without this anyone could mint "cosigned" +1s with a software P-256 key and a throwaway
///         vault (or a contract that accepts every delegation signature), or launder AUTO spends into co-sign
///         records by re-delegating a mandate to itself under its own Pulse caveat.
///         SHIELD (v1.2): the ERC-8004 ReputationRegistry refuses feedback from a caller that isAuthorizedOrOwner for
///         the agent. An agent owner who makes this relay an operator of its agent would make every denial revert,
///         and could lift that approval just inside its own attestApproval transaction. So attestDenial first asks
///         the IdentityRegistry whether this relay is authorized for the agent; if so, the denial is still recorded
///         (denialAttested, shieldedDenials[agentId] += 1, Verdict + AgentShielded) without calling giveFeedback, and
///         attestApproval refuses the agent for good (AgentIsShielded) once it has a shielded denial.
///         TRUST (v1.1): only the canonical DelegationManager's approval records count. The enforcer keys records and
///         replay protection by (manager, digest), where manager is beforeHook's msg.sender, so a record made by
///         anyone calling beforeHook directly lives under that caller's address and is never read here.
///         Only the approval's redeemer may attest it: another agent's owner cannot take the credit by authorizing
///         the redeemer for its own agent (ERC-721 approve) and attesting first. The redeemer chooses which of the
///         agents it is authorized for gets the credit; a redeemer that is a smart account must make the call
///         itself (e.g. through its own execute).
///         KNOWN LIMITATION 1: anyone can register a device key in the RiparDeviceRegistry, so denials are Sybil-able
///         (one party can file many denials against an agent with many keys) and a denial's requestHash is opaque
///         on-chain (it need not match any real request). Reputation readers should weigh the verdicts, e.g. by
///         filtering on the feedback client (this relay) and on keyIds or vault owners they trust.
///         KNOWN LIMITATION 2: for the same reason approvals are only as trustworthy as the registered key. The device
///         check ties the co-signing key to the vault's owner, not to genuine Ripar hardware: whoever registers a key
///         of its own (a software P-256 key and its own K1) and delegates from a vault that K1 owns can still co-sign
///         requests of its own agent, one +1 per co-sign (and a smart-account agent whose owner() has a registered
///         key can do the same with a re-delegated mandate). Every Verdict names the keyId, which is now always the
///         vault owner's registered key, so readers can weigh approvals by keyId or vault owner like denials.
///         KNOWN LIMITATION 3: a denial filed against a shielded agent lives only here (shieldedDenials and the
///         Verdict / AgentShielded events), not in the ReputationRegistry; readers should read shieldedDenials too.
contract RiparReputationRelay is IRiparReputationRelay, EIP712 {
    /// @notice keccak256("Deny(uint256 agentId,bytes32 requestHash,bytes32 presenceHash)")
    bytes32 public constant DENY_TYPEHASH = keccak256("Deny(uint256 agentId,bytes32 requestHash,bytes32 presenceHash)");

    /// @notice ERC-8004 ReputationRegistry that receives the feedback (this contract is the feedback client).
    IERC8004Reputation public immutable reputation;
    /// @notice ERC-8004 IdentityRegistry that says which addresses act for an agent.
    IERC8004Identity public immutable identity;
    /// @notice PulseCosignEnforcer whose consumed co-signatures count as approvals.
    IPulseCosignEnforcer public immutable enforcer;
    /// @notice RiparDeviceRegistry whose registered keys may file denials, and whose binding of a vault owner to its
    ///         device key decides which co-signatures count as approvals (v1.2).
    IRiparDeviceRegistry public immutable registry;
    /// @notice The canonical MetaMask DelegationManager (v1.3.0: 0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3, the one
    ///         the firmware pins). Only the enforcer's records under this manager count as approvals.
    address public immutable delegationManager;

    /// @notice approval digest => already attested
    mapping(bytes32 approvalDigest => bool) public approvalAttested;
    /// @notice keyId => requestHash => already attested
    mapping(bytes32 keyId => mapping(bytes32 requestHash => bool)) public denialAttested;
    /// @notice agentId => number of denials recorded while this relay was authorized for the agent (v1.2). While it
    ///         is non-zero the agent cannot collect approvals (AgentIsShielded). It never decreases.
    mapping(uint256 agentId => uint256) public shieldedDenials;

    /// @param reputation_        ERC-8004 ReputationRegistry
    /// @param identity_          ERC-8004 IdentityRegistry
    /// @param enforcer_          PulseCosignEnforcer
    /// @param registry_          RiparDeviceRegistry
    /// @param delegationManager_ the canonical DelegationManager whose redemptions count
    constructor(
        IERC8004Reputation reputation_,
        IERC8004Identity identity_,
        IPulseCosignEnforcer enforcer_,
        IRiparDeviceRegistry registry_,
        address delegationManager_
    ) EIP712("RiparReputationRelay", "1") {
        reputation = reputation_;
        identity = identity_;
        enforcer = enforcer_;
        registry = registry_;
        delegationManager = delegationManager_;
    }

    // ------------------------------------------------------------------ views

    /// @notice The EIP-712 domain separator (name "RiparReputationRelay", version "1", this chain, this contract).
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @notice keccak256(0x1901 ‖ domainSeparator ‖ hashStruct(Deny(agentId, requestHash, presenceHash))): what the
    ///         device's P1 signs for a denial.
    function denyDigest(uint256 agentId, bytes32 requestHash, bytes32 presenceHash) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(DENY_TYPEHASH, agentId, requestHash, presenceHash)));
    }

    // ------------------------------------------------------------------ verdicts

    /// @notice Files +1 feedback for `agentId` for a human co-signature the enforcer consumed in a redemption through
    ///         the canonical DelegationManager. Only that redemption's redeemer may call it.
    /// @dev    Checks, in this order:
    ///         - NotConsumed unless enforcer.consumed(delegationManager, approvalDigest);
    ///         - NotRedeemer unless msg.sender == enforcer.approvalOf(delegationManager, approvalDigest).redeemer;
    ///         - UnknownDevice (v1.2) unless registry.keyOf(approval.keyId).owner is non-zero and equals
    ///           IERC173(approval.delegator).owner() (a vault whose owner() cannot be read also maps to UnknownDevice);
    ///         - AgentIsShielded (v1.2) while shieldedDenials[agentId] > 0;
    ///         - NotAgentRedeemer unless identity.isAuthorizedOrOwner(redeemer, agentId) returns true (a revert, e.g.
    ///           ERC721NonexistentToken for an unknown agentId, also maps to NotAgentRedeemer);
    ///         - AlreadyAttested when the digest was attested before (for any agent).
    ///         Emits Verdict(agentId, keyId, approvalDigest, true).
    /// @param agentId        the ERC-8004 agent id the redeemer acts for and credits
    /// @param approvalDigest the HumanApproval digest the enforcer consumed
    function attestApproval(uint256 agentId, bytes32 approvalDigest) external {
        address manager = delegationManager;
        if (!enforcer.consumed(manager, approvalDigest)) revert NotConsumed();
        IPulseCosignEnforcer.Approval memory a = enforcer.approvalOf(manager, approvalDigest);
        if (msg.sender != a.redeemer) revert NotRedeemer();
        if (!_isVaultOwnersDevice(a.keyId, a.delegator)) revert UnknownDevice();
        if (shieldedDenials[agentId] != 0) revert AgentIsShielded();
        if (!_actsForAgent(a.redeemer, agentId)) revert NotAgentRedeemer();
        if (approvalAttested[approvalDigest]) revert AlreadyAttested();

        approvalAttested[approvalDigest] = true;
        reputation.giveFeedback(agentId, 1, 0, "ripar", "cosigned", "", "", approvalDigest);
        emit Verdict(agentId, a.keyId, approvalDigest, true);
    }

    /// @notice Files -1 feedback for `agentId` for a request a registered device denied. Anyone may relay it.
    /// @dev    keyId = keccak256(abi.encode(px, py)). Reverts UnknownDevice unless registry.keyOf(keyId) has an owner,
    ///         BadDenySignature unless P256.verify(denyDigest(agentId, requestHash, presenceHash)) (low-s),
    ///         AlreadyAttested when (keyId, requestHash) was attested before. Then records the denial and:
    ///         - when identity.isAuthorizedOrOwner(address(this), agentId) is true (the agent's owner made this relay
    ///           an operator, so the ReputationRegistry would refuse the feedback as self-feedback; a revert counts as
    ///           false): shieldedDenials[agentId] += 1, emits Verdict(agentId, keyId, requestHash, false) and then
    ///           AgentShielded(agentId, keyId, requestHash), and does NOT call giveFeedback (v1.2);
    ///         - otherwise: giveFeedback(agentId, -1, 0, "ripar", "denied", "", "", requestHash) (its revert, e.g. for
    ///           an unknown agent, bubbles up and nothing is recorded) and emits Verdict(agentId, keyId, requestHash,
    ///           false).
    /// @param agentId      the ERC-8004 agent id the device denied (the agent of its last mandate)
    /// @param requestHash  what the device denied (hashStruct(HumanApproval) with presenceHash = 0, or a companion's)
    /// @param presenceHash sha256(evidence12 ‖ salt16) from the `ripar-deny` response (evidence may be all-zero)
    /// @param px           device P1 public key X
    /// @param py           device P1 public key Y
    /// @param r            P1 signature r
    /// @param s            P1 signature s (low-s)
    function attestDenial(
        uint256 agentId,
        bytes32 requestHash,
        bytes32 presenceHash,
        bytes32 px,
        bytes32 py,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 keyId = keccak256(abi.encode(px, py));
        (,, address owner) = registry.keyOf(keyId);
        if (owner == address(0)) revert UnknownDevice();
        if (!P256.verify(denyDigest(agentId, requestHash, presenceHash), r, s, px, py)) revert BadDenySignature();
        if (denialAttested[keyId][requestHash]) revert AlreadyAttested();

        denialAttested[keyId][requestHash] = true;
        if (_actsForAgent(address(this), agentId)) {
            // the agent shields itself from feedback: record the denial here and bar its approvals from now on
            ++shieldedDenials[agentId];
            emit Verdict(agentId, keyId, requestHash, false);
            emit AgentShielded(agentId, keyId, requestHash);
            return;
        }
        reputation.giveFeedback(agentId, -1, 0, "ripar", "denied", "", "", requestHash);
        emit Verdict(agentId, keyId, requestHash, false);
    }

    // ------------------------------------------------------------------ internal

    /// @dev true iff `keyId` is registered in the registry to the current owner of `vault` (its IERC173 owner()).
    ///      An unregistered key (owner 0), or a vault whose owner() cannot be read, gives false.
    function _isVaultOwnersDevice(bytes32 keyId, address vault) private view returns (bool) {
        (,, address keyOwner) = registry.keyOf(keyId);
        if (keyOwner == address(0)) return false;
        (bool ok, address vaultOwner) = _ownerOf(vault);
        return ok && vaultOwner == keyOwner;
    }

    /// @dev IERC173(vault).owner() without letting a missing function, a revert or malformed return data bubble up
    ///      (the same read as RiparSentinel's). A plain try/catch does not catch an EOA / no-code vault: the empty
    ///      return data fails to decode in the caller. Only the first 32 bytes of return data are copied.
    function _ownerOf(address vault) private view returns (bool ok, address owner) {
        bytes4 selector = IERC173.owner.selector;
        uint256 word;
        assembly ("memory-safe") {
            mstore(0x00, selector)
            ok := staticcall(gas(), vault, 0x00, 0x04, 0x00, 0x20)
            ok := and(ok, gt(returndatasize(), 0x1f))
            word := mload(0x00)
        }
        if (!ok || word >> 160 != 0) return (false, address(0));
        // casting to 'uint160' is safe because the upper 96 bits were checked to be zero just above
        // forge-lint: disable-next-line(unsafe-typecast)
        return (true, address(uint160(word)));
    }

    /// @dev identity.isAuthorizedOrOwner(who, agentId), with a revert (the live IdentityRegistry reverts
    ///      ERC721NonexistentToken for an unknown agentId) read as false. `identity` is an immutable, trusted registry.
    function _actsForAgent(address who, uint256 agentId) private view returns (bool) {
        try identity.isAuthorizedOrOwner(who, agentId) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }
}
