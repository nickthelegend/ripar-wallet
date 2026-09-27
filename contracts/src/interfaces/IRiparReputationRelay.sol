// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/// @title IRiparReputationRelay
/// @notice Turns human verdicts into ERC-8004 reputation feedback for the agent.
///         - approval: a co-signature the PulseCosignEnforcer consumed in a redemption through the canonical
///           DelegationManager, attested by its redeemer (msg.sender) for an agentId the redeemer is authorized for in
///           the ERC-8004 IdentityRegistry -> giveFeedback(agentId, +1, 0, "ripar", "cosigned", "", "", digest)
///         - denial: Deny(agentId, requestHash, presenceHash) signed by a registered Ripar device (P1) under the
///           EIP-712 domain name "RiparReputationRelay", version "1" (docs/PROTOCOL.md §3, `ripar-deny`)
///           -> giveFeedback(agentId, -1, 0, "ripar", "denied", "", "", requestHash)
///         Each approval digest and each (keyId, requestHash) counts once.
interface IRiparReputationRelay {
    event Verdict(uint256 indexed agentId, bytes32 indexed keyId, bytes32 requestHash, bool approved);
    /// @notice v1.2: a denial for an agent whose owner made this relay an authorized operator (ERC-8004 then refuses the
    ///         feedback as self-feedback). The denial is still recorded; the agent can no longer collect approvals.
    event AgentShielded(uint256 indexed agentId, bytes32 indexed keyId, bytes32 requestHash);

    error NotConsumed();
    error NotRedeemer();
    error NotAgentRedeemer();
    error AlreadyAttested();
    error UnknownDevice();
    error BadDenySignature();
    error AgentIsShielded();

    function domainSeparator() external view returns (bytes32);
    function delegationManager() external view returns (address);
    function denyDigest(uint256 agentId, bytes32 requestHash, bytes32 presenceHash) external view returns (bytes32);

    /// @notice Only the approval's redeemer may attest it (so nobody can credit another agent's approvals).
    function attestApproval(uint256 agentId, bytes32 approvalDigest) external;
    function attestDenial(
        uint256 agentId,
        bytes32 requestHash,
        bytes32 presenceHash,
        bytes32 px,
        bytes32 py,
        bytes32 r,
        bytes32 s
    )
        external;

    function approvalAttested(bytes32 approvalDigest) external view returns (bool);
    /// @notice number of denials recorded while the agent shielded itself from feedback (v1.2)
    function shieldedDenials(uint256 agentId) external view returns (uint256);
    function denialAttested(bytes32 keyId, bytes32 requestHash) external view returns (bool);
}
