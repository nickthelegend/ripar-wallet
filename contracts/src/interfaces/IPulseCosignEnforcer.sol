// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/// @title IPulseCosignEnforcer
/// @notice Caveat enforcer for MetaMask delegation-framework v1.3.0. An agent redeems a delegation on its own (AUTO path)
///         inside per-tx / per-period caps, to payees a human approved before, while the sentinel lane is open.
///         Everything else needs a P-256 co-signature from the Ripar device (HUMAN path), checked with the RIP-7212 /
///         EIP-7951 precompile at 0x0100 (OpenZeppelin P256, Solidity fallback off-chain).
/// @dev    EIP-712 domain: name "RiparPulseCosign", version "1" (docs/PROTOCOL.md §3). Byte-exact with the firmware.
interface IPulseCosignEnforcer {
    /// @notice Caveat terms = abi.encode(PulseTerms) = exactly 288 bytes, every word canonical (docs/PROTOCOL.md §4).
    struct PulseTerms {
        bytes32 px; // device P1 key (P-256), keyId = keccak256(abi.encode(px, py))
        bytes32 py;
        address token; // metered asset: address(0) = native coin only, else this ERC-20 only
        uint128 perTxAutoCap; // AUTO path: max per redemption (base units of the metered asset)
        uint128 periodAutoCap; // AUTO path: max per period
        uint32 period; // seconds; 0 = the period never resets (lifetime cap)
        uint64 epoch; // mandate dies when epoch < minEpoch(keyId) (device PANIC)
        bool newPayeeNeedsHuman; // AUTO path only to payees a human co-signed before under THIS mandate
        address sentinel; // RiparSentinel whose laneOpen(delegator) gates the AUTO path; address(0) = no sentinel
    }

    /// @notice What the enforcer remembers about a human co-signature consumed by a DelegationManager (read by
    ///         RiparReputationRelay, which only trusts the canonical DelegationManager's records).
    struct Approval {
        bytes32 keyId;
        bytes32 delegationHash;
        address delegator;
        address redeemer;
        address payee; // address(0) when the call has no decodable payee
        uint64 timestamp;
    }

    // HUMAN path caveat args = abi.encode(uint256 nonce, uint64 expiry, bytes32 presenceHash, bytes32 r, bytes32 s)
    // (exactly 160 bytes); AUTO path caveat args = empty.

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
    /// @notice v1.2: the payee of a human co-sign becomes an AUTO payee of that mandate (delegationHash) under that
    ///         DelegationManager only when the co-signed call is meterable for the mandate's asset (a native send
    ///         under native terms, or an ERC-20 `transfer` of terms.token with no native value) with a non-zero
    ///         amount. `approve` spenders, `transferFrom` recipients, zero-value and foreign-asset co-signs never do.
    ///         Revoke / panic kill the mandate, and with it its payee list.
    event PayeeApproved(address indexed delegationManager, bytes32 indexed delegationHash, address indexed payee);
    event Revoked(bytes32 indexed keyId, bytes32 indexed delegationHash);
    event Panicked(bytes32 indexed keyId, uint64 minEpoch);

    error InvalidTerms();
    error InvalidArgs();
    error HumanRequired();
    error LaneClosed();
    error DelegationRevoked();
    error StaleEpoch();
    error EpochNotIncreasing();
    error BadCosign();
    error CosignReplayed();
    error CosignExpired();
    error BadSignature();

    // ------------------------------------------------------------------ views / helpers
    function getTermsInfo(bytes calldata terms) external pure returns (PulseTerms memory);
    function keyIdOf(bytes32 px, bytes32 py) external pure returns (bytes32);
    function domainSeparator() external view returns (bytes32);

    /// @notice hashStruct(HumanApproval). With presenceHash = 0 this is the `requestHash` a device deny signs.
    function approvalStructHash(
        bytes32 delegationHash,
        address delegator,
        address redeemer,
        address target,
        uint256 value,
        bytes32 callDataHash,
        uint256 nonce,
        uint64 expiry,
        bytes32 presenceHash
    )
        external
        pure
        returns (bytes32);

    /// @notice keccak256(0x1901 ‖ domainSeparator ‖ approvalStructHash(...)): what the device's P1 signs.
    function approvalDigest(
        bytes32 delegationHash,
        address delegator,
        address redeemer,
        address target,
        uint256 value,
        bytes32 callDataHash,
        uint256 nonce,
        uint64 expiry,
        bytes32 presenceHash
    )
        external
        view
        returns (bytes32);

    function revokeDigest(bytes32 delegationHash) external view returns (bytes32);
    function panicDigest(uint64 minEpoch) external view returns (bytes32);

    /// @notice Co-sign replay protection is per DelegationManager (msg.sender of beforeHook): calling beforeHook
    ///         directly with someone's caveat args only consumes them for the caller's own address and cannot burn
    ///         the co-sign for the real DelegationManager.
    function consumed(address delegationManager, bytes32 approvalDigest) external view returns (bool);
    function approvalOf(address delegationManager, bytes32 approvalDigest) external view returns (Approval memory);
    function isRevoked(bytes32 keyId, bytes32 delegationHash) external view returns (bool);
    function minEpoch(bytes32 keyId) external view returns (uint64);
    /// @notice Raw stored AUTO accounting (updated lazily: an elapsed period is only reset by the next AUTO spend).
    function periodSpent(address delegationManager, bytes32 delegationHash) external view returns (uint256 spent, uint64 start);
    /// @notice AUTO budget with the period rollover applied, for companions / agents (`terms` = the caveat terms).
    ///         periodEnd = 0 when the period never resets (period 0) or nothing was spent yet.
    function autoBudget(
        address delegationManager,
        bytes32 delegationHash,
        bytes calldata terms
    )
        external
        view
        returns (uint256 spent, uint256 remaining, uint64 periodStart, uint64 periodEnd);
    function isKnownPayee(address delegationManager, bytes32 delegationHash, address payee) external view returns (bool);
    /// @notice v1.2: a co-sign nonce is single-use per (DelegationManager, mandate). Signing the same request twice
    ///         (same nonce, fresh presence salt) can no longer pay twice.
    function nonceUsed(address delegationManager, bytes32 delegationHash, uint256 nonce) external view returns (bool);

    // ------------------------------------------------------------------ device-signed kill switch (anyone may relay)
    /// @notice Revoke(delegationHash) signed by the device key (px, py). Idempotent.
    function revoke(bytes32 px, bytes32 py, bytes32 delegationHash, bytes32 r, bytes32 s) external;
    /// @notice Panic(minEpoch) signed by the device key: every mandate with terms.epoch < newMinEpoch dies.
    ///         Reverts EpochNotIncreasing unless newMinEpoch > minEpoch(keyId).
    function panic(bytes32 px, bytes32 py, uint64 newMinEpoch, bytes32 r, bytes32 s) external;
}
