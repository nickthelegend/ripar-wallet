// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/// @title IRiparSentinel
/// @notice Per-vault "autonomous lane" switch read by PulseCosignEnforcer's AUTO path.
///         Chainlink CRE (through its KeystoneForwarder) can only CLOSE a lane; only the vault owner's registered
///         Ripar device can REOPEN it, with Reopen(vault, nonce) signed by P1 under the EIP-712 domain
///         name "RiparSentinel", version "1" (docs/PROTOCOL.md §3, `ripar-reopen`).
interface IRiparSentinel {
    event LaneChanged(address indexed vault, bool open, uint8 reason, uint64 asOfBlock);
    event ReportIgnored(address indexed vault, uint8 reason, uint64 asOfBlock);

    error NotForwarder();
    error BadWorkflowOwner();
    error BadReport();
    error NonceNotIncreasing();
    error NoDeviceForVault();
    error BadReopenSignature();
    error LaneNotClosed();

    /// @notice CRE IReceiver entry point. report = abi.encode(address vault, bool open, uint8 reason, uint64 asOfBlock).
    ///         Only msg.sender == forwarder. Only open == false is acted on (open == true reverts BadReport).
    ///         A close whose asOfBlock is older than the vault's last reopen block is ignored (ReportIgnored),
    ///         so a delayed report cannot undo a newer human reopen.
    function onReport(bytes calldata metadata, bytes calldata report) external;

    function laneOpen(address vault) external view returns (bool); // true unless closed
    function lastReopenNonce(address vault) external view returns (uint256);
    function domainSeparator() external view returns (bytes32);
    function reopenDigest(address vault, uint256 nonce) external view returns (bytes32);

    /// @notice Device-signed reopen. The key is registry.keyOf(registry.keyIdOf(IERC173(vault).owner())).
    ///         nonce must be > lastReopenNonce(vault). Anyone may relay. v1.2: reverts LaneNotClosed unless the lane
    ///         is closed, so a withheld reopen cannot pre-empt an in-flight close report.
    function reopen(address vault, uint256 nonce, bytes32 r, bytes32 s) external;
}
