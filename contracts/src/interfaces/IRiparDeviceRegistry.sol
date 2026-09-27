// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/// @title IRiparDeviceRegistry
/// @notice Binds a Ripar device's P-256 key (P1) to its secp256k1 vault owner (K1). Both keys come from the same
///         device seed, and both sign BindDevice(owner, px, py) under the EIP-712 domain
///         name "RiparDeviceRegistry", version "1" (docs/PROTOCOL.md §3, the `ripar-pair` response keys 2..5).
interface IRiparDeviceRegistry {
    event DeviceRegistered(address indexed owner, bytes32 indexed keyId, bytes32 px, bytes32 py);

    error ZeroOwner();
    error BadDeviceSignature();
    error BadOwnerSignature();
    error KeyTaken();

    function domainSeparator() external view returns (bytes32);
    function bindDigest(address owner, bytes32 px, bytes32 py) external view returns (bytes32);

    /// @param pr,ps   P1 signature (low-s) over bindDigest(owner, px, py)
    /// @param ownerSig K1 signature r‖s‖v (65 bytes, v = 27/28, low-s) over the same digest; must recover `owner`
    /// @dev Re-registering the same owner with a new device replaces its key; the old key is RETIRED (v1.2) and can
    ///      never be bound again (so an old BindDevice signature cannot roll the rotation back).
    ///      A key bound to a different owner, or retired, reverts KeyTaken.
    function registerDevice(
        address owner,
        bytes32 px,
        bytes32 py,
        bytes32 pr,
        bytes32 ps,
        bytes calldata ownerSig
    )
        external
        returns (bytes32 keyId);

    function keyIdOf(address owner) external view returns (bytes32); // 0 = none
    function isRetired(bytes32 keyId) external view returns (bool);
    function keyOf(bytes32 keyId) external view returns (bytes32 px, bytes32 py, address owner); // owner 0 = none
}
