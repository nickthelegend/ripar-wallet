// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { P256 } from "@openzeppelin/contracts/utils/cryptography/P256.sol";

import { IRiparDeviceRegistry } from "./interfaces/IRiparDeviceRegistry.sol";

/// @title RiparDeviceRegistry
/// @notice Public, permissionless binding between a Ripar device's P-256 key (P1) and its secp256k1 vault owner (K1).
///         Both keys sign `BindDevice(address owner,bytes32 px,bytes32 py)` under the EIP-712 domain
///         name "RiparDeviceRegistry", version "1" (docs/PROTOCOL.md §3, `ripar-pair` response keys 2..5).
///         Each owner has at most one key and each key at most one owner, ever: a key an owner rotated away from is
///         RETIRED (v1.2) and can never be bound again. No admin, no upgradability.
/// @dev    Anyone can register a key it controls: a binding proves that one P1 key and one K1 key agreed to be
///         bound, nothing more (in particular it does not prove that the pair lives in genuine Ripar hardware).
///         BindDevice carries no nonce or deadline, so every binding signature ever made stays valid and public (it
///         is in the pairing transaction's calldata). Retiring rotated keys is what stops anyone from replaying an
///         owner's old binding to roll a key rotation back (v1.2, the adversarial review's bind-replay finding).
contract RiparDeviceRegistry is IRiparDeviceRegistry, EIP712 {
    /// @notice keccak256("BindDevice(address owner,bytes32 px,bytes32 py)")
    bytes32 public constant BIND_DEVICE_TYPEHASH = keccak256("BindDevice(address owner,bytes32 px,bytes32 py)");

    struct Key {
        bytes32 px;
        bytes32 py;
        address owner;
    }

    /// @dev keyId => bound key; `owner == address(0)` means no binding (the whole entry is then zero).
    mapping(bytes32 keyId => Key) private _keys;
    /// @dev owner => keyId of its current key; 0 means none.
    mapping(address owner => bytes32 keyId) private _keyIdOf;
    /// @dev keyId => retired (v1.2): the key was bound to an owner that later re-registered with another key.
    ///      A retired key is never bound again, for any owner.
    mapping(bytes32 keyId => bool) private _retired;

    constructor() EIP712("RiparDeviceRegistry", "1") { }

    // ------------------------------------------------------------------ views

    /// @notice The EIP-712 domain separator (name "RiparDeviceRegistry", version "1", this chain, this contract).
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @notice keccak256(0x1901 ‖ domainSeparator ‖ hashStruct(BindDevice(owner, px, py))): what P1 and K1 both sign.
    function bindDigest(address owner, bytes32 px, bytes32 py) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(BIND_DEVICE_TYPEHASH, owner, px, py)));
    }

    /// @notice The keyId (keccak256(abi.encode(px, py))) currently bound to `owner`, or 0 when it has none.
    function keyIdOf(address owner) external view returns (bytes32) {
        return _keyIdOf[owner];
    }

    /// @notice true when `keyId` was bound to an owner that re-registered with another key since (v1.2). A retired key
    ///         is unbound (keyOf returns zeros) and registerDevice reverts KeyTaken for it, whatever the owner.
    function isRetired(bytes32 keyId) external view returns (bool) {
        return _retired[keyId];
    }

    /// @notice The key bound under `keyId`. `owner == address(0)` (and px = py = 0) when the keyId is not bound.
    function keyOf(bytes32 keyId) external view returns (bytes32 px, bytes32 py, address owner) {
        Key storage k = _keys[keyId];
        return (k.px, k.py, k.owner);
    }

    // ------------------------------------------------------------------ registration

    /// @notice Binds the P1 key (px, py) to the K1 address `owner`. Anyone may relay the two signatures.
    /// @dev    Checks, in order: owner != 0 (ZeroOwner), the P1 signature (BadDeviceSignature; OZ P256.verify, low-s,
    ///         the 0x0100 precompile or the Solidity fallback), the K1 signature (BadOwnerSignature; exactly 65 bytes
    ///         r‖s‖v, v = 27/28, low-s; every malformed signature maps to this error), then KeyTaken when the key is
    ///         bound to another owner or is retired (for any owner, the previous owner included). An owner that
    ///         already has a different key loses it: the old key is unlinked (keyOf(old) returns zeros) and retired
    ///         (isRetired(old) == true), so replaying the old BindDevice signatures cannot undo the rotation.
    ///         Registering the same (owner, key) pair again is a no-op that succeeds and emits the event again.
    /// @param owner    the K1 address (the vault owner)
    /// @param px       P1 public key X coordinate
    /// @param py       P1 public key Y coordinate
    /// @param pr       P1 signature r over bindDigest(owner, px, py)
    /// @param ps       P1 signature s (low-s) over bindDigest(owner, px, py)
    /// @param ownerSig K1 signature r‖s‖v (65 bytes) over the same digest
    /// @return keyId   keccak256(abi.encode(px, py))
    function registerDevice(address owner, bytes32 px, bytes32 py, bytes32 pr, bytes32 ps, bytes calldata ownerSig)
        external
        returns (bytes32 keyId)
    {
        if (owner == address(0)) revert ZeroOwner();

        bytes32 digest = bindDigest(owner, px, py);
        if (!P256.verify(digest, pr, ps, px, py)) revert BadDeviceSignature();
        if (!_isOwnerSignature(digest, owner, ownerSig)) revert BadOwnerSignature();

        keyId = keccak256(abi.encode(px, py));
        address current = _keys[keyId].owner;
        if (current != address(0) && current != owner) revert KeyTaken();

        if (current == address(0)) {
            // a retired key is never bound again, for any owner (a bound key is never retired)
            if (_retired[keyId]) revert KeyTaken();
            // New binding for this key: unlink and retire the owner's previous key (if any), then bind both ways.
            bytes32 oldKeyId = _keyIdOf[owner];
            if (oldKeyId != bytes32(0)) {
                delete _keys[oldKeyId];
                _retired[oldKeyId] = true;
            }
            _keys[keyId] = Key({ px: px, py: py, owner: owner });
            _keyIdOf[owner] = keyId;
        }
        // else: the same owner and the same key again, a no-op that still emits the event.

        emit DeviceRegistered(owner, keyId, px, py);
    }

    // ------------------------------------------------------------------ internal

    /// @dev true iff `sig` is exactly 65 bytes r‖s‖v and ECDSA.tryRecover (low-s, v = 27/28) yields `owner`.
    function _isOwnerSignature(bytes32 digest, address owner, bytes calldata sig) private pure returns (bool) {
        if (sig.length != 65) return false;
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, v, r, s);
        return err == ECDSA.RecoverError.NoError && recovered == owner;
    }
}
