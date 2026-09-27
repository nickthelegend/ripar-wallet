// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { IRiparDeviceRegistry } from "../../../src/interfaces/IRiparDeviceRegistry.sol";

/// @notice A deliberately inconsistent registry: keyIdOf(owner) points at a key whose recorded owner is someone
///         else. Used to check RiparSentinel does not trust keyIdOf alone.
contract InconsistentRegistry {
    bytes32 public keyId;
    bytes32 public px;
    bytes32 public py;
    address public keyOwner;

    function set(bytes32 keyId_, bytes32 px_, bytes32 py_, address keyOwner_) external {
        (keyId, px, py, keyOwner) = (keyId_, px_, py_, keyOwner_);
    }

    function keyIdOf(address) external view returns (bytes32) {
        return keyId;
    }

    function keyOf(bytes32) external view returns (bytes32, bytes32, address) {
        return (px, py, keyOwner);
    }

    function asRegistry() external view returns (IRiparDeviceRegistry) {
        return IRiparDeviceRegistry(address(this));
    }
}
