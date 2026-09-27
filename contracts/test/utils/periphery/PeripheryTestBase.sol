// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { P256TestUtils } from "../P256TestUtils.sol";
import { RiparDeviceRegistry } from "../../../src/RiparDeviceRegistry.sol";

/// @notice Shared helpers for the periphery suites: hand-rolled EIP-712, K1 signatures r‖s‖v, device registration.
///         Every suite runs twice: once with OZ P256's Solidity fallback (no code at 0x0100) and once with the
///         P256VERIFY precompile mock etched at 0x0100 (like Monad).
abstract contract PeripheryTestBase is P256TestUtils {
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    /// @dev The canonical MetaMask DelegationManager v1.3.0 the firmware pins (docs/PROTOCOL.md). The v1.1 enforcer
    ///      keys approvals by (manager, digest) (consumed(manager, d), approvalOf(manager, d)), and the relay only
    ///      trusts this manager's records.
    address internal constant DELEGATION_MANAGER = 0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3;

    /// @dev true in the "Precompile" variant of a suite
    bool internal withPrecompile;

    function _setUpP256Path(bool precompile) internal {
        withPrecompile = precompile;
        if (precompile) {
            etchP256Precompile();
            assertGt(P256_PRECOMPILE.code.length, 0);
        } else {
            assertEq(P256_PRECOMPILE.code.length, 0, "no precompile in the local EVM");
        }
    }

    /// @dev EIP-712 domain separator computed by hand (name, version "1").
    function handDomain(string memory name, uint256 chainId, address verifyingContract)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(name)), keccak256(bytes("1")), chainId, verifyingContract)
        );
    }

    function handDigest(bytes32 domain, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes2(0x1901), domain, structHash));
    }

    /// @dev K1 signature r‖s‖v (65 bytes, v = 27/28, low-s from vm.sign).
    function k1Sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev The malleable twin of a K1 signature: s' = n - s, v flipped (27 <-> 28). ecrecover accepts it, OZ rejects.
    function k1HighS(bytes memory sig) internal pure returns (bytes memory) {
        (bytes32 r, bytes32 s, uint8 v) = splitK1(sig);
        return abi.encodePacked(r, bytes32(SECP256K1_N - uint256(s)), v == 27 ? uint8(28) : uint8(27));
    }

    function splitK1(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
    }

    /// @dev Registers the (P1 = p1Pk, K1 = k1Pk) pair in `reg` with genuine signatures; returns the keyId.
    function registerPair(RiparDeviceRegistry reg, uint256 p1Pk, uint256 k1Pk) internal returns (bytes32 keyId) {
        (bytes32 px, bytes32 py) = p256Key(p1Pk);
        address owner = vm.addr(k1Pk);
        bytes32 d = reg.bindDigest(owner, px, py);
        (bytes32 r, bytes32 s) = p256Sign(p1Pk, d);
        keyId = reg.registerDevice(owner, px, py, r, s, k1Sign(k1Pk, d));
    }

    function hexAddr(bytes20 b) internal pure returns (address) {
        return address(b);
    }
}
