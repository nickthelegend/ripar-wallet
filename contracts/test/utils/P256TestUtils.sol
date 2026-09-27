// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { Test } from "forge-std/Test.sol";
import { P256 } from "@openzeppelin/contracts/utils/cryptography/P256.sol";

/// @notice Stand-in for the RIP-7212 / EIP-7951 P256VERIFY precompile that Monad has at 0x0100 (6,900 gas).
///         Input: h ‖ r ‖ s ‖ qx ‖ qy (160 bytes). Output: 32-byte 1 when valid, empty otherwise.
///         Etch it at address(0x100) to exercise OpenZeppelin P256's native path; without it OZ falls back to Solidity.
contract P256PrecompileMock {
    fallback(bytes calldata input) external returns (bytes memory) {
        if (input.length != 160) return "";
        (bytes32 h, bytes32 r, bytes32 s, bytes32 qx, bytes32 qy) =
            abi.decode(input, (bytes32, bytes32, bytes32, bytes32, bytes32));
        return P256.verifySolidity(h, r, s, qx, qy) ? abi.encode(uint256(1)) : bytes("");
    }
}

/// @notice P-256 (device P1) signing helpers for tests. Signatures are normalised to low-s like the firmware's.
abstract contract P256TestUtils is Test {
    uint256 internal constant P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    address internal constant P256_PRECOMPILE = address(0x100);

    function p256Key(uint256 pk) internal pure returns (bytes32 x, bytes32 y) {
        (uint256 ux, uint256 uy) = vm.publicKeyP256(pk);
        return (bytes32(ux), bytes32(uy));
    }

    function p256Sign(uint256 pk, bytes32 digest) internal pure returns (bytes32 r, bytes32 s) {
        (r, s) = vm.signP256(pk, digest);
        if (uint256(s) > P256_N / 2) s = bytes32(P256_N - uint256(s));
    }

    /// @dev the same signature with s' = n - s (valid ECDSA, rejected by OZ / the enforcer as malleable)
    function p256HighS(bytes32 s) internal pure returns (bytes32) {
        return bytes32(P256_N - uint256(s));
    }

    function p256KeyId(bytes32 x, bytes32 y) internal pure returns (bytes32) {
        return keccak256(abi.encode(x, y));
    }

    function etchP256Precompile() internal {
        vm.etch(P256_PRECOMPILE, address(new P256PrecompileMock()).code);
    }
}
