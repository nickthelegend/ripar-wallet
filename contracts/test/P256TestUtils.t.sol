// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { P256 } from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import { P256TestUtils } from "./utils/P256TestUtils.sol";

contract P256TestUtilsTest is P256TestUtils {
    function test_signVerify_solidityAndPrecompile() public {
        (bytes32 x, bytes32 y) = p256Key(0xA11CE);
        bytes32 h = keccak256("ripar");
        (bytes32 r, bytes32 s) = p256Sign(0xA11CE, h);
        assertLe(uint256(s), P256_N / 2);
        assertTrue(P256.verify(h, r, s, x, y), "solidity fallback");
        assertFalse(P256.verify(h, r, p256HighS(s), x, y), "high-s rejected");
        etchP256Precompile();
        assertTrue(P256.verify(h, r, s, x, y), "precompile path");
        assertFalse(P256.verify(keccak256("other"), r, s, x, y), "wrong digest");
    }
}
