// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/// @notice Test stand-in for RiparSentinel: only `laneOpen` is read by PulseCosignEnforcer. Lanes are open by default.
contract MockSentinel {
    mapping(address vault => bool) public closed;

    function setClosed(address vault, bool isClosed) external {
        closed[vault] = isClosed;
    }

    function laneOpen(address vault) external view returns (bool) {
        return !closed[vault];
    }
}

/// @notice A sentinel whose `laneOpen` always reverts (the enforcer must fail closed).
contract RevertingSentinel {
    function laneOpen(address) external pure returns (bool) {
        revert("sentinel down");
    }
}

/// @notice A sentinel that answers with a non-canonical bool (2): the ABI decoder in the enforcer must revert.
contract GarbageSentinel {
    fallback() external {
        assembly {
            mstore(0, 2)
            return(0, 32)
        }
    }
}

/// @notice Constant-time stand-in for the P256VERIFY precompile, used ONLY to measure the enforcer's own gas
///         (everything but the curve maths). It accepts every input: never use it in behaviour tests.
contract P256AcceptAllStub {
    fallback() external {
        assembly {
            mstore(0, 1)
            return(0, 32)
        }
    }
}
