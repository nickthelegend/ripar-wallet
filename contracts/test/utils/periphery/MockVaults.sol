// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/// @notice A vault exposing ERC-173 owner() (like the framework's DeleGators), with a settable owner.
contract MockVault {
    address public owner;

    constructor(address owner_) {
        owner = owner_;
    }

    function setOwner(address owner_) external {
        owner = owner_;
    }
}

/// @notice A contract with code but no owner() (and no fallback): owner() reverts without data.
contract NoOwnerVault {
    function hello() external pure returns (uint256) {
        return 1;
    }
}

/// @notice owner() reverts with a reason.
contract RevertingOwnerVault {
    error Nope();

    function owner() external pure returns (address) {
        revert Nope();
    }
}

/// @notice owner() returns a word that is not a clean address.
contract DirtyOwnerVault {
    uint256 public immutable word;

    constructor(uint256 word_) {
        word = word_;
    }

    fallback() external {
        uint256 w = word;
        assembly {
            mstore(0, w)
            return(0, 0x20)
        }
    }
}

/// @notice owner() returns fewer than 32 bytes.
contract ShortOwnerVault {
    fallback() external {
        assembly {
            mstore(0, shl(96, 0x1234))
            return(0, 0x14)
        }
    }
}

/// @notice owner() writes state, so it fails under STATICCALL (a vault's owner() must be read without side effects).
contract StatefulOwnerVault {
    address internal immutable _owner;
    uint256 public reads;

    constructor(address owner_) {
        _owner = owner_;
    }

    function owner() external returns (address) {
        ++reads;
        return _owner;
    }
}
