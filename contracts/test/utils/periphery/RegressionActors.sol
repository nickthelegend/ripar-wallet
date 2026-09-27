// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { ModeCode } from "@delegation-framework/utils/Types.sol";

import { IRiparReputationRelay } from "../../../src/interfaces/IRiparReputationRelay.sol";

/// @notice A "vault" an attacker writes itself (the adversarial review's SelfDealDelegator / FakeVault): it accepts
///         every delegation signature (ERC-1271) and executes nothing. The DelegationManager accepts any contract as
///         a root delegator and runs the caveat hooks on it. It has no owner().
contract AcceptAllDelegator {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0x1626ba7e;
    }

    function executeFromExecutor(ModeCode, bytes calldata) external payable returns (bytes[] memory r) {
        r = new bytes[](1);
    }
}

/// @notice The same fake vault, claiming any owner() the attacker likes (e.g. a victim whose device is registered).
contract AcceptAllOwnedDelegator is AcceptAllDelegator {
    address public owner;

    constructor(address owner_) {
        owner = owner_;
    }
}

/// @notice PERIPHERY-5: an agent owner that is a contract (any smart account or EIP-7702 EOA can do the same). It keeps
///         the relay authorized for its agent, so the ERC-8004 ReputationRegistry refuses every denial as
///         self-feedback, and lifts the authorization only inside its own attestApproval transaction.
contract DenialShield {
    address internal immutable boss;

    constructor() {
        boss = msg.sender;
    }

    /// @dev the live IdentityRegistry mints the agent NFT with _safeMint
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }

    function exec(address to, bytes calldata data) external returns (bytes memory ret) {
        require(msg.sender == boss, "boss");
        ret = _call(to, data);
    }

    /// @notice lift the shield (`lift` on the identity registry), attest, put the shield back (`restore`)
    function attestShielded(
        address identity,
        bytes calldata lift,
        bytes calldata restore,
        IRiparReputationRelay relay,
        uint256 agentId,
        bytes32 digest
    ) external {
        require(msg.sender == boss, "boss");
        _call(identity, lift);
        relay.attestApproval(agentId, digest);
        _call(identity, restore);
    }

    function _call(address to, bytes calldata data) private returns (bytes memory ret) {
        bool ok;
        (ok, ret) = to.call(data);
        if (!ok) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }
}
