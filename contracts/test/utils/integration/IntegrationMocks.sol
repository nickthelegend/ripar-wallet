// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { IERC8004Identity, IERC8004Reputation } from "../../../src/interfaces/external/IERC8004.sol";

/// @notice Minimal ERC-8004 IdentityRegistry for the integration suite. Like the live registry on Monad testnet
///         (checked by eth_call), `isAuthorizedOrOwner` reverts ERC721NonexistentToken for an unknown agent id.
contract IntegrationIdentityStub is IERC8004Identity {
    error ERC721NonexistentToken(uint256 tokenId);

    uint256 public nextId = 1;
    mapping(uint256 agentId => address) public owners;
    mapping(uint256 agentId => mapping(address who => bool)) public authorized;

    /// @notice Registers a new agent owned by the caller.
    function register(string calldata, MetadataEntry[] calldata) external returns (uint256 agentId) {
        agentId = nextId++;
        owners[agentId] = msg.sender;
    }

    /// @notice Test helper: authorize `who` to act for `agentId` (an ERC-721 approval / operator in the real registry).
    function setAuthorized(uint256 agentId, address who, bool ok) external {
        require(msg.sender == ownerOf(agentId), "not agent owner");
        authorized[agentId][who] = ok;
    }

    function ownerOf(uint256 agentId) public view returns (address o) {
        o = owners[agentId];
        if (o == address(0)) revert ERC721NonexistentToken(agentId);
    }

    function isAuthorizedOrOwner(address spender, uint256 agentId) external view returns (bool) {
        address o = ownerOf(agentId);
        return spender != address(0) && (spender == o || authorized[agentId][spender]);
    }

    function getMetadata(uint256, string calldata) external pure returns (bytes memory) {
        return "";
    }
}

/// @notice Minimal ERC-8004 ReputationRegistry for the integration suite: records every feedback verbatim and, like
///         the live registry, refuses feedback from an address that is authorized for (or owns) the agent.
contract IntegrationReputationStub is IERC8004Reputation {
    struct Feedback {
        address client;
        uint256 agentId;
        int128 value;
        uint8 valueDecimals;
        string tag1;
        string tag2;
        string endpoint;
        string feedbackURI;
        bytes32 feedbackHash;
    }

    IERC8004Identity internal immutable IDENTITY;
    Feedback[] internal _feedback;

    constructor(IERC8004Identity identity_) {
        IDENTITY = identity_;
    }

    function giveFeedback(
        uint256 agentId,
        int128 value,
        uint8 valueDecimals,
        string calldata tag1,
        string calldata tag2,
        string calldata endpoint,
        string calldata feedbackURI,
        bytes32 feedbackHash
    ) external {
        require(!IDENTITY.isAuthorizedOrOwner(msg.sender, agentId), "Self-feedback not allowed");
        _feedback.push(
            Feedback({
                client: msg.sender,
                agentId: agentId,
                value: value,
                valueDecimals: valueDecimals,
                tag1: tag1,
                tag2: tag2,
                endpoint: endpoint,
                feedbackURI: feedbackURI,
                feedbackHash: feedbackHash
            })
        );
    }

    function getIdentityRegistry() external view returns (address) {
        return address(IDENTITY);
    }

    function feedbackCount() external view returns (uint256) {
        return _feedback.length;
    }

    function feedbackAt(uint256 i) external view returns (Feedback memory) {
        return _feedback[i];
    }
}

/// @notice Gas stand-in for Monad's P256VERIFY precompile at 0x0100: accepts every 160-byte input (returns 32-byte 1)
///         after burning about 6,900 gas, the precompile's price. Used ONLY by the gas suite, never for behaviour.
contract MonadP256GasStub {
    fallback() external {
        assembly {
            let start := gas()
            // burn until ~6,900 gas of this frame are spent (the loop overhead makes it land a little above)
            for { } gt(6850, sub(start, gas())) { } { }
            mstore(0, 1)
            return(0, 32)
        }
    }
}
