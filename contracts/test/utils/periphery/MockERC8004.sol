// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { IERC8004Identity, IERC8004Reputation } from "../../../src/interfaces/external/IERC8004.sol";

/// @notice Minimal ERC-8004 IdentityRegistry stand-in: agent owners plus explicitly authorized addresses.
///         Like the live registry on Monad testnet, ownerOf / isAuthorizedOrOwner revert ERC721NonexistentToken for an
///         agent id that does not exist.
contract MockERC8004Identity is IERC8004Identity {
    error ERC721NonexistentToken(uint256 tokenId);

    uint256 public nextId = 1;
    mapping(uint256 agentId => address) public owners;
    mapping(uint256 agentId => mapping(address => bool)) public authorized;
    mapping(uint256 agentId => mapping(string => bytes)) internal _metadata;

    function register(string calldata, MetadataEntry[] calldata metadata) external returns (uint256 agentId) {
        agentId = nextId++;
        owners[agentId] = msg.sender;
        for (uint256 i; i < metadata.length; ++i) {
            _metadata[agentId][metadata[i].key] = metadata[i].value;
        }
    }

    function setOwner(uint256 agentId, address owner) external {
        owners[agentId] = owner;
    }

    function setAuthorized(uint256 agentId, address who, bool ok) external {
        authorized[agentId][who] = ok;
    }

    function ownerOf(uint256 agentId) public view returns (address o) {
        o = owners[agentId];
        if (o == address(0)) revert ERC721NonexistentToken(agentId);
    }

    function isAuthorizedOrOwner(address spender, uint256 agentId) external view returns (bool) {
        address o = ownerOf(agentId);
        return spender != address(0) && (o == spender || authorized[agentId][spender]);
    }

    function getMetadata(uint256 agentId, string calldata key) external view returns (bytes memory) {
        return _metadata[agentId][key];
    }
}

/// @notice ERC-8004 ReputationRegistry stand-in that records every giveFeedback call verbatim. Like the live registry
///         it refuses feedback from a caller that isAuthorizedOrOwner for the agent (and so reverts for unknown agents).
contract MockERC8004Reputation is IERC8004Reputation {
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

    address public immutable identityRegistry;
    Feedback[] internal _feedback;

    constructor(address identityRegistry_) {
        identityRegistry = identityRegistry_;
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
        require(
            !IERC8004Identity(identityRegistry).isAuthorizedOrOwner(msg.sender, agentId), "Self-feedback not allowed"
        );
        _feedback.push(
            Feedback(msg.sender, agentId, value, valueDecimals, tag1, tag2, endpoint, feedbackURI, feedbackHash)
        );
    }

    function getIdentityRegistry() external view returns (address) {
        return identityRegistry;
    }

    function feedbackCount() external view returns (uint256) {
        return _feedback.length;
    }

    function feedbackAt(uint256 i) external view returns (Feedback memory) {
        return _feedback[i];
    }
}

/// @notice IdentityRegistry stand-in whose isAuthorizedOrOwner reverts for one spender (and answers false otherwise).
///         Used to check that RiparReputationRelay's shield pre-check reads a revert as "not authorized".
contract RevertingForIdentity is IERC8004Identity {
    error Boom();

    address public revertFor;

    function setRevertFor(address who) external {
        revertFor = who;
    }

    function register(string calldata, MetadataEntry[] calldata) external pure returns (uint256) {
        return 0;
    }

    function ownerOf(uint256) external pure returns (address) {
        return address(0xdead);
    }

    function isAuthorizedOrOwner(address spender, uint256) external view returns (bool) {
        if (spender == revertFor) revert Boom();
        return false;
    }

    function getMetadata(uint256, string calldata) external pure returns (bytes memory) {
        return "";
    }
}
