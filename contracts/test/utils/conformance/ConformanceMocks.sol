// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { IERC8004Identity, IERC8004Reputation } from "../../../src/interfaces/external/IERC8004.sol";

/// @title MockERC8004Identity
/// @notice Test stand-in for the ERC-8004 IdentityRegistry: the test decides who owns / operates an agent id.
contract MockERC8004Identity is IERC8004Identity {
    mapping(uint256 agentId => address owner) public owners;
    mapping(uint256 agentId => mapping(address operator => bool)) public operators;

    /// @notice Sets the owner of `agentId` (test helper).
    function setOwner(uint256 agentId, address owner) external {
        owners[agentId] = owner;
    }

    /// @notice Authorizes or de-authorizes `operator` for `agentId` (test helper).
    function setOperator(uint256 agentId, address operator, bool authorized) external {
        operators[agentId][operator] = authorized;
    }

    /// @notice Not supported by the mock.
    function register(string calldata, MetadataEntry[] calldata) external pure returns (uint256) {
        revert("MockERC8004Identity: register not supported");
    }

    /// @inheritdoc IERC8004Identity
    function ownerOf(uint256 agentId) external view returns (address) {
        return owners[agentId];
    }

    /// @inheritdoc IERC8004Identity
    function isAuthorizedOrOwner(address spender, uint256 agentId) public view returns (bool) {
        return (spender != address(0) && spender == owners[agentId]) || operators[agentId][spender];
    }

    /// @inheritdoc IERC8004Identity
    function getMetadata(uint256, string calldata) external pure returns (bytes memory) {
        return "";
    }
}

/// @title MockERC8004Reputation
/// @notice Test stand-in for the ERC-8004 ReputationRegistry: records every feedback. Like the real registry it refuses
///         feedback from the agent's owner or an approved operator.
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

    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    MockERC8004Identity public immutable identity;
    Feedback[] internal _feedback;

    event FeedbackGiven(address indexed client, uint256 indexed agentId, int128 value, bytes32 feedbackHash);

    constructor(MockERC8004Identity identity_) {
        identity = identity_;
    }

    /// @inheritdoc IERC8004Reputation
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
        require(!identity.isAuthorizedOrOwner(msg.sender, agentId), "MockERC8004Reputation: self feedback");
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
        emit FeedbackGiven(msg.sender, agentId, value, feedbackHash);
    }

    /// @inheritdoc IERC8004Reputation
    function getIdentityRegistry() external view returns (address) {
        return address(identity);
    }

    /// @notice Number of feedback entries recorded.
    function feedbackCount() external view returns (uint256) {
        return _feedback.length;
    }

    /// @notice The `i`-th feedback entry.
    function feedbackAt(uint256 i) external view returns (Feedback memory) {
        return _feedback[i];
    }
}

/// @title MockOwnedVault
/// @notice ERC-173 `owner()` only: what RiparSentinel.reopen reads from a vault. Deployed at the vector's vault
///         address. No storage (immutable owner), so a HybridDeleGator proxy can later be etched over it.
contract MockOwnedVault {
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    address public immutable owner; // ERC-173 owner()

    constructor(address owner_) {
        owner = owner_;
    }
}
