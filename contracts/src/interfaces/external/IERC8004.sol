// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/// @notice Subset of the ERC-8004 registries live on Monad testnet (10143), selectors checked against the deployed
///         implementations on 2026-09-27:
///         IdentityRegistry   0x8004A818BFB912233c491871b3d84c89A494BD9e (ERC-721 agent ids)
///         ReputationRegistry 0x8004B663056A597Dffe9eCcC1965A193B7388713
///         (mainnet 143 uses different addresses: 0x8004A169FB4a3325136EB29fA0ceB6D2e539a432 / 0x8004BAa1...9b63)
interface IERC8004Identity {
    struct MetadataEntry {
        string key;
        bytes value;
    }

    function register(string calldata agentURI, MetadataEntry[] calldata metadata) external returns (uint256 agentId);
    function ownerOf(uint256 agentId) external view returns (address);
    function isAuthorizedOrOwner(address spender, uint256 agentId) external view returns (bool);
    function getMetadata(uint256 agentId, string calldata key) external view returns (bytes memory);
}

interface IERC8004Reputation {
    /// @dev The caller must not be the agent's owner or an approved operator (ERC-8004).
    function giveFeedback(
        uint256 agentId,
        int128 value,
        uint8 valueDecimals,
        string calldata tag1,
        string calldata tag2,
        string calldata endpoint,
        string calldata feedbackURI,
        bytes32 feedbackHash
    )
        external;

    function getIdentityRegistry() external view returns (address);
}
