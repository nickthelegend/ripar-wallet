// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { Script } from "forge-std/Script.sol";

/// @title DeployConfig
/// @notice Per-chain configuration of the Ripar deployment (script/Deploy.s.sol).
/// @dev    Environment variables (all optional unless noted):
///         - RIPAR_WORKFLOW_OWNER    : the address that owns the Chainlink CRE workflow, which RiparSentinel requires in
///                                     every report's metadata. REQUIRED (non-zero) on Monad testnet (10143) and mainnet
///                                     (143), otherwise MissingWorkflowOwner (SPEC v1.2): without it any CRE workflow
///                                     the KeystoneForwarder delivers could close any vault's lane. Optional on a local
///                                     chain (31337, default 0 = no metadata check). RiparSentinel's CREATE2 address
///                                     commits to it (see Deploy.predict).
///         - RIPAR_CRE_FORWARDER     : KeystoneForwarder. REQUIRED on Monad mainnet (143); ignored on 10143 (pinned);
///                                     optional on a local chain (31337, default 0 = nobody can close a lane)
///         - RIPAR_ERC8004_IDENTITY  : local chain (31337) only, default 0
///         - RIPAR_ERC8004_REPUTATION: local chain (31337) only, default 0
///         - RIPAR_DELEGATION_MANAGER: local chain (31337) only, default (and when set to 0) the canonical MetaMask
///                                     DelegationManager v1.3.0; pinned to the canonical one on 10143 and 143
abstract contract DeployConfig is Script {
    /// @notice CREATE2 salt of every Ripar contract (through the deterministic deployer at CREATE2_FACTORY).
    bytes32 public constant SALT = keccak256("ripar-wallet v1");

    uint256 public constant MONAD_TESTNET = 10_143;
    uint256 public constant MONAD_MAINNET = 143;
    uint256 public constant LOCAL_CHAIN = 31_337;

    /// @notice Chainlink CRE KeystoneForwarder on Monad testnet.
    address public constant TESTNET_CRE_FORWARDER = 0xF8344CFd5c43616a4366C34E3EEE75af79a74482;
    /// @notice ERC-8004 registries on Monad testnet.
    address public constant TESTNET_ERC8004_IDENTITY = 0x8004A818BFB912233c491871b3d84c89A494BD9e;
    address public constant TESTNET_ERC8004_REPUTATION = 0x8004B663056A597Dffe9eCcC1965A193B7388713;
    /// @notice ERC-8004 registries on Monad mainnet.
    address public constant MAINNET_ERC8004_IDENTITY = 0x8004A169FB4a3325136EB29fA0ceB6D2e539a432;
    address public constant MAINNET_ERC8004_REPUTATION = 0x8004BAa17C55a88189AE136b182e5fdA19dE9b63;
    /// @notice The canonical MetaMask DelegationManager v1.3.0 (the one the firmware pins, same address on 10143 and
    ///         143). RiparReputationRelay only credits co-signatures the enforcer consumed in its redemptions.
    address public constant CANONICAL_DELEGATION_MANAGER = 0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3;

    /// @notice Constructor arguments that differ per chain.
    struct ChainConfig {
        address forwarder; // RiparSentinel: the only caller of onReport
        address expectedWorkflowOwner; // RiparSentinel: never 0 on 10143 / 143; 0 = no metadata check (31337 only)
        address identity; // RiparReputationRelay: ERC-8004 IdentityRegistry
        address reputation; // RiparReputationRelay: ERC-8004 ReputationRegistry
        address delegationManager; // RiparReputationRelay: the DelegationManager whose redemptions count
        bool deployMockUsd; // testnet / local only, never on a mainnet
    }

    error UnsupportedChain(uint256 chainId);
    error MissingForwarder();
    /// @notice RIPAR_WORKFLOW_OWNER is 0 on Monad testnet or mainnet (SPEC v1.2).
    error MissingWorkflowOwner();

    /// @notice The configuration of `chainId`, with the environment variables above applied.
    function chainConfig(uint256 chainId) public view returns (ChainConfig memory) {
        return configFor(
            chainId,
            vm.envOr("RIPAR_CRE_FORWARDER", address(0)),
            vm.envOr("RIPAR_WORKFLOW_OWNER", address(0)),
            vm.envOr("RIPAR_ERC8004_IDENTITY", address(0)),
            vm.envOr("RIPAR_ERC8004_REPUTATION", address(0)),
            vm.envOr("RIPAR_DELEGATION_MANAGER", CANONICAL_DELEGATION_MANAGER)
        );
    }

    /// @notice The configuration of `chainId` for the given environment values (pure, so it can be tested).
    /// @dev Reverts, in this order: UnsupportedChain for any chain other than 10143, 143 and 31337; on 143
    ///      MissingForwarder without a forwarder; on 10143 and 143 MissingWorkflowOwner when `envWorkflowOwner` is 0
    ///      (SPEC v1.2; 31337 accepts 0 = no metadata check). The DelegationManager is the canonical one on 10143 and
    ///      143 (`envDelegationManager` is ignored there); on 31337 it is `envDelegationManager`, or the canonical one
    ///      when that is 0.
    function configFor(
        uint256 chainId,
        address envForwarder,
        address envWorkflowOwner,
        address envIdentity,
        address envReputation,
        address envDelegationManager
    ) public pure returns (ChainConfig memory c) {
        c.expectedWorkflowOwner = envWorkflowOwner;
        if (chainId == MONAD_TESTNET) {
            if (envWorkflowOwner == address(0)) revert MissingWorkflowOwner();
            c.forwarder = TESTNET_CRE_FORWARDER;
            c.identity = TESTNET_ERC8004_IDENTITY;
            c.reputation = TESTNET_ERC8004_REPUTATION;
            c.delegationManager = CANONICAL_DELEGATION_MANAGER;
            c.deployMockUsd = true;
        } else if (chainId == MONAD_MAINNET) {
            if (envForwarder == address(0)) revert MissingForwarder();
            if (envWorkflowOwner == address(0)) revert MissingWorkflowOwner();
            c.forwarder = envForwarder;
            c.identity = MAINNET_ERC8004_IDENTITY;
            c.reputation = MAINNET_ERC8004_REPUTATION;
            c.delegationManager = CANONICAL_DELEGATION_MANAGER;
            c.deployMockUsd = false;
        } else if (chainId == LOCAL_CHAIN) {
            c.forwarder = envForwarder;
            c.identity = envIdentity;
            c.reputation = envReputation;
            c.delegationManager =
                envDelegationManager == address(0) ? CANONICAL_DELEGATION_MANAGER : envDelegationManager;
            c.deployMockUsd = true;
        } else {
            revert UnsupportedChain(chainId);
        }
    }
}
