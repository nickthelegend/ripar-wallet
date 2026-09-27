// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { VmSafe } from "forge-std/Vm.sol";
import { console2 } from "forge-std/console2.sol";

import { MockUSD } from "../src/MockUSD.sol";
import { PulseCosignEnforcer } from "../src/PulseCosignEnforcer.sol";
import { RiparDeviceRegistry } from "../src/RiparDeviceRegistry.sol";
import { RiparSentinel } from "../src/RiparSentinel.sol";
import { RiparReputationRelay } from "../src/RiparReputationRelay.sol";
import { IPulseCosignEnforcer } from "../src/interfaces/IPulseCosignEnforcer.sol";
import { IRiparDeviceRegistry } from "../src/interfaces/IRiparDeviceRegistry.sol";
import { IERC8004Identity, IERC8004Reputation } from "../src/interfaces/external/IERC8004.sol";
import { DeployConfig } from "./DeployConfig.sol";

/// @title Deploy
/// @notice Deterministic deployment of the Ripar contracts with CREATE2 through the deterministic deployer
///         0x4e59b44847b379578588920cA78FbF26c0B4956C (forge routes `new X{salt: SALT}(...)` inside a broadcast
///         through it), SALT = keccak256("ripar-wallet v1"). The firmware pins the resulting addresses.
///         Order: RiparDeviceRegistry, PulseCosignEnforcer, RiparSentinel, RiparReputationRelay, MockUSD (testnet
///         and local only). A contract whose predicted address already has code is skipped, so the script is
///         idempotent. RiparDeviceRegistry, PulseCosignEnforcer and MockUSD take no constructor arguments and land at
///         the same address on every chain; RiparSentinel and RiparReputationRelay depend on the chain's config.
///         RiparReputationRelay (v1.1) also takes the DelegationManager whose redemptions it credits: the canonical
///         MetaMask DelegationManager v1.3.0 on 10143 and 143 (see DeployConfig).
///         v1.2: on 10143 and 143 the config requires RIPAR_WORKFLOW_OWNER (the Chainlink CRE workflow owner) and
///         reverts MissingWorkflowOwner without it. RiparSentinel's constructor takes that owner, so its address is only
///         known once the owner is chosen (see predict()).
/// @dev    Usage (see DeployConfig for the environment variables):
///           forge script script/Deploy.s.sol --sig "predict()"                     # print the addresses
///           forge script script/Deploy.s.sol                                       # simulate (dry run)
///           forge script script/Deploy.s.sol --rpc-url <rpc> --broadcast [...]     # deploy
///         run() writes deployments/<chainid>.json on a broadcast (deployments/<chainid>.dry-run.json otherwise).
contract Deploy is DeployConfig {
    /// @notice Addresses of the Ripar contracts (mockUsd = 0 where it is not deployed).
    struct Deployment {
        address registry;
        address enforcer;
        address sentinel;
        address relay;
        address mockUsd;
    }

    error AddressMismatch(string name, address predicted, address deployed);
    error NotDeployed(string name, address predicted);
    error BadWiring(string what);

    // ------------------------------------------------------------------ entry points

    /// @notice Prints (and returns) the predicted addresses on the current chain. Deploys nothing.
    /// @dev    Reverts like DeployConfig.configFor: on 10143 and 143 without RIPAR_WORKFLOW_OWNER it reverts
    ///         MissingWorkflowOwner (SPEC v1.2).
    ///         - RiparDeviceRegistry, PulseCosignEnforcer and MockUSD: no constructor arguments, so the same address on
    ///           every chain and for every configuration (what the firmware pins).
    ///         - RiparSentinel: its init code carries (forwarder, registry, expectedWorkflowOwner), so its address
    ///           DEPENDS ON THE CRE WORKFLOW OWNER (RIPAR_WORKFLOW_OWNER) and on the chain's forwarder: it is only known
    ///           once the workflow owner is chosen, and a different owner means a different sentinel (and different
    ///           mandate terms, which name the sentinel).
    ///         - RiparReputationRelay: its init code carries (reputation, identity, enforcer, registry,
    ///           delegationManager). It depends on the chain's ERC-8004 registries and DelegationManager, NOT on the
    ///           workflow owner, although the workflow owner must still be set for predict() to run on 10143 / 143.
    function predict() external view returns (Deployment memory p) {
        ChainConfig memory c = chainConfig(block.chainid);
        p = predictFor(c);
        _logConfig(c);
        console2.log("predicted addresses (code = already deployed):");
        console2.log("(RiparSentinel commits to the expected workflow owner above: another owner, another address)");
        _logAddress("RiparDeviceRegistry ", p.registry);
        _logAddress("PulseCosignEnforcer ", p.enforcer);
        _logAddress("RiparSentinel       ", p.sentinel);
        _logAddress("RiparReputationRelay", p.relay);
        _logAddress("MockUSD             ", p.mockUsd);
    }

    /// @notice Deploys what is missing, checks it, and writes the deployment JSON.
    function run() external returns (Deployment memory d) {
        d = deploy();
        _writeJson(d, chainConfig(block.chainid));
    }

    /// @notice Deploys every contract that is not at its predicted address yet (in a broadcast) and checks the result:
    ///         every address equals the prediction, has code, and is wired to the configured addresses.
    function deploy() public returns (Deployment memory) {
        return deployFor(chainConfig(block.chainid));
    }

    /// @notice deploy() for an explicit configuration `c` (e.g. from configFor, which applies the per-chain rules to
    ///         the given environment values), without reading the environment. Used by the in-process tests.
    function deployFor(ChainConfig memory c) public returns (Deployment memory p) {
        p = predictFor(c);
        _logConfig(c);

        vm.startBroadcast();
        if (_missing("RiparDeviceRegistry", p.registry)) {
            _same("RiparDeviceRegistry", p.registry, address(new RiparDeviceRegistry{ salt: SALT }()));
        }
        if (_missing("PulseCosignEnforcer", p.enforcer)) {
            _same("PulseCosignEnforcer", p.enforcer, address(new PulseCosignEnforcer{ salt: SALT }()));
        }
        if (_missing("RiparSentinel", p.sentinel)) {
            _same(
                "RiparSentinel",
                p.sentinel,
                address(
                    new RiparSentinel{ salt: SALT }(
                        c.forwarder, IRiparDeviceRegistry(p.registry), c.expectedWorkflowOwner
                    )
                )
            );
        }
        if (_missing("RiparReputationRelay", p.relay)) {
            _same(
                "RiparReputationRelay",
                p.relay,
                address(
                    new RiparReputationRelay{ salt: SALT }(
                        IERC8004Reputation(c.reputation),
                        IERC8004Identity(c.identity),
                        IPulseCosignEnforcer(p.enforcer),
                        IRiparDeviceRegistry(p.registry),
                        c.delegationManager
                    )
                )
            );
        }
        if (c.deployMockUsd && _missing("MockUSD", p.mockUsd)) {
            _same("MockUSD", p.mockUsd, address(new MockUSD{ salt: SALT }()));
        }
        vm.stopBroadcast();

        _check(p, c);
    }

    // ------------------------------------------------------------------ prediction

    /// @notice The CREATE2 addresses for `c` (through CREATE2_FACTORY, with SALT). The sentinel's address commits to
    ///         c.expectedWorkflowOwner and c.forwarder; the relay's to c.reputation, c.identity and
    ///         c.delegationManager (see predict()).
    function predictFor(ChainConfig memory c) public pure returns (Deployment memory p) {
        p.registry = _create2(type(RiparDeviceRegistry).creationCode);
        p.enforcer = _create2(type(PulseCosignEnforcer).creationCode);
        p.sentinel = _create2(
            abi.encodePacked(
                type(RiparSentinel).creationCode, abi.encode(c.forwarder, p.registry, c.expectedWorkflowOwner)
            )
        );
        p.relay = _create2(
            abi.encodePacked(
                type(RiparReputationRelay).creationCode,
                abi.encode(c.reputation, c.identity, p.enforcer, p.registry, c.delegationManager)
            )
        );
        if (c.deployMockUsd) p.mockUsd = _create2(type(MockUSD).creationCode);
    }

    function _create2(bytes memory initCode) private pure returns (address) {
        return vm.computeCreate2Address(SALT, keccak256(initCode), CREATE2_FACTORY);
    }

    // ------------------------------------------------------------------ checks

    function _missing(string memory name, address predicted) private view returns (bool) {
        if (predicted.code.length != 0) {
            console2.log("skip (already deployed):", name, predicted);
            return false;
        }
        return true;
    }

    function _same(string memory name, address predicted, address deployed) private pure {
        if (deployed != predicted) revert AddressMismatch(name, predicted, deployed);
        console2.log("deployed:", name, deployed);
    }

    function _check(Deployment memory p, ChainConfig memory c) private view {
        _hasCode("RiparDeviceRegistry", p.registry);
        _hasCode("PulseCosignEnforcer", p.enforcer);
        _hasCode("RiparSentinel", p.sentinel);
        _hasCode("RiparReputationRelay", p.relay);
        if (c.deployMockUsd) _hasCode("MockUSD", p.mockUsd);

        RiparSentinel sentinel = RiparSentinel(p.sentinel);
        if (sentinel.forwarder() != c.forwarder) revert BadWiring("sentinel.forwarder");
        if (address(sentinel.registry()) != p.registry) revert BadWiring("sentinel.registry");
        if (sentinel.expectedWorkflowOwner() != c.expectedWorkflowOwner) revert BadWiring("sentinel.workflowOwner");
        RiparReputationRelay relay = RiparReputationRelay(p.relay);
        if (address(relay.reputation()) != c.reputation) revert BadWiring("relay.reputation");
        if (address(relay.identity()) != c.identity) revert BadWiring("relay.identity");
        if (address(relay.enforcer()) != p.enforcer) revert BadWiring("relay.enforcer");
        if (address(relay.registry()) != p.registry) revert BadWiring("relay.registry");
        if (relay.delegationManager() != c.delegationManager) revert BadWiring("relay.delegationManager");
    }

    function _hasCode(string memory name, address a) private view {
        if (a.code.length == 0) revert NotDeployed(name, a);
    }

    // ------------------------------------------------------------------ output

    function _writeJson(Deployment memory d, ChainConfig memory c) private {
        string memory k = "ripar";
        vm.serializeUint(k, "chainId", block.chainid);
        vm.serializeBytes32(k, "salt", SALT);
        vm.serializeAddress(k, "create2Deployer", CREATE2_FACTORY);
        vm.serializeAddress(k, "RiparDeviceRegistry", d.registry);
        vm.serializeAddress(k, "PulseCosignEnforcer", d.enforcer);
        vm.serializeAddress(k, "RiparSentinel", d.sentinel);
        vm.serializeAddress(k, "RiparReputationRelay", d.relay);
        vm.serializeAddress(k, "MockUSD", d.mockUsd);
        vm.serializeAddress(k, "creForwarder", c.forwarder);
        vm.serializeAddress(k, "expectedWorkflowOwner", c.expectedWorkflowOwner);
        vm.serializeAddress(k, "erc8004Identity", c.identity);
        vm.serializeAddress(k, "delegationManager", c.delegationManager);
        string memory json = vm.serializeAddress(k, "erc8004Reputation", c.reputation);

        bool broadcast =
            vm.isContext(VmSafe.ForgeContext.ScriptBroadcast) || vm.isContext(VmSafe.ForgeContext.ScriptResume);
        string memory path =
            string.concat("deployments/", vm.toString(block.chainid), broadcast ? ".json" : ".dry-run.json");
        vm.createDir("deployments", true);
        vm.writeJson(json, path);
        console2.log("wrote", path);
    }

    function _logConfig(ChainConfig memory c) private view {
        console2.log("chainId", block.chainid);
        console2.log("salt");
        console2.logBytes32(SALT);
        console2.log("CRE forwarder          ", c.forwarder);
        console2.log("expected workflow owner", c.expectedWorkflowOwner);
        console2.log("ERC-8004 identity      ", c.identity);
        console2.log("ERC-8004 reputation    ", c.reputation);
        console2.log("DelegationManager      ", c.delegationManager);
        if (c.delegationManager.code.length == 0) {
            console2.log("  (no code there on the chain this runs on: the relay credits no approval until it exists)");
        }
    }

    function _logAddress(string memory name, address a) private view {
        if (a == address(0)) {
            console2.log(name, "(not deployed on this chain)");
        } else {
            console2.log(name, a, a.code.length != 0 ? "code" : "-");
        }
    }
}
