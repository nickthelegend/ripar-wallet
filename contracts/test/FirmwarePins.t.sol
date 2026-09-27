// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { Test } from "forge-std/Test.sol";
import { MockUSD } from "../src/MockUSD.sol";
import { Deploy } from "../script/Deploy.s.sol";
import { DeployConfig } from "../script/DeployConfig.sol";

/// @title FirmwarePinsTest
/// @notice The Ripar contract addresses compiled into firmware v1.2 (firmware/src/enforcers.cpp RIPAR_COSIGN,
///         RIPAR_REGISTRY, RIPAR_RELAY; firmware/src/tokens.cpp MockUSD; firmware/tools/make_request.py; typed here from
///         those tables) are exactly the CREATE2 addresses script/Deploy.s.sol predicts from the frozen bytecode.
///         Firmware v1.2 review (medium): every constructor argument of RiparReputationRelay on Monad (143) is a public
///         constant (the ERC-8004 registries, the CREATE2 enforcer and registry, the canonical DelegationManager -
///         configFor ignores the environment for them), so its 143 address is known before deployment and pinned like
///         the 10143 one; the relay's address depends neither on the forwarder nor on the CRE workflow owner.
contract FirmwarePinsTest is Test {
    address internal constant FW_PULSE_ENFORCER = 0x64d61fe5438981DC803ED61250FEf024617ae7eE;
    address internal constant FW_REGISTRY = 0xA08a47c9d645926615CF04D69b7a048133F68c9f;
    address internal constant FW_RELAY_10143 = 0xE433dCA75CA6cd730b1006F51A26208B000eA9E2;
    address internal constant FW_RELAY_143 = 0x108BA102F7D0915f51c93F128b96Bd24F647f06d;
    address internal constant FW_MUSD_10143 = 0xB5b7eaffbF9bf68cbcC1Ce8B5850b2ea9d6f9a2a;

    Deploy internal script;

    function setUp() public {
        script = new Deploy();
    }

    function _cfg(uint256 chainId, address forwarder, address owner)
        internal
        view
        returns (DeployConfig.ChainConfig memory)
    {
        return script.configFor(chainId, forwarder, owner, address(0x1111), address(0x2222), address(0x3333));
    }

    function test_monadTestnet_pins() public {
        Deploy.Deployment memory p = script.predictFor(_cfg(10_143, address(0), makeAddr("owner")));
        assertEq(p.enforcer, FW_PULSE_ENFORCER, "PulseCosignEnforcer (10143)");
        assertEq(p.registry, FW_REGISTRY, "RiparDeviceRegistry (10143)");
        assertEq(p.relay, FW_RELAY_10143, "RiparReputationRelay (10143)");
        assertEq(p.mockUsd, FW_MUSD_10143, "MockUSD (10143)");
    }

    function test_monadMainnet_pins() public {
        Deploy.Deployment memory p = script.predictFor(_cfg(143, makeAddr("forwarder"), makeAddr("owner")));
        assertEq(p.enforcer, FW_PULSE_ENFORCER, "PulseCosignEnforcer (143)");
        assertEq(p.registry, FW_REGISTRY, "RiparDeviceRegistry (143)");
        assertEq(p.relay, FW_RELAY_143, "RiparReputationRelay (143)");
        assertEq(p.mockUsd, address(0), "no MockUSD on 143");
    }

    /// @dev whatever forwarder / workflow owner / environment registries the 143 deployment is run with, the relay (and
    ///      the enforcer and registry) land at the pinned addresses; only the sentinel moves
    function testFuzz_monadMainnet_relayIndependentOfEnv(
        address forwarder,
        address owner,
        address a,
        address b,
        address c
    ) public view {
        vm.assume(forwarder != address(0) && owner != address(0));
        DeployConfig.ChainConfig memory cfg = script.configFor(143, forwarder, owner, a, b, c);
        Deploy.Deployment memory p = script.predictFor(cfg);
        assertEq(p.relay, FW_RELAY_143, "relay (143)");
        assertEq(p.enforcer, FW_PULSE_ENFORCER);
        assertEq(p.registry, FW_REGISTRY);
    }

    /// @dev MockUSD's metadata as the firmware token table lists it (tokens.cpp: mUSD, 6 decimals)
    function test_mockUsd_metadata() public {
        MockUSD m = new MockUSD();
        assertEq(m.symbol(), "mUSD");
        assertEq(m.decimals(), 6);
    }
}
