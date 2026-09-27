// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { IPulseCosignEnforcer } from "../../../src/interfaces/IPulseCosignEnforcer.sol";

/// @notice The two PulseCosignEnforcer views RiparReputationRelay reads, settable by tests. Like the v1.1 enforcer,
///         records are keyed by (manager, digest), where manager is the caller of beforeHook (the canonical
///         DelegationManager, or anyone calling beforeHook directly). Cast its address to IPulseCosignEnforcer.
contract MockEnforcer {
    mapping(address manager => mapping(bytes32 digest => IPulseCosignEnforcer.Approval)) internal _approvals;
    /// @notice consumed(manager, digest), same selector as IPulseCosignEnforcer.consumed
    mapping(address manager => mapping(bytes32 digest => bool)) public consumed;

    /// @notice Records `a` under (manager, digest) and marks it consumed, as beforeHook's HUMAN path does when
    ///         `manager` calls it.
    function setApproval(address manager, bytes32 digest, IPulseCosignEnforcer.Approval calldata a) external {
        _approvals[manager][digest] = a;
        consumed[manager][digest] = true;
    }

    /// @notice All fields are zero for a (manager, digest) that was never consumed, like the enforcer.
    function approvalOf(address manager, bytes32 digest) external view returns (IPulseCosignEnforcer.Approval memory) {
        return _approvals[manager][digest];
    }
}
