// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @notice Chainlink CRE consumer interface: the KeystoneForwarder calls onReport(metadata, report) after it has
///         verified the DON signatures. Monad testnet forwarder: 0xF8344CFd5c43616a4366C34E3EEE75af79a74482.
///         metadata = abi.encodePacked(bytes32 workflowId, bytes10 workflowName, address workflowOwner).
interface IReceiver is IERC165 {
    function onReport(bytes calldata metadata, bytes calldata report) external;
}
