// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { P256 } from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import { IERC173 } from "@delegation-framework/interfaces/IERC173.sol";

import { IRiparSentinel } from "./interfaces/IRiparSentinel.sol";
import { IRiparDeviceRegistry } from "./interfaces/IRiparDeviceRegistry.sol";
import { IReceiver } from "./interfaces/external/IReceiver.sol";

/// @title RiparSentinel
/// @notice Per-vault "autonomous lane" switch read by PulseCosignEnforcer's AUTO path. Every lane starts open.
///         Chainlink CRE (through its KeystoneForwarder, the only allowed caller of onReport) can only CLOSE a lane.
///         Only the vault owner's registered Ripar device can REOPEN it, with `Reopen(address vault,uint256 nonce)`
///         signed by its P-256 key under the EIP-712 domain name "RiparSentinel", version "1"
///         (docs/PROTOCOL.md §3, `ripar-reopen`). No admin, no upgradability.
/// @dev    v1.2 (after the adversarial review):
///         - reopen needs a CLOSED lane (LaneNotClosed otherwise). A reopen the device signed but nobody relayed (a
///           withheld QR) can therefore no longer be relayed while the lane is open to pre-empt an in-flight close
///           report (lastReopenBlock would out-rank the report's asOfBlock and the close would be ignored).
///         - a report whose asOfBlock is in the future (> block.number) is BadReport, so a report cannot claim a
///           future block to out-rank every later reopen.
///         KNOWN LIMITATION (documented, by design): a reopen is a bearer authorization with no deadline. A withheld
///         reopen with a nonce above lastReopenNonce can still be relayed after a LATER close and undo it; relay
///         every reopen immediately (the next relayed nonce voids the older ones). PANIC and revoke are unaffected.
contract RiparSentinel is IRiparSentinel, IReceiver, EIP712 {
    /// @notice keccak256("Reopen(address vault,uint256 nonce)")
    bytes32 public constant REOPEN_TYPEHASH = keccak256("Reopen(address vault,uint256 nonce)");

    /// @dev report = abi.encode(address vault, bool open, uint8 reason, uint64 asOfBlock): 4 words.
    uint256 private constant REPORT_LENGTH = 128;
    /// @dev metadata = workflowId(32) ‖ workflowName(10) ‖ workflowOwner(20) [‖ reportId(2)]; the owner is [42:62].
    uint256 private constant WORKFLOW_OWNER_OFFSET = 42;
    uint256 private constant WORKFLOW_OWNER_END = 62;

    /// @notice The Chainlink KeystoneForwarder, the only address allowed to call onReport.
    address public immutable forwarder;
    /// @notice The registry that maps a vault owner (K1) to its device key (P1).
    IRiparDeviceRegistry public immutable registry;
    /// @notice The CRE workflow owner a report's metadata must name; address(0) skips the check.
    address public immutable expectedWorkflowOwner;

    struct Lane {
        bool closed; // false = open (the default)
        uint64 lastReopenBlock; // block.number of the last device reopen (0 = never)
    }

    mapping(address vault => Lane) private _lanes;
    mapping(address vault => uint256 nonce) private _lastReopenNonce;

    /// @param forwarder_             the KeystoneForwarder (Monad testnet: 0xF8344CFd5c43616a4366C34E3EEE75af79a74482)
    /// @param registry_              the RiparDeviceRegistry
    /// @param expectedWorkflowOwner_ the CRE workflow owner to require in the metadata, or address(0) to skip the check
    constructor(address forwarder_, IRiparDeviceRegistry registry_, address expectedWorkflowOwner_)
        EIP712("RiparSentinel", "1")
    {
        forwarder = forwarder_;
        registry = registry_;
        expectedWorkflowOwner = expectedWorkflowOwner_;
    }

    // ------------------------------------------------------------------ views

    /// @notice true unless the lane of `vault` was closed by a report and not reopened by the device since.
    function laneOpen(address vault) external view returns (bool) {
        return !_lanes[vault].closed;
    }

    /// @notice The last nonce a device reopen of `vault` used (0 = never). The next one must be greater.
    function lastReopenNonce(address vault) external view returns (uint256) {
        return _lastReopenNonce[vault];
    }

    /// @notice The block of the last device reopen of `vault` (0 = never). Close reports older than it are ignored.
    function lastReopenBlock(address vault) external view returns (uint64) {
        return _lanes[vault].lastReopenBlock;
    }

    /// @notice The EIP-712 domain separator (name "RiparSentinel", version "1", this chain, this contract).
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @notice keccak256(0x1901 ‖ domainSeparator ‖ hashStruct(Reopen(vault, nonce))): what the device's P1 signs.
    function reopenDigest(address vault, uint256 nonce) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(REOPEN_TYPEHASH, vault, nonce)));
    }

    /// @notice ERC-165: true for IReceiver (onReport) and IERC165.
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IReceiver).interfaceId || interfaceId == type(IERC165).interfaceId;
    }

    // ------------------------------------------------------------------ CRE: close only

    /// @notice CRE IReceiver entry point, callable only by the forwarder.
    /// @dev    metadata: when an expected workflow owner is set, metadata[42:62] must equal it (shorter metadata
    ///         reverts BadWorkflowOwner). report: exactly 128 canonical bytes = abi.encode(address vault, bool open,
    ///         uint8 reason, uint64 asOfBlock), otherwise BadReport; open == true also reverts BadReport (CRE can only
    ///         close), and so does asOfBlock > block.number (v1.2: a report cannot claim a future block). A close with
    ///         asOfBlock < lastReopenBlock(vault) is ignored (ReportIgnored), so a delayed report cannot undo a newer
    ///         device reopen; otherwise the lane is closed (LaneChanged(vault, false, ...)).
    /// @param metadata abi.encodePacked(bytes32 workflowId, bytes10 workflowName, address workflowOwner[, bytes2 id])
    /// @param report   abi.encode(address vault, bool open, uint8 reason, uint64 asOfBlock)
    function onReport(bytes calldata metadata, bytes calldata report) external override(IRiparSentinel, IReceiver) {
        if (msg.sender != forwarder) revert NotForwarder();

        address expected = expectedWorkflowOwner;
        if (expected != address(0)) {
            if (metadata.length < WORKFLOW_OWNER_END) revert BadWorkflowOwner();
            if (address(bytes20(metadata[WORKFLOW_OWNER_OFFSET:WORKFLOW_OWNER_END])) != expected) {
                revert BadWorkflowOwner();
            }
        }

        (address vault, bool open, uint8 reason, uint64 asOfBlock) = _decodeReport(report);
        if (open) revert BadReport();
        if (asOfBlock > block.number) revert BadReport();

        Lane storage lane = _lanes[vault];
        if (asOfBlock < lane.lastReopenBlock) {
            emit ReportIgnored(vault, reason, asOfBlock);
            return;
        }
        lane.closed = true;
        emit LaneChanged(vault, false, reason, asOfBlock);
    }

    // ------------------------------------------------------------------ device: reopen

    /// @notice Device-signed reopen of `vault`'s lane. Anyone may relay.
    /// @dev    The signer must be the P1 key the registry binds to IERC173(vault).owner(). Checks, in this order:
    ///         - NoDeviceForVault when owner() cannot be read (no code, revert, short or non-address return data) or
    ///           the owner has no registered key;
    ///         - LaneNotClosed unless the lane is closed (v1.2; before the nonce and the signature, so a withheld
    ///           reopen cannot be relayed while the lane is open, to pre-empt an in-flight close report);
    ///         - NonceNotIncreasing unless nonce > lastReopenNonce(vault);
    ///         - BadReopenSignature unless P256.verify(reopenDigest(vault, nonce)) (low-s).
    ///         Then opens the lane, stores the nonce and the block.
    /// @param vault the vault (delegator) whose lane to reopen
    /// @param nonce any value greater than lastReopenNonce(vault) (the device uses its last nonce + 1)
    /// @param r     P1 signature r
    /// @param s     P1 signature s (low-s)
    function reopen(address vault, uint256 nonce, bytes32 r, bytes32 s) external {
        (bool ok, address owner) = _ownerOf(vault);
        if (!ok) revert NoDeviceForVault();

        bytes32 keyId = registry.keyIdOf(owner);
        if (keyId == bytes32(0)) revert NoDeviceForVault();
        (bytes32 px, bytes32 py, address keyOwner) = registry.keyOf(keyId);
        if (keyOwner != owner) revert NoDeviceForVault();

        if (!_lanes[vault].closed) revert LaneNotClosed();
        if (nonce <= _lastReopenNonce[vault]) revert NonceNotIncreasing();
        if (!P256.verify(reopenDigest(vault, nonce), r, s, px, py)) revert BadReopenSignature();

        _lastReopenNonce[vault] = nonce;
        _lanes[vault] = Lane({ closed: false, lastReopenBlock: uint64(block.number) });
        emit LaneChanged(vault, true, 0, uint64(block.number));
    }

    // ------------------------------------------------------------------ internal

    /// @dev Strict decoder for the 128-byte report: every word must be canonical for its type, else BadReport
    ///      (abi.decode would revert without a reason on a dirty word, and would accept trailing bytes).
    function _decodeReport(bytes calldata report)
        private
        pure
        returns (address vault, bool open, uint8 reason, uint64 asOfBlock)
    {
        if (report.length != REPORT_LENGTH) revert BadReport();
        uint256 w0;
        uint256 w1;
        uint256 w2;
        uint256 w3;
        assembly ("memory-safe") {
            w0 := calldataload(report.offset)
            w1 := calldataload(add(report.offset, 0x20))
            w2 := calldataload(add(report.offset, 0x40))
            w3 := calldataload(add(report.offset, 0x60))
        }
        if (w0 >> 160 != 0 || w1 > 1 || w2 > type(uint8).max || w3 > type(uint64).max) revert BadReport();
        // casting is safe because every word was range-checked just above
        // forge-lint: disable-next-line(unsafe-typecast)
        return (address(uint160(w0)), w1 == 1, uint8(w2), uint64(w3));
    }

    /// @dev IERC173(vault).owner() without letting a missing function, a revert or malformed return data bubble up.
    ///      (A plain try/catch does not catch an EOA / no-code vault: the empty return data fails to decode in the
    ///      caller.) Only the first 32 bytes of return data are copied.
    function _ownerOf(address vault) private view returns (bool ok, address owner) {
        bytes4 selector = IERC173.owner.selector;
        uint256 word;
        assembly ("memory-safe") {
            mstore(0x00, selector)
            ok := staticcall(gas(), vault, 0x00, 0x04, 0x00, 0x20)
            ok := and(ok, gt(returndatasize(), 0x1f))
            word := mload(0x00)
        }
        if (!ok || word >> 160 != 0) return (false, address(0));
        // casting to 'uint160' is safe because the upper 96 bits were checked to be zero just above
        // forge-lint: disable-next-line(unsafe-typecast)
        return (true, address(uint160(word)));
    }
}
