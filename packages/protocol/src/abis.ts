// viem ABIs of the Ripar contracts, written from contracts/src/interfaces/*.sol (SPEC v1.2; the tests compare every
// function / event / error signature with the .sol files), plus the DelegationManager / ERC-8004 subsets the apps use.
import { parseAbi } from 'viem';

export const PULSE_COSIGN_ENFORCER_ABI = parseAbi([
  'struct PulseTerms { bytes32 px; bytes32 py; address token; uint128 perTxAutoCap; uint128 periodAutoCap; uint32 period; uint64 epoch; bool newPayeeNeedsHuman; address sentinel; }',
  'struct Approval { bytes32 keyId; bytes32 delegationHash; address delegator; address redeemer; address payee; uint64 timestamp; }',
  'event AutoSpend(bytes32 indexed delegationHash, address indexed delegator, address indexed redeemer, address delegationManager, address payee, uint256 amount, uint256 periodSpent)',
  'event HumanCosigned(bytes32 indexed delegationHash, address indexed delegator, address indexed redeemer, address delegationManager, address payee, uint256 amount, bytes32 keyId, bytes32 approvalDigest, bytes32 presenceHash)',
  'event PayeeApproved(address indexed delegationManager, bytes32 indexed delegationHash, address indexed payee)',
  'event Revoked(bytes32 indexed keyId, bytes32 indexed delegationHash)',
  'event Panicked(bytes32 indexed keyId, uint64 minEpoch)',
  'error InvalidTerms()',
  'error InvalidArgs()',
  'error HumanRequired()',
  'error LaneClosed()',
  'error DelegationRevoked()',
  'error StaleEpoch()',
  'error EpochNotIncreasing()',
  'error BadCosign()',
  'error CosignReplayed()',
  'error CosignExpired()',
  'error BadSignature()',
  'function getTermsInfo(bytes terms) pure returns (PulseTerms)',
  'function keyIdOf(bytes32 px, bytes32 py) pure returns (bytes32)',
  'function domainSeparator() view returns (bytes32)',
  'function approvalStructHash(bytes32 delegationHash, address delegator, address redeemer, address target, uint256 value, bytes32 callDataHash, uint256 nonce, uint64 expiry, bytes32 presenceHash) pure returns (bytes32)',
  'function approvalDigest(bytes32 delegationHash, address delegator, address redeemer, address target, uint256 value, bytes32 callDataHash, uint256 nonce, uint64 expiry, bytes32 presenceHash) view returns (bytes32)',
  'function revokeDigest(bytes32 delegationHash) view returns (bytes32)',
  'function panicDigest(uint64 minEpoch) view returns (bytes32)',
  'function consumed(address delegationManager, bytes32 approvalDigest) view returns (bool)',
  'function approvalOf(address delegationManager, bytes32 approvalDigest) view returns (Approval)',
  'function isRevoked(bytes32 keyId, bytes32 delegationHash) view returns (bool)',
  'function minEpoch(bytes32 keyId) view returns (uint64)',
  'function periodSpent(address delegationManager, bytes32 delegationHash) view returns (uint256 spent, uint64 start)',
  'function autoBudget(address delegationManager, bytes32 delegationHash, bytes terms) view returns (uint256 spent, uint256 remaining, uint64 periodStart, uint64 periodEnd)',
  'function isKnownPayee(address delegationManager, bytes32 delegationHash, address payee) view returns (bool)',
  'function nonceUsed(address delegationManager, bytes32 delegationHash, uint256 nonce) view returns (bool)',
  'function revoke(bytes32 px, bytes32 py, bytes32 delegationHash, bytes32 r, bytes32 s)',
  'function panic(bytes32 px, bytes32 py, uint64 newMinEpoch, bytes32 r, bytes32 s)',
]);

export const RIPAR_DEVICE_REGISTRY_ABI = parseAbi([
  'event DeviceRegistered(address indexed owner, bytes32 indexed keyId, bytes32 px, bytes32 py)',
  'error ZeroOwner()',
  'error BadDeviceSignature()',
  'error BadOwnerSignature()',
  'error KeyTaken()',
  'function domainSeparator() view returns (bytes32)',
  'function bindDigest(address owner, bytes32 px, bytes32 py) view returns (bytes32)',
  'function registerDevice(address owner, bytes32 px, bytes32 py, bytes32 pr, bytes32 ps, bytes ownerSig) returns (bytes32 keyId)',
  'function keyIdOf(address owner) view returns (bytes32)',
  'function isRetired(bytes32 keyId) view returns (bool)',
  'function keyOf(bytes32 keyId) view returns (bytes32 px, bytes32 py, address owner)',
]);

export const RIPAR_SENTINEL_ABI = parseAbi([
  'event LaneChanged(address indexed vault, bool open, uint8 reason, uint64 asOfBlock)',
  'event ReportIgnored(address indexed vault, uint8 reason, uint64 asOfBlock)',
  'error NotForwarder()',
  'error BadWorkflowOwner()',
  'error BadReport()',
  'error NonceNotIncreasing()',
  'error NoDeviceForVault()',
  'error BadReopenSignature()',
  'error LaneNotClosed()',
  'function onReport(bytes metadata, bytes report)',
  'function laneOpen(address vault) view returns (bool)',
  'function lastReopenNonce(address vault) view returns (uint256)',
  'function domainSeparator() view returns (bytes32)',
  'function reopenDigest(address vault, uint256 nonce) view returns (bytes32)',
  'function reopen(address vault, uint256 nonce, bytes32 r, bytes32 s)',
]);

export const RIPAR_REPUTATION_RELAY_ABI = parseAbi([
  'event Verdict(uint256 indexed agentId, bytes32 indexed keyId, bytes32 requestHash, bool approved)',
  'event AgentShielded(uint256 indexed agentId, bytes32 indexed keyId, bytes32 requestHash)',
  'error NotConsumed()',
  'error NotRedeemer()',
  'error NotAgentRedeemer()',
  'error AlreadyAttested()',
  'error UnknownDevice()',
  'error BadDenySignature()',
  'error AgentIsShielded()',
  'function domainSeparator() view returns (bytes32)',
  'function delegationManager() view returns (address)',
  'function denyDigest(uint256 agentId, bytes32 requestHash, bytes32 presenceHash) view returns (bytes32)',
  'function attestApproval(uint256 agentId, bytes32 approvalDigest)',
  'function attestDenial(uint256 agentId, bytes32 requestHash, bytes32 presenceHash, bytes32 px, bytes32 py, bytes32 r, bytes32 s)',
  'function approvalAttested(bytes32 approvalDigest) view returns (bool)',
  'function shieldedDenials(uint256 agentId) view returns (uint256)',
  'function denialAttested(bytes32 keyId, bytes32 requestHash) view returns (bool)',
]);

/** the DelegationManager v1.3.0 functions a Ripar app calls */
export const DELEGATION_MANAGER_ABI = parseAbi([
  'function redeemDelegations(bytes[] _permissionContexts, bytes32[] _modes, bytes[] _executionCallDatas)',
  'function disabledDelegations(bytes32 delegationHash) view returns (bool)',
  'function getDomainHash() view returns (bytes32)',
]);

/** ERC-8004 subset live on Monad testnet (contracts/src/interfaces/external/IERC8004.sol) */
export const ERC8004_IDENTITY_ABI = parseAbi([
  'struct MetadataEntry { string key; bytes value; }',
  'function register(string agentURI, MetadataEntry[] metadata) returns (uint256 agentId)',
  'function ownerOf(uint256 agentId) view returns (address)',
  'function isAuthorizedOrOwner(address spender, uint256 agentId) view returns (bool)',
  'function getMetadata(uint256 agentId, string key) view returns (bytes)',
]);

/** the vault's ERC-173 owner() (= K1) */
export const ERC173_OWNER_ABI = parseAbi(['function owner() view returns (address)']);
