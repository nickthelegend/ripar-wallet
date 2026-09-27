// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { P256TestUtils } from "../P256TestUtils.sol";
import { IPulseCosignEnforcer } from "../../../src/interfaces/IPulseCosignEnforcer.sol";
import { Delegation, Caveat } from "@delegation-framework/utils/Types.sol";

/// @title DeviceVectors
/// @notice Typed loader for test/vectors/device_vectors.json, which test/vectors/gen_device_vectors.py generates from
///         the firmware's protocol reference (firmware/tools/make_request.py, demo device). Every struct mirrors one
///         JSON section; the JSON is re-read for every load (values stay in memory, never in storage).
abstract contract DeviceVectors is P256TestUtils {
    string internal constant DEVICE_VECTORS = "/test/vectors/device_vectors.json";

    struct Addrs {
        address dm; // MetaMask DelegationManager v1.3.0 (real address)
        address enforcer;
        address registry;
        address sentinel;
        address relay;
        address vault; // delegator (HybridDeleGator owned by the demo K1)
        address agent; // delegate = redeemer
        address token; // MockUSD
        address payee;
        address spender; // approve(spender, ..) co-sign
        address holder; // transferFrom(holder, payee2, ..) co-sign
        address payee2;
        address timestampEnforcer; // MetaMask v1.3.0 TimestampEnforcer (real address) in the re-paired mandate
    }

    struct Domains {
        bytes32 dm;
        bytes32 enforcer;
        bytes32 registry;
        bytes32 sentinel;
        bytes32 relay;
    }

    struct Demo {
        address k1;
        uint256 k1PrivateKey; // public demo seed: never fund
        uint256 p1PrivateKey;
        bytes32 px;
        bytes32 py;
        bytes32 keyId;
    }

    struct PairV {
        address owner;
        bytes32 px;
        bytes32 py;
        bytes32 keyId;
        bytes32 digest;
        bytes32 r;
        bytes32 s;
        bytes k1Signature;
    }

    struct MandateV {
        address delegate;
        address delegator;
        bytes32 authority;
        uint256 salt;
        uint256 agentId;
        uint256 pulseIndex; // index of the PulseCosignEnforcer caveat
        address[] enforcers;
        bytes[] terms;
        IPulseCosignEnforcer.PulseTerms t;
        bytes termsHex;
        bytes32 delegationHash;
        bytes32 digest;
        bytes signature;
    }

    struct CosignV {
        bytes32 delegationHash;
        address delegator;
        address redeemer;
        address target;
        uint256 value;
        bytes callData;
        bytes32 callDataHash;
        uint256 nonce;
        uint64 expiry;
        address payee;
        uint256 amount;
        bytes32 presenceHash;
        bytes32 structHash;
        bytes32 requestHash;
        bytes32 digest;
        bytes32 r;
        bytes32 s;
        bytes args;
    }

    /// @dev One entry of the firmware's ERC-20 decode table (firmware/test/host/vectors_eip712_abi.h ERC20S).
    struct Erc20DecodeV {
        bytes callData;
        uint256 kind; // 0 none, 1 transfer, 2 approve, 3 transferFrom, 4 unknown (C++ Erc20Call::Kind)
        address from;
        address to;
        uint256 amount;
        string note;
    }

    struct DenyV {
        address relay;
        uint256 agentId;
        bytes32 requestHash;
        bytes32 presenceHash;
        bytes32 digest;
        bytes32 r;
        bytes32 s;
    }

    struct RevokeV {
        bytes32 delegationHash;
        bytes32 digest;
        bytes32 r;
        bytes32 s;
    }

    struct PanicV {
        uint64 minEpoch;
        bytes32 digest;
        bytes32 r;
        bytes32 s;
    }

    struct ReopenV {
        address vault;
        uint256 nonce;
        bytes32 digest;
        bytes32 r;
        bytes32 s;
    }

    // ------------------------------------------------------------------ raw access
    function _json() internal view returns (string memory) {
        // read-only, inside foundry.toml fs_permissions (./test/vectors)
        // forge-lint: disable-next-line(unsafe-cheatcode)
        return vm.readFile(string.concat(vm.projectRoot(), DEVICE_VECTORS));
    }

    function _u(string memory j, string memory key) internal pure returns (uint256) {
        return vm.parseJsonUint(j, key);
    }

    function _h(string memory j, string memory key) internal pure returns (bytes32) {
        return vm.parseJsonBytes32(j, key);
    }

    function _a(string memory j, string memory key) internal pure returns (address) {
        return vm.parseJsonAddress(j, key);
    }

    function _b(string memory j, string memory key) internal pure returns (bytes memory) {
        return vm.parseJsonBytes(j, key);
    }

    // ------------------------------------------------------------------ typed sections
    function _loadAddrs(string memory j) internal pure returns (Addrs memory a) {
        a.dm = _a(j, ".addresses.delegationManager");
        a.enforcer = _a(j, ".addresses.enforcer");
        a.registry = _a(j, ".addresses.registry");
        a.sentinel = _a(j, ".addresses.sentinel");
        a.relay = _a(j, ".addresses.relay");
        a.vault = _a(j, ".addresses.vault");
        a.agent = _a(j, ".addresses.agent");
        a.token = _a(j, ".addresses.token");
        a.payee = _a(j, ".addresses.payee");
        a.spender = _a(j, ".addresses.spender");
        a.holder = _a(j, ".addresses.holder");
        a.payee2 = _a(j, ".addresses.payee2");
        a.timestampEnforcer = _a(j, ".addresses.timestampEnforcer");
    }

    function _loadDomains(string memory j) internal pure returns (Domains memory d) {
        d.dm = _h(j, ".domains.delegationManager.separator");
        d.enforcer = _h(j, ".domains.enforcer.separator");
        d.registry = _h(j, ".domains.registry.separator");
        d.sentinel = _h(j, ".domains.sentinel.separator");
        d.relay = _h(j, ".domains.relay.separator");
    }

    function _loadDemo(string memory j) internal pure returns (Demo memory d) {
        d.k1 = _a(j, ".demo.k1");
        d.k1PrivateKey = _u(j, ".demo.k1PrivateKey");
        d.p1PrivateKey = _u(j, ".demo.p1PrivateKey");
        d.px = _h(j, ".demo.px");
        d.py = _h(j, ".demo.py");
        d.keyId = _h(j, ".demo.keyId");
    }

    function _loadPair(string memory j) internal pure returns (PairV memory) {
        return _loadPair(j, ".pair");
    }

    /// @param key ".pair" or ".repair.pair"
    function _loadPair(string memory j, string memory key) internal pure returns (PairV memory p) {
        p.owner = _a(j, string.concat(key, ".owner"));
        p.px = _h(j, string.concat(key, ".px"));
        p.py = _h(j, string.concat(key, ".py"));
        p.keyId = _h(j, string.concat(key, ".keyId"));
        p.digest = _h(j, string.concat(key, ".digest"));
        p.r = _h(j, string.concat(key, ".r"));
        p.s = _h(j, string.concat(key, ".s"));
        p.k1Signature = _b(j, string.concat(key, ".k1Signature"));
    }

    function _loadMandate(string memory j) internal pure returns (MandateV memory) {
        return _loadMandate(j, ".mandate");
    }

    /// @param key ".mandate" or ".repair.mandate"
    function _loadMandate(string memory j, string memory key) internal pure returns (MandateV memory m) {
        m.delegate = _a(j, string.concat(key, ".delegate"));
        m.delegator = _a(j, string.concat(key, ".delegator"));
        m.authority = _h(j, string.concat(key, ".authority"));
        m.salt = _u(j, string.concat(key, ".salt"));
        m.agentId = _u(j, string.concat(key, ".agentId"));
        m.pulseIndex = _u(j, string.concat(key, ".pulseIndex"));
        uint256 n = _u(j, string.concat(key, ".caveatCount"));
        m.enforcers = new address[](n);
        m.terms = new bytes[](n);
        for (uint256 i; i < n; ++i) {
            string memory c = string.concat(key, ".caveats[", vm.toString(i), "]");
            m.enforcers[i] = _a(j, string.concat(c, ".enforcer"));
            m.terms[i] = _b(j, string.concat(c, ".terms"));
        }
        string memory t = string.concat(key, ".terms");
        m.t.px = _h(j, string.concat(t, ".px"));
        m.t.py = _h(j, string.concat(t, ".py"));
        m.t.token = _a(j, string.concat(t, ".token"));
        m.t.perTxAutoCap = uint128(_u(j, string.concat(t, ".perTxAutoCap")));
        m.t.periodAutoCap = uint128(_u(j, string.concat(t, ".periodAutoCap")));
        m.t.period = uint32(_u(j, string.concat(t, ".period")));
        m.t.epoch = uint64(_u(j, string.concat(t, ".epoch")));
        m.t.newPayeeNeedsHuman = vm.parseJsonBool(j, string.concat(t, ".newPayeeNeedsHuman"));
        m.t.sentinel = _a(j, string.concat(t, ".sentinel"));
        m.termsHex = _b(j, string.concat(t, ".hex"));
        m.delegationHash = _h(j, string.concat(key, ".delegationHash"));
        m.digest = _h(j, string.concat(key, ".digest"));
        m.signature = _b(j, string.concat(key, ".signature"));
    }

    /// @param key ".cosignErc20", ".cosignNative", ".cosignApprove" or ".cosignTransferFrom"
    function _loadCosign(string memory j, string memory key) internal pure returns (CosignV memory c) {
        c.delegationHash = _h(j, string.concat(key, ".delegationHash"));
        c.delegator = _a(j, string.concat(key, ".delegator"));
        c.redeemer = _a(j, string.concat(key, ".redeemer"));
        c.target = _a(j, string.concat(key, ".target"));
        c.value = _u(j, string.concat(key, ".value"));
        c.callData = _b(j, string.concat(key, ".calldata"));
        c.callDataHash = _h(j, string.concat(key, ".callDataHash"));
        c.nonce = _u(j, string.concat(key, ".nonce"));
        c.expiry = uint64(_u(j, string.concat(key, ".expiry")));
        c.payee = _a(j, string.concat(key, ".payee"));
        c.amount = _u(j, string.concat(key, ".amount"));
        c.presenceHash = _h(j, string.concat(key, ".presenceHash"));
        c.structHash = _h(j, string.concat(key, ".structHash"));
        c.requestHash = _h(j, string.concat(key, ".requestHash"));
        c.digest = _h(j, string.concat(key, ".digest"));
        c.r = _h(j, string.concat(key, ".r"));
        c.s = _h(j, string.concat(key, ".s"));
        c.args = _b(j, string.concat(key, ".args"));
    }

    function _loadDeny(string memory j) internal pure returns (DenyV memory) {
        return _loadDeny(j, ".deny");
    }

    /// @param key ".deny" (built by the device from a co-sign review) or ".denyRequest" (ripar-deny-req)
    function _loadDeny(string memory j, string memory key) internal pure returns (DenyV memory d) {
        d.relay = _a(j, string.concat(key, ".relay"));
        d.agentId = _u(j, string.concat(key, ".agentId"));
        d.requestHash = _h(j, string.concat(key, ".requestHash"));
        d.presenceHash = _h(j, string.concat(key, ".presenceHash"));
        d.digest = _h(j, string.concat(key, ".digest"));
        d.r = _h(j, string.concat(key, ".r"));
        d.s = _h(j, string.concat(key, ".s"));
    }

    function _loadRevoke(string memory j) internal pure returns (RevokeV memory v) {
        v.delegationHash = _h(j, ".revoke.delegationHash");
        v.digest = _h(j, ".revoke.digest");
        v.r = _h(j, ".revoke.r");
        v.s = _h(j, ".revoke.s");
    }

    function _loadPanic(string memory j) internal pure returns (PanicV memory) {
        return _loadPanic(j, ".panic");
    }

    /// @param key ".panic" or ".repair.panic"
    function _loadPanic(string memory j, string memory key) internal pure returns (PanicV memory v) {
        v.minEpoch = uint64(_u(j, string.concat(key, ".minEpoch")));
        v.digest = _h(j, string.concat(key, ".digest"));
        v.r = _h(j, string.concat(key, ".r"));
        v.s = _h(j, string.concat(key, ".s"));
    }

    function _loadReopen(string memory j) internal pure returns (ReopenV memory) {
        return _loadReopen(j, ".reopen");
    }

    /// @param key ".reopen" or ".repair.reopen"
    function _loadReopen(string memory j, string memory key) internal pure returns (ReopenV memory v) {
        v.vault = _a(j, string.concat(key, ".vault"));
        v.nonce = _u(j, string.concat(key, ".nonce"));
        v.digest = _h(j, string.concat(key, ".digest"));
        v.r = _h(j, string.concat(key, ".r"));
        v.s = _h(j, string.concat(key, ".s"));
    }

    /// @notice The firmware's ERC-20 decode known answers, as copied (and cross-checked) by the generator.
    function _loadErc20Decode(string memory j) internal pure returns (Erc20DecodeV[] memory v) {
        uint256 n = _u(j, ".erc20Decode.count");
        v = new Erc20DecodeV[](n);
        for (uint256 i; i < n; ++i) {
            string memory e = string.concat(".erc20Decode.vectors[", vm.toString(i), "]");
            v[i].callData = _b(j, string.concat(e, ".calldata"));
            v[i].kind = _u(j, string.concat(e, ".kind"));
            v[i].from = _a(j, string.concat(e, ".from"));
            v[i].to = _a(j, string.concat(e, ".to"));
            v[i].amount = uint256(_h(j, string.concat(e, ".amount")));
            v[i].note = vm.parseJsonString(j, string.concat(e, ".note"));
        }
    }

    // ------------------------------------------------------------------ framework structs
    /// @notice The signed mandate as a framework Delegation. `args` (the co-sign) goes into the pulse caveat only; the
    ///         other caveats get empty args, as the companion relays them.
    function _delegation(MandateV memory m, bytes memory args) internal pure returns (Delegation memory d) {
        Caveat[] memory caveats = new Caveat[](m.enforcers.length);
        for (uint256 i; i < caveats.length; ++i) {
            caveats[i] =
                Caveat({ enforcer: m.enforcers[i], terms: m.terms[i], args: i == m.pulseIndex ? args : bytes("") });
        }
        d = Delegation({
            delegate: m.delegate,
            delegator: m.delegator,
            authority: m.authority,
            caveats: caveats,
            salt: m.salt,
            signature: m.signature
        });
    }
}
