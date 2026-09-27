// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { Vm } from "forge-std/Vm.sol";
import {
    ModeLib,
    ModeCode,
    ModePayload,
    ExecType,
    CALLTYPE_SINGLE,
    CALLTYPE_BATCH,
    CALLTYPE_DELEGATECALL,
    EXECTYPE_DEFAULT,
    EXECTYPE_TRY,
    MODE_DEFAULT
} from "@erc7579/lib/ModeLib.sol";
import { P256 } from "@openzeppelin/contracts/utils/cryptography/P256.sol";

import { PulseCosignEnforcer } from "../src/PulseCosignEnforcer.sol";
import { IPulseCosignEnforcer } from "../src/interfaces/IPulseCosignEnforcer.sol";
import { PulseCosignEnforcerBase } from "./utils/enforcer/PulseCosignEnforcerBase.sol";
import { RevertingSentinel, GarbageSentinel, P256AcceptAllStub } from "./utils/enforcer/MockSentinel.sol";
import { FirmwareVectors } from "./utils/enforcer/FirmwareVectors.sol";

/// @notice Behaviour suite for PulseCosignEnforcer (SPEC.md, docs/PROTOCOL.md §3/§4). P-256 verification runs on the
///         OpenZeppelin Solidity fallback here; PulseCosignEnforcerPrecompileTest re-runs everything with the
///         0x0100 precompile mock etched.
contract PulseCosignEnforcerTest is PulseCosignEnforcerBase {
    // =================================================================================================== terms

    function test_terms_wrongLength_reverts() public {
        bytes memory good = _enc(_nativeTerms());
        assertEq(good.length, 288);
        uint256[6] memory lens = [uint256(0), 1, 256, 287, 289, 320];
        for (uint256 i; i < lens.length; ++i) {
            bytes memory bad = _resize(good, lens[i]);
            vm.expectRevert(IPulseCosignEnforcer.InvalidTerms.selector);
            enforcer.getTermsInfo(bad);
            vm.expectRevert(IPulseCosignEnforcer.InvalidTerms.selector);
            _autoNative(bad, PAYEE, 1);
            vm.expectRevert(IPulseCosignEnforcer.InvalidTerms.selector);
            enforcer.beforeHook(bad, new bytes(160), single, _exec(PAYEE, 1, ""), DH, DELEGATOR, REDEEMER);
        }
    }

    function _expectNonCanonical(uint256 index, uint256 word) internal {
        bytes memory bad = _setWord(_enc(_nativeTerms()), index, word);
        vm.expectRevert(IPulseCosignEnforcer.InvalidTerms.selector);
        enforcer.getTermsInfo(bad);
        vm.expectRevert(IPulseCosignEnforcer.InvalidTerms.selector);
        _autoNative(bad, PAYEE, 1);
        vm.expectRevert(IPulseCosignEnforcer.InvalidTerms.selector);
        enforcer.beforeHook(bad, new bytes(160), single, _exec(PAYEE, 1, ""), DH, DELEGATOR, REDEEMER);
    }

    function test_terms_nonCanonicalWords_revert() public {
        _expectNonCanonical(2, (uint256(1) << 160) | uint160(TOKEN)); // dirty token address
        _expectNonCanonical(2, type(uint256).max);
        _expectNonCanonical(3, uint256(1) << 128); // perTxAutoCap: uint128 overflow word
        _expectNonCanonical(3, type(uint256).max);
        _expectNonCanonical(4, uint256(type(uint128).max) + 1); // periodAutoCap
        _expectNonCanonical(5, uint256(1) << 32); // period: uint32
        _expectNonCanonical(6, uint256(1) << 64); // epoch: uint64
        _expectNonCanonical(7, 2); // bool = 2
        _expectNonCanonical(7, uint256(1) << 255);
        _expectNonCanonical(8, (uint256(1) << 160) | uint160(address(sentinel))); // dirty sentinel
    }

    function test_terms_maxCanonicalValues_ok() public view {
        IPulseCosignEnforcer.PulseTerms memory t = IPulseCosignEnforcer.PulseTerms({
            px: bytes32(type(uint256).max),
            py: bytes32(0),
            token: address(type(uint160).max),
            perTxAutoCap: type(uint128).max,
            periodAutoCap: type(uint128).max,
            period: type(uint32).max,
            epoch: type(uint64).max,
            newPayeeNeedsHuman: true,
            sentinel: address(type(uint160).max)
        });
        IPulseCosignEnforcer.PulseTerms memory d = enforcer.getTermsInfo(abi.encode(t));
        assertEq(keccak256(abi.encode(d)), keccak256(abi.encode(t)));
    }

    function testFuzz_getTermsInfo_roundTrip(IPulseCosignEnforcer.PulseTerms memory t) public view {
        IPulseCosignEnforcer.PulseTerms memory d = enforcer.getTermsInfo(abi.encode(t));
        assertEq(d.px, t.px);
        assertEq(d.py, t.py);
        assertEq(d.token, t.token);
        assertEq(d.perTxAutoCap, t.perTxAutoCap);
        assertEq(d.periodAutoCap, t.periodAutoCap);
        assertEq(d.period, t.period);
        assertEq(d.epoch, t.epoch);
        assertEq(d.newPayeeNeedsHuman, t.newPayeeNeedsHuman);
        assertEq(d.sentinel, t.sentinel);
    }

    /// @dev Reference: the Solidity ABI decoder (what SPEC.md step 1 describes).
    function abiDecodeTerms(bytes calldata terms) external pure returns (IPulseCosignEnforcer.PulseTerms memory) {
        return abi.decode(terms, (IPulseCosignEnforcer.PulseTerms));
    }

    /// @notice Differential: the enforcer's strict decoder accepts exactly the 288-byte blobs abi.decode accepts, with
    ///         the same result, and rejects the others with InvalidTerms().
    function testFuzz_terms_acceptExactlyWhatAbiDecodeAccepts(uint256[9] memory words, uint16 dirtyMask) public view {
        uint256[9] memory masks = [
            type(uint256).max,
            type(uint256).max,
            type(uint160).max,
            type(uint128).max,
            type(uint128).max,
            type(uint32).max,
            type(uint64).max,
            1,
            type(uint160).max
        ];
        for (uint256 i; i < 9; ++i) {
            if ((dirtyMask >> i) & 1 == 0) words[i] &= masks[i];
        }
        bytes memory raw = abi.encodePacked(words);
        assertEq(raw.length, 288);
        (bool okAbi, bytes memory retAbi) = address(this).staticcall(abi.encodeCall(this.abiDecodeTerms, (raw)));
        (bool okEnf, bytes memory retEnf) =
            address(enforcer).staticcall(abi.encodeCall(IPulseCosignEnforcer.getTermsInfo, (raw)));
        assertEq(okEnf, okAbi, "same acceptance as abi.decode");
        if (okAbi) {
            assertEq(retEnf, retAbi, "same decoded terms");
        } else {
            assertEq(retEnf, abi.encodeWithSelector(IPulseCosignEnforcer.InvalidTerms.selector));
        }
    }

    // =================================================================================================== args

    function test_args_validLengths_ok() public {
        bytes memory terms = _enc(_nativeTerms());
        _autoNative(terms, PAYEE, 1); // 0 bytes: AUTO
        Req memory q = _req(PAYEE, 1, "");
        (bytes memory args,) = _sign(DEVICE_PK, q);
        assertEq(args.length, 160);
        _human(terms, q, args); // 160 bytes: HUMAN
    }

    function test_args_invalidLengths_revert() public {
        bytes memory terms = _enc(_nativeTerms());
        Req memory q = _req(PAYEE, 1, "");
        (bytes memory args,) = _sign(DEVICE_PK, q);
        uint256[6] memory lens = [uint256(1), 32, 128, 159, 161, 192];
        for (uint256 i; i < lens.length; ++i) {
            vm.expectRevert(IPulseCosignEnforcer.InvalidArgs.selector);
            _human(terms, q, _resize(args, lens[i]));
        }
    }

    function testFuzz_args_badLength_reverts(bytes memory args) public {
        vm.assume(args.length != 0 && args.length != 160);
        vm.expectRevert(IPulseCosignEnforcer.InvalidArgs.selector);
        enforcer.beforeHook(_enc(_nativeTerms()), args, single, _exec(PAYEE, 1, ""), DH, DELEGATOR, REDEEMER);
    }

    function test_args_nonCanonicalExpiry_reverts() public {
        Req memory q = _req(PAYEE, 1, "");
        (bytes memory args,) = _sign(DEVICE_PK, q);
        bytes memory bad = _setWord(args, 1, (uint256(1) << 64) | q.expiry);
        vm.expectRevert(IPulseCosignEnforcer.InvalidArgs.selector);
        _human(_enc(_nativeTerms()), q, bad);
    }

    // =================================================================================================== modes

    function test_modes_batchAndTry_revert() public {
        bytes memory terms = _enc(_nativeTerms());
        bytes memory exec = _exec(PAYEE, 1, "");
        Req memory q = _req(PAYEE, 1, "");
        (bytes memory args,) = _sign(DEVICE_PK, q);

        ModeCode batch = ModeLib.encodeSimpleBatch();
        ModeCode trySingle = ModeLib.encode(CALLTYPE_SINGLE, EXECTYPE_TRY, MODE_DEFAULT, ModePayload.wrap(0x00));
        ModeCode tryBatch = ModeLib.encode(CALLTYPE_BATCH, EXECTYPE_TRY, MODE_DEFAULT, ModePayload.wrap(0x00));
        ModeCode delegatecall_ =
            ModeLib.encode(CALLTYPE_DELEGATECALL, EXECTYPE_DEFAULT, MODE_DEFAULT, ModePayload.wrap(0x00));
        ModeCode unknownExec =
            ModeLib.encode(CALLTYPE_SINGLE, ExecType.wrap(0x02), MODE_DEFAULT, ModePayload.wrap(0x00));

        bytes[2] memory argSets = [bytes(""), args];
        for (uint256 i; i < 2; ++i) {
            vm.expectRevert("CaveatEnforcer:invalid-call-type");
            enforcer.beforeHook(terms, argSets[i], batch, exec, DH, DELEGATOR, REDEEMER);
            vm.expectRevert("CaveatEnforcer:invalid-call-type");
            enforcer.beforeHook(terms, argSets[i], tryBatch, exec, DH, DELEGATOR, REDEEMER);
            vm.expectRevert("CaveatEnforcer:invalid-call-type");
            enforcer.beforeHook(terms, argSets[i], delegatecall_, exec, DH, DELEGATOR, REDEEMER);
            vm.expectRevert("CaveatEnforcer:invalid-execution-type");
            enforcer.beforeHook(terms, argSets[i], trySingle, exec, DH, DELEGATOR, REDEEMER);
            vm.expectRevert("CaveatEnforcer:invalid-execution-type");
            enforcer.beforeHook(terms, argSets[i], unknownExec, exec, DH, DELEGATOR, REDEEMER);
        }
        // nothing was consumed or spent by the rejected calls
        _human(terms, q, args);
        (uint256 spent,) = enforcer.periodSpent(address(this), DH);
        assertEq(spent, 0);
    }

    function test_otherHooks_areNoOps() public {
        bytes memory junk = hex"deadbeef";
        ModeCode batch = ModeLib.encodeSimpleBatch();
        enforcer.beforeAllHook(junk, junk, batch, junk, DH, DELEGATOR, REDEEMER);
        enforcer.afterHook(junk, junk, batch, junk, DH, DELEGATOR, REDEEMER);
        enforcer.afterAllHook(junk, junk, batch, junk, DH, DELEGATOR, REDEEMER);
        (uint256 spent, uint64 start) = enforcer.periodSpent(address(this), DH);
        assertEq(spent, 0);
        assertEq(start, 0);
    }

    function test_executionCallData_tooShort_reverts() public {
        bytes memory terms = _enc(_nativeTerms());
        vm.expectRevert();
        enforcer.beforeHook(terms, "", single, new bytes(51), DH, DELEGATOR, REDEEMER);
        vm.expectRevert();
        enforcer.beforeHook(terms, "", single, "", DH, DELEGATOR, REDEEMER);
    }

    // =================================================================================================== AUTO native

    function test_auto_native_ok() public {
        bytes memory terms = _enc(_nativeTerms());
        vm.expectEmit(address(enforcer));
        emit AutoSpend(DH, DELEGATOR, REDEEMER, address(this), PAYEE, 0.4 ether, 0.4 ether);
        _autoNative(terms, PAYEE, 0.4 ether);
        (uint256 spent, uint64 start) = enforcer.periodSpent(address(this), DH);
        assertEq(spent, 0.4 ether);
        assertEq(start, T0);

        vm.warp(T0 + 10);
        vm.expectEmit(address(enforcer));
        emit AutoSpend(DH, DELEGATOR, REDEEMER, address(this), PAYEE2, 0.5 ether, 0.9 ether);
        _autoNative(terms, PAYEE2, 0.5 ether);
        (spent, start) = enforcer.periodSpent(address(this), DH);
        assertEq(spent, 0.9 ether);
        assertEq(start, T0, "start is set by the first spend only");
    }

    function test_auto_native_zeroValue_humanRequired() public {
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoNative(_enc(_nativeTerms()), PAYEE, 0);
    }

    function test_auto_native_withCalldata_humanRequired() public {
        bytes memory terms = _enc(_nativeTerms());
        bytes[5] memory datas = [bytes(hex"00"), hex"a9059cbb", _transfer(PAYEE, 1), hex"deadbeefcafe", new bytes(100)];
        for (uint256 i; i < datas.length; ++i) {
            vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
            _auto(terms, _exec(PAYEE, 0.1 ether, datas[i]));
        }
    }

    function test_auto_native_perTxCap() public {
        bytes memory terms = _enc(_nativeTerms());
        _autoNative(terms, PAYEE, NATIVE_PER_TX); // == cap ok
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoNative(terms, PAYEE, uint256(NATIVE_PER_TX) + 1);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoNative(terms, PAYEE, type(uint256).max);
    }

    function test_auto_zeroPerTxCap_alwaysHuman() public {
        IPulseCosignEnforcer.PulseTerms memory t = _nativeTerms();
        t.perTxAutoCap = 0;
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoNative(_enc(t), PAYEE, 1);
    }

    function test_auto_native_periodCap() public {
        bytes memory terms = _enc(_nativeTerms());
        _autoNative(terms, PAYEE, 1 ether);
        _autoNative(terms, PAYEE, 1 ether);
        _autoNative(terms, PAYEE, 1 ether - 1);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoNative(terms, PAYEE, 2);
        _autoNative(terms, PAYEE, 1); // exactly the period cap
        (uint256 spent,) = enforcer.periodSpent(address(this), DH);
        assertEq(spent, NATIVE_PERIOD_CAP);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoNative(terms, PAYEE, 1);
    }

    function test_auto_periodRollover_aligned() public {
        bytes memory terms = _enc(_nativeTerms());
        _autoNative(terms, PAYEE, 1 ether);
        _autoNative(terms, PAYEE, 1 ether);
        _autoNative(terms, PAYEE, 1 ether);

        vm.warp(T0 + PERIOD - 1); // still the first period
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoNative(terms, PAYEE, 1);

        vm.warp(T0 + PERIOD); // boundary: new period
        vm.expectEmit(address(enforcer));
        emit AutoSpend(DH, DELEGATOR, REDEEMER, address(this), PAYEE, 0.5 ether, 0.5 ether);
        _autoNative(terms, PAYEE, 0.5 ether);
        (uint256 spent, uint64 start) = enforcer.periodSpent(address(this), DH);
        assertEq(spent, 0.5 ether);
        assertEq(start, T0 + PERIOD);

        // 3.5 periods later than the first start: the new start is aligned to T0 + 3 periods, not to now
        vm.warp(T0 + 3 * uint256(PERIOD) + PERIOD / 2);
        _autoNative(terms, PAYEE, 1 ether);
        (spent, start) = enforcer.periodSpent(address(this), DH);
        assertEq(spent, 1 ether);
        assertEq(start, T0 + 3 * uint256(PERIOD));

        // the aligned window ends at T0 + 4 periods, not at now + period
        _autoNative(terms, PAYEE, 1 ether);
        _autoNative(terms, PAYEE, 1 ether);
        vm.warp(T0 + 4 * uint256(PERIOD) - 1);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoNative(terms, PAYEE, 1);
        vm.warp(T0 + 4 * uint256(PERIOD));
        _autoNative(terms, PAYEE, 1 ether);
        (, start) = enforcer.periodSpent(address(this), DH);
        assertEq(start, T0 + 4 * uint256(PERIOD));
    }

    function test_auto_periodZero_neverResets() public {
        IPulseCosignEnforcer.PulseTerms memory t = _nativeTerms();
        t.period = 0;
        bytes memory terms = _enc(t);
        _autoNative(terms, PAYEE, 1 ether);
        _autoNative(terms, PAYEE, 1 ether);
        _autoNative(terms, PAYEE, 1 ether);
        vm.warp(T0 + 3650 days);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoNative(terms, PAYEE, 1);
        (uint256 spent, uint64 start) = enforcer.periodSpent(address(this), DH);
        assertEq(spent, 3 ether);
        assertEq(start, T0);
    }

    function test_auto_periodState_perDelegationAndManager() public {
        bytes memory terms = _enc(_nativeTerms());
        _autoNative(terms, PAYEE, 1 ether);
        enforcer.beforeHook(terms, "", single, _exec(PAYEE, 1 ether, ""), DH2, DELEGATOR, REDEEMER);
        vm.prank(MANAGER_B);
        enforcer.beforeHook(terms, "", single, _exec(PAYEE, 0.25 ether, ""), DH, DELEGATOR, REDEEMER);
        (uint256 a,) = enforcer.periodSpent(address(this), DH);
        (uint256 b,) = enforcer.periodSpent(address(this), DH2);
        (uint256 c,) = enforcer.periodSpent(MANAGER_B, DH);
        assertEq(a, 1 ether);
        assertEq(b, 1 ether);
        assertEq(c, 0.25 ether);
    }

    function test_auto_knownPayee_required() public {
        IPulseCosignEnforcer.PulseTerms memory t = _nativeTerms();
        t.newPayeeNeedsHuman = true;
        bytes memory terms = _enc(t);

        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoNative(terms, PAYEE, 0.1 ether);

        _cosign(terms, _req(PAYEE, 0.01 ether, "")); // a human pays PAYEE once
        assertTrue(enforcer.isKnownPayee(address(this), DH, PAYEE));
        _autoNative(terms, PAYEE, 0.1 ether);

        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoNative(terms, PAYEE2, 0.1 ether); // still unknown

        // known payees are per mandate (delegationHash), even for the same delegator (v1.1)
        assertFalse(enforcer.isKnownPayee(address(this), DH2, PAYEE));
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        enforcer.beforeHook(terms, "", single, _exec(PAYEE, 0.1 ether, ""), DH2, DELEGATOR, REDEEMER);

        // and per manager
        vm.prank(MANAGER_B);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        enforcer.beforeHook(terms, "", single, _exec(PAYEE, 0.1 ether, ""), DH, DELEGATOR, REDEEMER);
    }

    function test_auto_knownPayee_off_anyPayee() public {
        bytes memory terms = _enc(_nativeTerms());
        _autoNative(terms, PAYEE, 0.1 ether);
        _autoNative(terms, PAYEE2, 0.1 ether);
        _autoNative(terms, address(0x1234), 0.1 ether);
        assertFalse(enforcer.isKnownPayee(address(this), DH, PAYEE), "AUTO never marks payees");
    }

    function test_auto_tokenTerms_nativeCall_humanRequired() public {
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoNative(_enc(_tokenTerms()), PAYEE, 1);
    }

    // =================================================================================================== AUTO ERC-20

    function test_auto_erc20_transfer_ok() public {
        bytes memory terms = _enc(_tokenTerms());
        vm.expectEmit(address(enforcer));
        emit AutoSpend(DH, DELEGATOR, REDEEMER, address(this), PAYEE, 40e6, 40e6);
        _auto(terms, _exec(TOKEN, 0, _transfer(PAYEE, 40e6)));
        _auto(terms, _exec(TOKEN, 0, _transfer(PAYEE2, TOKEN_PER_TX)));
        (uint256 spent, uint64 start) = enforcer.periodSpent(address(this), DH);
        assertEq(spent, 140e6);
        assertEq(start, T0);
    }

    function test_auto_erc20_caps() public {
        bytes memory terms = _enc(_tokenTerms());
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _auto(terms, _exec(TOKEN, 0, _transfer(PAYEE, uint256(TOKEN_PER_TX) + 1)));
        _auto(terms, _exec(TOKEN, 0, _transfer(PAYEE, 100e6)));
        _auto(terms, _exec(TOKEN, 0, _transfer(PAYEE, 100e6)));
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _auto(terms, _exec(TOKEN, 0, _transfer(PAYEE, 50e6 + 1)));
        _auto(terms, _exec(TOKEN, 0, _transfer(PAYEE, 50e6)));
        vm.warp(T0 + PERIOD);
        _auto(terms, _exec(TOKEN, 0, _transfer(PAYEE, 100e6)));
    }

    function test_auto_erc20_notMeterable_humanRequired() public {
        bytes memory terms = _enc(_tokenTerms());
        bytes memory transferOk = _transfer(PAYEE, 1e6);

        bytes[] memory execs = new bytes[](12);
        execs[0] = _exec(TOKEN, 0, _approve(PAYEE, 1e6));
        execs[1] = _exec(TOKEN, 0, _transferFrom(DELEGATOR, PAYEE, 1e6));
        execs[2] = _exec(address(0xBAD), 0, transferOk); // wrong token
        execs[3] = _exec(TOKEN, 1, transferOk); // native value on an ERC-20 call
        execs[4] = _exec(TOKEN, 0, _resize(transferOk, 67));
        execs[5] = _exec(TOKEN, 0, bytes.concat(transferOk, hex"00"));
        execs[6] = _exec(TOKEN, 0, _setWordAt(transferOk, 4, (uint256(1) << 160) | uint160(PAYEE))); // dirty to
        execs[7] = _exec(TOKEN, 0, abi.encodeWithSelector(bytes4(0x12345678), PAYEE, 1e6)); // unknown selector
        execs[8] = _exec(TOKEN, 0, ""); // native call to the token
        execs[9] = _exec(TOKEN, 0, hex"a9059cbb"); // selector only
        execs[10] = _exec(TOKEN, 0, bytes.concat(transferOk, new bytes(32))); // 100-byte transfer
        execs[11] = _exec(TOKEN, 0, _resize(_transferFrom(DELEGATOR, PAYEE, 1e6), 68)); // truncated transferFrom
        for (uint256 i; i < execs.length; ++i) {
            vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
            _auto(terms, execs[i]);
        }
        _auto(terms, _exec(TOKEN, 0, transferOk)); // sanity: the well-formed one passes
    }

    function test_auto_erc20_knownPayee_isTheRecipient() public {
        IPulseCosignEnforcer.PulseTerms memory t = _tokenTerms();
        t.newPayeeNeedsHuman = true;
        bytes memory terms = _enc(t);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _auto(terms, _exec(TOKEN, 0, _transfer(PAYEE, 1e6)));

        _cosign(terms, _req(TOKEN, 0, _transfer(PAYEE, 5e6)));
        assertTrue(enforcer.isKnownPayee(address(this), DH, PAYEE));
        assertFalse(enforcer.isKnownPayee(address(this), DH, TOKEN), "the token contract is not the payee");
        _auto(terms, _exec(TOKEN, 0, _transfer(PAYEE, 1e6)));
    }

    // =================================================================================================== sentinel

    function _sentinelTerms() internal view returns (bytes memory) {
        IPulseCosignEnforcer.PulseTerms memory t = _nativeTerms();
        t.sentinel = address(sentinel);
        return _enc(t);
    }

    function test_sentinel_open_ok_closed_laneClosed() public {
        bytes memory terms = _sentinelTerms();
        _autoNative(terms, PAYEE, 0.1 ether);

        sentinel.setClosed(DELEGATOR, true);
        vm.expectRevert(IPulseCosignEnforcer.LaneClosed.selector);
        _autoNative(terms, PAYEE, 0.1 ether);

        // another vault's lane is still open
        enforcer.beforeHook(terms, "", single, _exec(PAYEE, 0.1 ether, ""), DH2, DELEGATOR2, REDEEMER);

        sentinel.setClosed(DELEGATOR, false);
        _autoNative(terms, PAYEE, 0.1 ether);
    }

    function test_sentinel_zero_skipsCheck() public {
        sentinel.setClosed(DELEGATOR, true);
        _autoNative(_enc(_nativeTerms()), PAYEE, 0.1 ether); // terms.sentinel == 0
    }

    function test_sentinel_humanWorksWhileClosed() public {
        bytes memory terms = _sentinelTerms();
        sentinel.setClosed(DELEGATOR, true);
        _cosign(terms, _reqN(PAYEE, 5 ether, "", 1));
        _cosign(terms, _reqN(address(0xC0DE), 0, hex"deadbeef", 2)); // v1.2: its own nonce
    }

    function test_sentinel_order_meterableFirst_thenLane_thenCaps() public {
        bytes memory terms = _sentinelTerms();
        sentinel.setClosed(DELEGATOR, true);
        // unmetered call on a closed lane: HumanRequired (meterable check comes first)
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _auto(terms, _exec(PAYEE, 1, hex"01"));
        // over the per-tx cap on a closed lane: LaneClosed (the lane comes before the caps)
        vm.expectRevert(IPulseCosignEnforcer.LaneClosed.selector);
        _autoNative(terms, PAYEE, 100 ether);
    }

    function test_sentinel_broken_failsClosed() public {
        IPulseCosignEnforcer.PulseTerms memory t = _nativeTerms();
        t.sentinel = address(new RevertingSentinel());
        vm.expectRevert("sentinel down");
        _autoNative(_enc(t), PAYEE, 0.1 ether);

        t.sentinel = address(new GarbageSentinel());
        vm.expectRevert();
        _autoNative(_enc(t), PAYEE, 0.1 ether);

        t.sentinel = address(0x5E47); // no code
        vm.expectRevert();
        _autoNative(_enc(t), PAYEE, 0.1 ether);
    }

    // =================================================================================================== HUMAN

    function test_human_native_ok_recordsEverything() public {
        bytes memory terms = _enc(_nativeTerms());
        Req memory q = _req(PAYEE, 7 ether, ""); // above every AUTO cap
        (bytes memory args, bytes32 digest) = _sign(DEVICE_PK, q);
        assertFalse(enforcer.consumed(address(this), digest));
        assertFalse(enforcer.isKnownPayee(address(this), DH, PAYEE));

        vm.expectEmit(address(enforcer));
        emit PayeeApproved(address(this), DH, PAYEE);
        vm.expectEmit(address(enforcer));
        emit HumanCosigned(DH, DELEGATOR, REDEEMER, address(this), PAYEE, 7 ether, keyId, digest, q.presenceHash);
        _human(terms, q, args);

        assertTrue(enforcer.consumed(address(this), digest));
        assertTrue(enforcer.isKnownPayee(address(this), DH, PAYEE));
        IPulseCosignEnforcer.Approval memory a = enforcer.approvalOf(address(this), digest);
        assertEq(a.keyId, keyId);
        assertEq(a.delegationHash, DH);
        assertEq(a.delegator, DELEGATOR);
        assertEq(a.redeemer, REDEEMER);
        assertEq(a.payee, PAYEE);
        assertEq(a.timestamp, T0);
    }

    function test_human_payeeApproved_onlyOnce() public {
        bytes memory terms = _enc(_nativeTerms());
        _cosign(terms, _req(PAYEE, 1, ""));

        Req memory q = _req(PAYEE, 2, "");
        q.nonce = 2;
        vm.recordLogs();
        bytes32 digest = _cosign(terms, q);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(_countLogs(logs, PayeeApproved.selector), 0, "PayeeApproved only the first time");
        assertEq(_countLogs(logs, HumanCosigned.selector), 1);
        assertEq(enforcer.approvalOf(address(this), digest).payee, PAYEE);
    }

    function test_human_erc20_decodesPayeeAndAmount() public {
        bytes memory terms = _enc(_tokenTerms());

        // transfer: payee = to, amount = amount
        Req memory q = _req(TOKEN, 0, _transfer(PAYEE, 123e6));
        (bytes memory args, bytes32 digest) = _sign(DEVICE_PK, q);
        vm.expectEmit(address(enforcer));
        emit PayeeApproved(address(this), DH, PAYEE);
        vm.expectEmit(address(enforcer));
        emit HumanCosigned(DH, DELEGATOR, REDEEMER, address(this), PAYEE, 123e6, keyId, digest, q.presenceHash);
        _human(terms, q, args);
        assertEq(enforcer.approvalOf(address(this), digest).payee, PAYEE);

        // approve: payee = spender (reported and recorded, but never a known payee: v1.1)
        q = _reqN(TOKEN, 0, _approve(PAYEE2, type(uint256).max), 2); // v1.2: one nonce per co-sign
        (args, digest) = _sign(DEVICE_PK, q);
        vm.recordLogs();
        vm.expectEmit(address(enforcer));
        emit HumanCosigned(
            DH, DELEGATOR, REDEEMER, address(this), PAYEE2, type(uint256).max, keyId, digest, q.presenceHash
        );
        _human(terms, q, args);
        assertEq(_countLogs(vm.getRecordedLogs(), PayeeApproved.selector), 0, "approve never whitelists");
        assertEq(enforcer.approvalOf(address(this), digest).payee, PAYEE2);
        assertFalse(enforcer.isKnownPayee(address(this), DH, PAYEE2));

        // transferFrom: payee = to (not from); never a known payee either
        address to = address(0x7070);
        q = _reqN(TOKEN, 0, _transferFrom(address(0xF00), to, 9), 3);
        (args, digest) = _sign(DEVICE_PK, q);
        vm.recordLogs();
        vm.expectEmit(address(enforcer));
        emit HumanCosigned(DH, DELEGATOR, REDEEMER, address(this), to, 9, keyId, digest, q.presenceHash);
        _human(terms, q, args);
        assertEq(_countLogs(vm.getRecordedLogs(), PayeeApproved.selector), 0, "transferFrom never whitelists");
        assertEq(enforcer.approvalOf(address(this), digest).payee, to);
        assertFalse(enforcer.isKnownPayee(address(this), DH, to));
        assertFalse(enforcer.isKnownPayee(address(this), DH, address(0xF00)));

        // ERC-20 call carrying native value: the event amount is still the decoded amount (and, not meterable, it
        // whitelists nobody: v1.2)
        q = _reqN(TOKEN, 5, _transfer(PAYEE2, 77), 4);
        (args, digest) = _sign(DEVICE_PK, q);
        vm.recordLogs();
        vm.expectEmit(address(enforcer));
        emit HumanCosigned(DH, DELEGATOR, REDEEMER, address(this), PAYEE2, 77, keyId, digest, q.presenceHash);
        _human(terms, q, args);
        assertEq(_countLogs(vm.getRecordedLogs(), PayeeApproved.selector), 0, "transfer with native value");
        assertFalse(enforcer.isKnownPayee(address(this), DH, PAYEE2));
    }

    function test_human_unmetered_payeeZero_amountIsValue() public {
        bytes memory terms = _enc(_nativeTerms());
        bytes memory dirty = _setWordAt(_transfer(PAYEE, 1), 4, (uint256(1) << 160) | uint160(PAYEE));
        bytes memory tf = _transferFrom(address(0xF00), PAYEE, 1);
        bytes[8] memory datas = [
            bytes(hex"deadbeef"),
            dirty, // transfer with a dirty `to` word
            bytes.concat(_transfer(PAYEE, 1), hex"00"), // 69-byte transfer
            _setWordAt(_approve(PAYEE, 1), 4, (uint256(1) << 200) | uint160(PAYEE)), // approve, dirty spender
            _setWordAt(tf, 4, (uint256(1) << 160) | uint160(address(0xF00))), // transferFrom, dirty `from`
            _setWordAt(tf, 36, (uint256(1) << 255) | uint160(PAYEE)), // transferFrom, dirty `to`
            _resize(tf, 99),
            bytes.concat(tf, hex"00")
        ];
        for (uint256 i; i < datas.length; ++i) {
            Req memory q = _reqN(address(0xC0DE), 3 + i, datas[i], 100 + i); // v1.2: one nonce per co-sign
            (bytes memory args, bytes32 digest) = _sign(DEVICE_PK, q);
            vm.recordLogs();
            vm.expectEmit(address(enforcer));
            emit HumanCosigned(DH, DELEGATOR, REDEEMER, address(this), address(0), 3 + i, keyId, digest, q.presenceHash);
            _human(terms, q, args);
            assertEq(_countLogs(vm.getRecordedLogs(), PayeeApproved.selector), 0);
            assertEq(enforcer.approvalOf(address(this), digest).payee, address(0));
            assertTrue(enforcer.consumed(address(this), digest));
        }
        assertFalse(enforcer.isKnownPayee(address(this), DH, PAYEE));
        assertFalse(enforcer.isKnownPayee(address(this), DH, address(0)));
    }

    function test_human_replay_reverts() public {
        bytes memory terms = _enc(_nativeTerms());
        Req memory q = _req(PAYEE, 1 ether, "");
        (bytes memory args,) = _sign(DEVICE_PK, q);
        _human(terms, q, args);
        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
        _human(terms, q, args);
        // single-use per manager (v1.1): another manager has its own replay set, and is single-use there too
        vm.prank(MANAGER_B);
        _human(terms, q, args);
        vm.prank(MANAGER_B);
        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
        _human(terms, q, args);
        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
        _human(terms, q, args);
        // a fresh nonce is a fresh co-sign
        q.nonce = 2;
        (args,) = _sign(DEVICE_PK, q);
        _human(terms, q, args);
    }

    function test_human_expiry() public {
        bytes memory terms = _enc(_nativeTerms());
        Req memory q = _req(PAYEE, 1, "");
        (bytes memory args,) = _sign(DEVICE_PK, q);
        vm.warp(uint256(q.expiry) + 1);
        vm.expectRevert(IPulseCosignEnforcer.CosignExpired.selector);
        _human(terms, q, args);
        vm.warp(q.expiry); // timestamp == expiry is still valid
        _human(terms, q, args);
    }

    function test_human_highS_badCosign() public {
        bytes memory terms = _enc(_nativeTerms());
        Req memory q = _req(PAYEE, 1, "");
        (bytes memory args,) = _sign(DEVICE_PK, q);
        (bytes32 r, bytes32 s) = _rs(args);
        assertTrue(P256.verifySolidity(_digest(q), r, s, px, py));
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _human(terms, q, _args(q, r, p256HighS(s)));
        _human(terms, q, args); // low-s still fine (nothing was consumed)
    }

    function test_human_degenerateSignatures_badCosign() public {
        bytes memory terms = _enc(_nativeTerms());
        Req memory q = _req(PAYEE, 1, "");
        (bytes memory args,) = _sign(DEVICE_PK, q);
        (bytes32 r, bytes32 s) = _rs(args);
        bytes32[2][5] memory sigs =
            [[bytes32(0), bytes32(0)], [r, bytes32(0)], [bytes32(0), s], [bytes32(P256_N), s], [r, bytes32(P256_N)]];
        for (uint256 i; i < sigs.length; ++i) {
            vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
            _human(terms, q, _args(q, sigs[i][0], sigs[i][1]));
        }
    }

    /// @dev Returns a copy of `q` with signed field `field` (0..8) changed to a different, still-valid value.
    function _mutate(Req memory q, uint256 field, uint256 salt) internal view returns (Req memory m) {
        m = _copy(q);
        uint256 x = salt | 1;
        // forge-lint: disable-start(unsafe-typecast)
        if (field == 0) m.delegationHash = q.delegationHash ^ bytes32(x);
        else if (field == 1) m.delegator = address(uint160(q.delegator) ^ uint160(x));
        else if (field == 2) m.redeemer = address(uint160(q.redeemer) ^ uint160(x));
        else if (field == 3) m.target = address(uint160(q.target) ^ uint160(x));
        else if (field == 4) m.value = q.value ^ x;
        else if (field == 5) m.callData = q.callData.length == 0 ? bytes(hex"00") : bytes.concat(q.callData, hex"00");
        else if (field == 6) m.nonce = q.nonce ^ x;
        else if (field == 7) m.expiry = q.expiry > block.timestamp ? q.expiry - 1 : q.expiry + 1;
        else m.presenceHash = q.presenceHash ^ bytes32(x);
        // forge-lint: disable-end(unsafe-typecast)
    }

    function test_human_eachSignedFieldMutated_badCosign() public {
        bytes memory terms = _enc(_nativeTerms());
        Req memory q = _req(TOKEN, 0, _transfer(PAYEE, 10e6));
        (bytes memory args,) = _sign(DEVICE_PK, q);
        (bytes32 r, bytes32 s) = _rs(args);
        for (uint256 field; field < 9; ++field) {
            Req memory m = _mutate(q, field, 0x40);
            vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
            _human(terms, m, _args(m, r, s));
        }
        _human(terms, q, args); // the untouched request passes
    }

    function test_human_wrongKey_badCosign() public {
        Req memory q = _req(PAYEE, 1, "");
        // signed by another device than the one in the terms
        (bytes memory args,) = _sign(OTHER_PK, q);
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _human(_enc(_nativeTerms()), q, args);

        // terms naming another device, signed by ours
        IPulseCosignEnforcer.PulseTerms memory t = _nativeTerms();
        (t.px, t.py) = (otherPx, otherPy);
        (args,) = _sign(DEVICE_PK, q);
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _human(_enc(t), q, args);

        // invalid public keys
        (t.px, t.py) = (bytes32(0), bytes32(0));
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _human(_enc(t), q, args);
        (t.px, t.py) = (px, bytes32(uint256(py) ^ 1)); // off the curve
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _human(_enc(t), q, args);
        // (x, -y) is on the curve but another key
        (t.px, t.py) = (px, bytes32(P256.P - uint256(py)));
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _human(_enc(t), q, args);
    }

    function test_human_signatureBoundToEnforcerAndChain() public {
        bytes memory terms = _enc(_nativeTerms());
        Req memory q = _req(PAYEE, 1, "");
        (bytes memory args,) = _sign(DEVICE_PK, q);

        // the same co-sign on another enforcer deployment
        PulseCosignEnforcer other = new PulseCosignEnforcer();
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        other.beforeHook(terms, args, single, _exec(PAYEE, 1, ""), DH, DELEGATOR, REDEEMER);

        // on another chain
        uint256 chainId = block.chainid;
        vm.chainId(143);
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _human(terms, q, args);
        vm.chainId(chainId);
        _human(terms, q, args);
    }

    function test_human_differentManager_worksWithOwnState() public {
        IPulseCosignEnforcer.PulseTerms memory t = _nativeTerms();
        t.newPayeeNeedsHuman = true;
        bytes memory terms = _enc(t);

        _cosign(terms, _req(PAYEE, 1, "")); // manager A = this
        assertTrue(enforcer.isKnownPayee(address(this), DH, PAYEE));
        assertFalse(enforcer.isKnownPayee(MANAGER_B, DH, PAYEE));

        // manager B cannot AUTO-pay PAYEE yet
        vm.prank(MANAGER_B);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        enforcer.beforeHook(terms, "", single, _exec(PAYEE, 1, ""), DH, DELEGATOR, REDEEMER);

        // a fresh co-sign through manager B works and approves PAYEE for B
        Req memory q = _req(PAYEE, 2, "");
        q.nonce = 2;
        (bytes memory args, bytes32 digest) = _sign(DEVICE_PK, q);
        vm.expectEmit(address(enforcer));
        emit PayeeApproved(MANAGER_B, DH, PAYEE);
        vm.prank(MANAGER_B);
        _human(terms, q, args);
        assertTrue(enforcer.consumed(MANAGER_B, digest));
        assertFalse(enforcer.consumed(address(this), digest), "consumed per manager");
        assertEq(enforcer.approvalOf(MANAGER_B, digest).redeemer, REDEEMER);
        assertEq(enforcer.approvalOf(address(this), digest).keyId, bytes32(0));
        assertTrue(enforcer.isKnownPayee(MANAGER_B, DH, PAYEE));

        vm.prank(MANAGER_B);
        enforcer.beforeHook(terms, "", single, _exec(PAYEE, 0.5 ether, ""), DH, DELEGATOR, REDEEMER);
        (uint256 spentB,) = enforcer.periodSpent(MANAGER_B, DH);
        (uint256 spentA,) = enforcer.periodSpent(address(this), DH);
        assertEq(spentB, 0.5 ether);
        assertEq(spentA, 0);
    }

    function test_human_doesNotTouchPeriod() public {
        bytes memory terms = _enc(_nativeTerms());
        _autoNative(terms, PAYEE, 1 ether);
        vm.warp(T0 + 5);
        _cosign(terms, _req(PAYEE, 50 ether, ""));
        (uint256 spent, uint64 start) = enforcer.periodSpent(address(this), DH);
        assertEq(spent, 1 ether);
        assertEq(start, T0);

        // a HUMAN spend before any AUTO spend does not start a period either
        Req memory q = _req(PAYEE, 2 ether, "");
        q.delegationHash = DH2;
        _cosign(terms, q);
        (spent, start) = enforcer.periodSpent(address(this), DH2);
        assertEq(spent, 0);
        assertEq(start, 0);
    }

    function test_human_anyCallAllowed_underTokenTerms() public {
        bytes memory terms = _enc(_tokenTerms());
        vm.recordLogs();
        _cosign(terms, _reqN(PAYEE, 1 ether, "", 1)); // native send under ERC-20 terms
        _cosign(terms, _reqN(address(0xBAD), 0, _transfer(PAYEE2, 1e30), 2)); // other token
        _cosign(terms, _reqN(address(0xC0DE), 0, hex"", 3)); // zero-value call
        // allowed, but none of them is meterable under the mUSD-style terms, so none whitelists (v1.2)
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(_countLogs(logs, HumanCosigned.selector), 3);
        assertEq(_countLogs(logs, PayeeApproved.selector), 0);
        assertFalse(enforcer.isKnownPayee(address(this), DH, PAYEE));
        assertFalse(enforcer.isKnownPayee(address(this), DH, PAYEE2));
        assertFalse(enforcer.isKnownPayee(address(this), DH, address(0xC0DE)));
    }

    // =================================================================================================== revoke

    function test_revoke_valid_idempotent() public {
        (bytes32 r, bytes32 s) = p256Sign(DEVICE_PK, _revokeDigest(DH));
        vm.expectEmit(address(enforcer));
        emit Revoked(keyId, DH);
        vm.prank(address(0xA11)); // anyone may relay
        enforcer.revoke(px, py, DH, r, s);
        assertTrue(enforcer.isRevoked(keyId, DH));

        vm.recordLogs();
        enforcer.revoke(px, py, DH, r, s);
        assertEq(vm.getRecordedLogs().length, 0, "event only the first time");
        assertTrue(enforcer.isRevoked(keyId, DH));
    }

    function test_revoke_badSignature() public {
        (bytes32 r, bytes32 s) = p256Sign(DEVICE_PK, _revokeDigest(DH));
        vm.expectRevert(IPulseCosignEnforcer.BadSignature.selector);
        enforcer.revoke(px, py, DH2, r, s); // signed another delegation
        vm.expectRevert(IPulseCosignEnforcer.BadSignature.selector);
        enforcer.revoke(otherPx, otherPy, DH, r, s); // another key
        vm.expectRevert(IPulseCosignEnforcer.BadSignature.selector);
        enforcer.revoke(px, py, DH, r, p256HighS(s)); // high-s
        vm.expectRevert(IPulseCosignEnforcer.BadSignature.selector);
        enforcer.revoke(px, py, DH, bytes32(0), bytes32(0));
        (r, s) = p256Sign(DEVICE_PK, _panicDigest(1)); // a panic signature is not a revoke
        vm.expectRevert(IPulseCosignEnforcer.BadSignature.selector);
        enforcer.revoke(px, py, DH, r, s);
        assertFalse(enforcer.isRevoked(keyId, DH));
    }

    function test_revoke_blocksBothPaths_only_thatDelegation_thatKey() public {
        bytes memory terms = _enc(_nativeTerms());
        Req memory q = _req(PAYEE, 1, "");
        (bytes memory args,) = _sign(DEVICE_PK, q);

        _revokeAs(DEVICE_PK, DH);

        vm.expectRevert(IPulseCosignEnforcer.DelegationRevoked.selector);
        _autoNative(terms, PAYEE, 1);
        vm.expectRevert(IPulseCosignEnforcer.DelegationRevoked.selector);
        _human(terms, q, args);
        // revocation is checked before the args length
        vm.expectRevert(IPulseCosignEnforcer.DelegationRevoked.selector);
        enforcer.beforeHook(terms, hex"01", single, _exec(PAYEE, 1, ""), DH, DELEGATOR, REDEEMER);

        // other delegations of the same key are unaffected
        enforcer.beforeHook(terms, "", single, _exec(PAYEE, 1, ""), DH2, DELEGATOR, REDEEMER);

        // the same delegation hash under another device key is unaffected
        IPulseCosignEnforcer.PulseTerms memory t = _nativeTerms();
        (t.px, t.py) = (otherPx, otherPy);
        _autoNative(_enc(t), PAYEE, 1);
        assertFalse(enforcer.isRevoked(p256KeyId(otherPx, otherPy), DH));
    }

    // =================================================================================================== panic

    function test_panic_killsOlderEpochs() public {
        IPulseCosignEnforcer.PulseTerms memory t = _nativeTerms();
        bytes memory epoch0 = _enc(t);
        t.epoch = 1;
        bytes memory epoch1 = _enc(t);
        t.epoch = 2;
        bytes memory epoch2 = _enc(t);

        Req memory q = _req(PAYEE, 1, "");
        (bytes memory args,) = _sign(DEVICE_PK, q);

        (bytes32 r, bytes32 s) = p256Sign(DEVICE_PK, _panicDigest(1));
        vm.expectEmit(address(enforcer));
        emit Panicked(keyId, 1);
        vm.prank(address(0xA11));
        enforcer.panic(px, py, 1, r, s);
        assertEq(enforcer.minEpoch(keyId), 1);

        vm.expectRevert(IPulseCosignEnforcer.StaleEpoch.selector);
        _autoNative(epoch0, PAYEE, 1);
        vm.expectRevert(IPulseCosignEnforcer.StaleEpoch.selector);
        _human(epoch0, q, args);

        _autoNative(epoch1, PAYEE, 1); // == minEpoch ok
        _human(epoch1, q, args);
        _autoNative(epoch2, PAYEE, 1); // > minEpoch ok

        // other keys are unaffected
        (t.px, t.py, t.epoch) = (otherPx, otherPy, 0);
        _autoNative(_enc(t), PAYEE, 1);
        assertEq(enforcer.minEpoch(p256KeyId(otherPx, otherPy)), 0);
    }

    function test_panic_epochMustIncrease() public {
        (bytes32 r0, bytes32 s0) = p256Sign(DEVICE_PK, _panicDigest(0));
        vm.expectRevert(IPulseCosignEnforcer.EpochNotIncreasing.selector);
        enforcer.panic(px, py, 0, r0, s0);

        _panicAs(DEVICE_PK, 5); // may skip epochs
        assertEq(enforcer.minEpoch(keyId), 5);

        (bytes32 r, bytes32 s) = p256Sign(DEVICE_PK, _panicDigest(5));
        vm.expectRevert(IPulseCosignEnforcer.EpochNotIncreasing.selector);
        enforcer.panic(px, py, 5, r, s); // replay of the same panic
        (r, s) = p256Sign(DEVICE_PK, _panicDigest(3));
        vm.expectRevert(IPulseCosignEnforcer.EpochNotIncreasing.selector);
        enforcer.panic(px, py, 3, r, s);
        // the epoch check comes before the signature check
        vm.expectRevert(IPulseCosignEnforcer.EpochNotIncreasing.selector);
        enforcer.panic(px, py, 4, bytes32(0), bytes32(0));

        _panicAs(DEVICE_PK, 6);
        _panicAs(DEVICE_PK, type(uint64).max);
        vm.expectRevert(IPulseCosignEnforcer.EpochNotIncreasing.selector);
        enforcer.panic(px, py, type(uint64).max, r, s);
    }

    function test_panic_badSignature() public {
        (bytes32 r, bytes32 s) = p256Sign(DEVICE_PK, _panicDigest(2));
        vm.expectRevert(IPulseCosignEnforcer.BadSignature.selector);
        enforcer.panic(px, py, 3, r, s); // signed another epoch
        vm.expectRevert(IPulseCosignEnforcer.BadSignature.selector);
        enforcer.panic(otherPx, otherPy, 2, r, s); // another key
        vm.expectRevert(IPulseCosignEnforcer.BadSignature.selector);
        enforcer.panic(px, py, 2, r, p256HighS(s));
        (r, s) = p256Sign(DEVICE_PK, _revokeDigest(bytes32(uint256(2)))); // a revoke is not a panic
        vm.expectRevert(IPulseCosignEnforcer.BadSignature.selector);
        enforcer.panic(px, py, 2, r, s);
        assertEq(enforcer.minEpoch(keyId), 0);
    }

    // =================================================================================================== digests

    function test_typehashes() public view {
        assertEq(enforcer.HUMAN_APPROVAL_TYPEHASH(), HUMAN_APPROVAL_TYPEHASH_STR);
        assertEq(enforcer.REVOKE_TYPEHASH(), keccak256("Revoke(bytes32 delegationHash)"));
        assertEq(enforcer.PANIC_TYPEHASH(), keccak256("Panic(uint64 minEpoch)"));
    }

    function test_domainSeparator_handRolled() public {
        assertEq(enforcer.domainSeparator(), _domainSeparatorFor(block.chainid, address(enforcer)));
        (, string memory name, string memory version, uint256 chainId, address verifyingContract,,) =
            enforcer.eip712Domain();
        assertEq(name, "RiparPulseCosign");
        assertEq(version, "1");
        assertEq(chainId, block.chainid);
        assertEq(verifyingContract, address(enforcer));

        vm.chainId(10_143); // Monad testnet
        assertEq(enforcer.domainSeparator(), _domainSeparatorFor(10_143, address(enforcer)));
        vm.chainId(143); // Monad mainnet
        assertEq(enforcer.domainSeparator(), _domainSeparatorFor(143, address(enforcer)));
    }

    function testFuzz_approvalHashes_handRolled(
        bytes32 delegationHash,
        address delegator,
        address redeemer,
        address target,
        uint256 value,
        bytes memory callData,
        uint256 nonce,
        uint64 expiry,
        bytes32 presenceHash
    ) public view {
        Req memory q = Req({
            delegationHash: delegationHash,
            delegator: delegator,
            redeemer: redeemer,
            target: target,
            value: value,
            callData: callData,
            nonce: nonce,
            expiry: expiry,
            presenceHash: presenceHash
        });
        bytes32 hand = keccak256(
            bytes.concat(
                abi.encode(HUMAN_APPROVAL_TYPEHASH_STR, delegationHash, delegator, redeemer, target),
                abi.encode(value, keccak256(callData), nonce, expiry, presenceHash)
            )
        );
        bytes32 structHash = enforcer.approvalStructHash(
            delegationHash, delegator, redeemer, target, value, keccak256(callData), nonce, expiry, presenceHash
        );
        assertEq(structHash, hand);
        assertEq(structHash, _structHash(q));
        bytes32 digest = enforcer.approvalDigest(
            delegationHash, delegator, redeemer, target, value, keccak256(callData), nonce, expiry, presenceHash
        );
        assertEq(digest, keccak256(abi.encodePacked(hex"1901", enforcer.domainSeparator(), hand)));
        assertEq(digest, _digest(q));
    }

    function test_requestHash_isStructHashWithZeroPresence() public view {
        Req memory q = _req(TOKEN, 0, _transfer(PAYEE, 1e6));
        q.presenceHash = bytes32(0);
        bytes32 requestHash = enforcer.approvalStructHash(
            q.delegationHash, q.delegator, q.redeemer, q.target, q.value, keccak256(q.callData), q.nonce, q.expiry, 0
        );
        assertEq(requestHash, _structHash(q));
    }

    function testFuzz_revokeAndPanicDigests_handRolled(bytes32 delegationHash, uint64 epoch) public view {
        assertEq(enforcer.revokeDigest(delegationHash), _revokeDigest(delegationHash));
        assertEq(enforcer.panicDigest(epoch), _panicDigest(epoch));
    }

    function testFuzz_keyIdOf(bytes32 x, bytes32 y) public view {
        assertEq(enforcer.keyIdOf(x, y), keccak256(abi.encode(x, y)));
    }

    /// @notice Known-answer vectors from the firmware's independent Python reference
    ///         (firmware/test/host/vectors_eip712_abi.h, generated by firmware/tools/ref_eip712.py).
    function test_firmwareVectors_humanApproval() public {
        FirmwareVectors.HumanApprovalVector[] memory vs = FirmwareVectors.humanApprovals();
        assertGt(vs.length, 0);
        for (uint256 i; i < vs.length; ++i) {
            FirmwareVectors.HumanApprovalVector memory v = vs[i];
            _atChainAndAddress(v.chainId, v.enforcer);
            PulseCosignEnforcer at = PulseCosignEnforcer(v.enforcer);
            assertEq(
                at.approvalStructHash(
                    v.delegationHash,
                    v.delegator,
                    v.redeemer,
                    v.target,
                    v.value,
                    v.callDataHash,
                    v.nonce,
                    v.expiry,
                    v.presenceHash
                ),
                v.structHash,
                "structHash"
            );
            assertEq(
                at.approvalDigest(
                    v.delegationHash,
                    v.delegator,
                    v.redeemer,
                    v.target,
                    v.value,
                    v.callDataHash,
                    v.nonce,
                    v.expiry,
                    v.presenceHash
                ),
                v.digest,
                "digest"
            );
        }
    }

    function test_firmwareVectors_revokePanicDomain() public {
        FirmwareVectors.RevokeVector[] memory rs = FirmwareVectors.revokes();
        for (uint256 i; i < rs.length; ++i) {
            _atChainAndAddress(rs[i].chainId, rs[i].enforcer);
            assertEq(PulseCosignEnforcer(rs[i].enforcer).revokeDigest(rs[i].delegationHash), rs[i].digest, "revoke");
        }
        FirmwareVectors.PanicVector[] memory ps = FirmwareVectors.panics();
        for (uint256 i; i < ps.length; ++i) {
            _atChainAndAddress(ps[i].chainId, ps[i].enforcer);
            assertEq(PulseCosignEnforcer(ps[i].enforcer).panicDigest(ps[i].minEpoch), ps[i].digest, "panic");
        }
        FirmwareVectors.DomainVector memory d = FirmwareVectors.domain();
        _atChainAndAddress(d.chainId, d.enforcer);
        assertEq(PulseCosignEnforcer(d.enforcer).domainSeparator(), d.separator, "domain");
    }

    /// @dev Puts the enforcer's runtime code at `where` and switches to `chainId` (OZ EIP712 rebuilds the domain
    ///      separator for the current address and chain).
    function _atChainAndAddress(uint256 chainId, address where) internal {
        vm.chainId(chainId);
        vm.etch(where, address(enforcer).code);
    }

    // =================================================================================================== fuzz

    /// @dev Reference model of the AUTO period accounting, plus the log of accepted spends.
    struct Model {
        uint32 period;
        uint128 perTx;
        uint128 cap;
        uint256 start;
        uint256 spent;
        uint256 first; // time of the first accepted spend = origin of the aligned windows
        uint256 n;
        uint256[24] windowOf;
        uint256[24] amountOf;
    }

    /// @notice AUTO spends never exceed periodAutoCap inside one aligned period, and the enforcer accepts a spend
    ///         exactly when the reference model says it fits.
    function testFuzz_auto_neverExceedsPeriodCap(uint256 seed, uint32 period, uint128 perTx, uint128 cap) public {
        Model memory m;
        m.period = uint32(bound(period, 0, 30 days));
        m.perTx = uint128(bound(perTx, 1, 1e24));
        m.cap = uint128(bound(cap, 0, 5e24));
        IPulseCosignEnforcer.PulseTerms memory t = _nativeTerms();
        (t.period, t.perTxAutoCap, t.periodAutoCap) = (m.period, m.perTx, m.cap);
        bytes memory terms = _enc(t);

        for (uint256 i; i < 24; ++i) {
            _modelStep(m, terms, uint256(keccak256(abi.encode(seed, i))));
        }
        // independent check: the sum of accepted spends per aligned window never exceeds the cap
        for (uint256 i; i < m.n; ++i) {
            uint256 sum;
            for (uint256 j; j < m.n; ++j) {
                if (m.windowOf[j] == m.windowOf[i]) sum += m.amountOf[j];
            }
            assertLe(sum, m.cap, "window over cap");
        }
    }

    function _modelStep(Model memory m, bytes memory terms, uint256 r) internal {
        uint256 span = m.period == 0 ? 30 days : 2 * uint256(m.period);
        vm.warp(block.timestamp + (r % (span + 1)) * ((r >> 250) % 2)); // half the steps stay in place
        uint256 amount = (r >> 16) % (uint256(m.perTx) + m.perTx / 4 + 2);

        uint256 nStart = m.start;
        uint256 nSpent = m.spent;
        if (nStart == 0) {
            nStart = block.timestamp;
        } else if (m.period != 0 && block.timestamp >= nStart + m.period) {
            // forge-lint: disable-next-line(divide-before-multiply)
            nStart += ((block.timestamp - nStart) / m.period) * m.period;
            nSpent = 0;
        }
        bool fits = amount > 0 && amount <= m.perTx && nSpent + amount <= m.cap;

        // v1.1: autoBudget applies the same rollover as the model, and predicts the period check exactly
        (uint256 bSpent, uint256 bRemaining, uint64 bStart, uint64 bEnd) = enforcer.autoBudget(address(this), DH, terms);
        assertEq(bSpent, m.start == 0 ? 0 : nSpent, "budget spent");
        assertEq(bRemaining, m.cap - bSpent, "budget remaining");
        assertEq(bStart, m.start == 0 ? 0 : nStart, "budget periodStart");
        assertEq(bEnd, (m.start == 0 || m.period == 0) ? 0 : nStart + m.period, "budget periodEnd");
        assertEq(fits, amount > 0 && amount <= m.perTx && amount <= bRemaining, "budget predicts the period check");

        try enforcer.beforeHook(terms, "", single, _exec(PAYEE, amount, ""), DH, DELEGATOR, REDEEMER) {
            assertTrue(fits, "accepted a spend the model rejects");
            if (m.n == 0) m.first = block.timestamp;
            m.windowOf[m.n] = m.period == 0 ? 0 : (block.timestamp - m.first) / m.period;
            m.amountOf[m.n] = amount;
            ++m.n;
            (m.start, m.spent) = (nStart, nSpent + amount);
        } catch (bytes memory err) {
            assertFalse(fits, "rejected a spend the model accepts");
            // forge-lint: disable-next-line(unsafe-typecast)
            assertEq(bytes4(err), IPulseCosignEnforcer.HumanRequired.selector);
        }
        (uint256 spent, uint64 start) = enforcer.periodSpent(address(this), DH);
        assertEq(spent, m.spent);
        assertEq(start, m.start);
        assertLe(spent, m.cap);
    }

    /// @notice Random HUMAN args (nonce, expiry, presenceHash, r, s) never pass without the device's signature.
    function testFuzz_human_unsignedArgsNeverPass(
        uint256 nonce,
        uint64 expiry,
        bytes32 presenceHash,
        bytes32 r,
        bytes32 s,
        address target,
        uint256 value,
        bytes memory callData
    ) public {
        expiry = uint64(bound(expiry, block.timestamp, type(uint64).max));
        bytes memory args = abi.encode(nonce, expiry, presenceHash, r, s);
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        enforcer.beforeHook(_enc(_nativeTerms()), args, single, _exec(target, value, callData), DH, DELEGATOR, REDEEMER);
    }

    /// @notice A real device signature never authorises a request that differs in any signed field.
    function testFuzz_human_mutatedRequestNeverPasses(
        uint8 field,
        uint256 salt,
        address target,
        uint256 value,
        bytes memory callData,
        uint256 nonce,
        bytes32 presenceHash
    ) public {
        Req memory q = _req(target, value, callData);
        (q.nonce, q.presenceHash) = (nonce, presenceHash);
        (bytes memory args,) = _sign(DEVICE_PK, q);
        (bytes32 r, bytes32 s) = _rs(args);
        Req memory m = _mutate(q, field % 9, salt);
        bytes memory terms = _enc(_nativeTerms());
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _human(terms, m, _args(m, r, s));
        _human(terms, q, args);
    }

    /// @notice A valid device signature never passes under terms naming a different (random) key.
    function testFuzz_human_randomTermsKeyNeverPasses(bytes32 x, bytes32 y) public {
        vm.assume(x != px || y != py);
        Req memory q = _req(PAYEE, 1, "");
        (bytes memory args,) = _sign(DEVICE_PK, q);
        IPulseCosignEnforcer.PulseTerms memory t = _nativeTerms();
        (t.px, t.py) = (x, y);
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _human(_enc(t), q, args);
    }

    /// @notice Approval packing (4 slots, redeemer split across two words) round-trips every address and time.
    function testFuzz_approvalOf_packing(address delegator, address redeemer, address payee, uint32 when) public {
        vm.warp(bound(when, 1, type(uint32).max - 2 hours));
        Req memory q = _req(payee, 1, "");
        (q.delegator, q.redeemer) = (delegator, redeemer);
        bytes32 digest = _cosign(_enc(_nativeTerms()), q);
        IPulseCosignEnforcer.Approval memory a = enforcer.approvalOf(address(this), digest);
        assertEq(a.keyId, keyId);
        assertEq(a.delegationHash, DH);
        assertEq(a.delegator, delegator);
        assertEq(a.redeemer, redeemer);
        assertEq(a.payee, payee);
        assertEq(a.timestamp, block.timestamp);
        assertTrue(enforcer.consumed(address(this), digest));
        assertEq(enforcer.isKnownPayee(address(this), DH, payee), payee != address(0));
    }

    function test_approvalOf_unknownDigest_isZero() public view {
        IPulseCosignEnforcer.Approval memory a = enforcer.approvalOf(address(this), keccak256("nope"));
        assertEq(a.keyId, bytes32(0));
        assertEq(a.delegationHash, bytes32(0));
        assertEq(a.delegator, address(0));
        assertEq(a.redeemer, address(0));
        assertEq(a.payee, address(0));
        assertEq(a.timestamp, 0);
        assertFalse(enforcer.consumed(address(this), keccak256("nope")));
    }

    // =================================================================================================== v1.1 #1 replay per manager

    /// @notice (v1.1 #1) Whoever sees a pending HUMAN redemption and calls beforeHook directly with its caveat args
    ///         only consumes them for its own address: the real DelegationManager's redemption still goes through, and
    ///         the direct call leaves no record under the manager (so the relay, which reads the canonical manager's
    ///         records only, has nothing to credit) and no known payee.
    function test_frontRun_directBeforeHook_doesNotBurnManagersCosign() public {
        IPulseCosignEnforcer.PulseTerms memory t = _nativeTerms();
        t.newPayeeNeedsHuman = true;
        bytes memory terms = _enc(t);
        Req memory q = _req(PAYEE, 2 ether, "");
        (bytes memory args, bytes32 digest) = _sign(DEVICE_PK, q);

        // the front-runner replays the exact caveat args of the pending redemption
        vm.expectEmit(address(enforcer));
        emit PayeeApproved(ATTACKER, DH, PAYEE);
        vm.expectEmit(address(enforcer));
        emit HumanCosigned(DH, DELEGATOR, REDEEMER, ATTACKER, PAYEE, 2 ether, keyId, digest, q.presenceHash);
        vm.prank(ATTACKER);
        _human(terms, q, args);
        assertTrue(enforcer.consumed(ATTACKER, digest));
        assertEq(enforcer.approvalOf(ATTACKER, digest).redeemer, REDEEMER);

        // the manager's state is untouched
        assertFalse(enforcer.consumed(address(this), digest));
        IPulseCosignEnforcer.Approval memory none = enforcer.approvalOf(address(this), digest);
        assertEq(none.keyId, bytes32(0));
        assertEq(none.redeemer, address(0));
        assertFalse(enforcer.isKnownPayee(address(this), DH, PAYEE));
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoNative(terms, PAYEE, 0.1 ether);

        // the real redemption does not revert CosignReplayed
        vm.warp(T0 + 12);
        vm.expectEmit(address(enforcer));
        emit PayeeApproved(address(this), DH, PAYEE);
        vm.expectEmit(address(enforcer));
        emit HumanCosigned(DH, DELEGATOR, REDEEMER, address(this), PAYEE, 2 ether, keyId, digest, q.presenceHash);
        _human(terms, q, args);
        assertTrue(enforcer.consumed(address(this), digest));
        IPulseCosignEnforcer.Approval memory a = enforcer.approvalOf(address(this), digest);
        assertEq(a.keyId, keyId);
        assertEq(a.delegationHash, DH);
        assertEq(a.delegator, DELEGATOR);
        assertEq(a.redeemer, REDEEMER);
        assertEq(a.payee, PAYEE);
        assertEq(a.timestamp, T0 + 12);
        assertEq(enforcer.approvalOf(ATTACKER, digest).timestamp, T0, "each manager keeps its own record");
        _autoNative(terms, PAYEE, 0.1 ether); // PAYEE is now known for the real manager

        // and the co-sign stays single-use for each of them
        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
        _human(terms, q, args);
        vm.prank(ATTACKER);
        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
        _human(terms, q, args);
    }

    /// @notice A direct call after the real redemption cannot overwrite the manager's record either.
    function test_directBeforeHook_afterRedemption_leavesManagersRecord() public {
        bytes memory terms = _enc(_tokenTerms());
        Req memory q = _req(TOKEN, 0, _transfer(PAYEE, 7e6));
        (bytes memory args, bytes32 digest) = _sign(DEVICE_PK, q);
        _human(terms, q, args);

        vm.warp(T0 + 99);
        vm.prank(ATTACKER);
        _human(terms, q, args);

        IPulseCosignEnforcer.Approval memory a = enforcer.approvalOf(address(this), digest);
        assertEq(a.timestamp, T0);
        assertEq(a.payee, PAYEE);
        assertEq(enforcer.approvalOf(ATTACKER, digest).timestamp, T0 + 99);
        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
        _human(terms, q, args);
    }

    /// @notice Any third party that calls beforeHook first with a pending co-sign's args leaves the real manager's
    ///         redemption working.
    function testFuzz_frontRun_anyCallerOnlyConsumesForItself(address caller, uint256 value) public {
        vm.assume(caller != address(this));
        bytes memory terms = _enc(_nativeTerms());
        Req memory q = _req(PAYEE, value, "");
        (bytes memory args, bytes32 digest) = _sign(DEVICE_PK, q);

        vm.prank(caller);
        _human(terms, q, args);
        assertTrue(enforcer.consumed(caller, digest));
        assertTrue(enforcer.nonceUsed(caller, DH, q.nonce));
        assertFalse(enforcer.consumed(address(this), digest));
        assertFalse(enforcer.nonceUsed(address(this), DH, q.nonce), "the nonce is not burnt for the manager");
        assertFalse(enforcer.isKnownPayee(address(this), DH, PAYEE));

        _human(terms, q, args); // no CosignReplayed for the real manager
        assertTrue(enforcer.consumed(address(this), digest));
        assertTrue(enforcer.nonceUsed(address(this), DH, q.nonce));
        // v1.2: a native send whitelists only when it moves a non-zero value
        assertEq(enforcer.isKnownPayee(address(this), DH, PAYEE), value != 0);
    }

    // =================================================================================================== v1.1 #2 payees per mandate

    /// @notice (v1.1 #2) After a revoke, a fresh mandate (new delegationHash, same delegator, device and terms) cannot
    ///         AUTO-pay the payees a human approved under the old one.
    function test_freshMandate_afterRevoke_cannotAutoPayOldPayees() public {
        IPulseCosignEnforcer.PulseTerms memory t = _nativeTerms();
        t.newPayeeNeedsHuman = true;
        bytes memory terms = _enc(t);

        _cosign(terms, _req(PAYEE, 0.01 ether, ""));
        Req memory q = _req(PAYEE2, 0.01 ether, "");
        q.nonce = 2;
        _cosign(terms, q);
        _autoNative(terms, PAYEE, 0.1 ether);
        _autoNative(terms, PAYEE2, 0.1 ether);

        _revokeAs(DEVICE_PK, DH);
        vm.expectRevert(IPulseCosignEnforcer.DelegationRevoked.selector);
        _autoNative(terms, PAYEE, 0.1 ether);

        // the fresh mandate starts with an empty payee list
        assertFalse(enforcer.isKnownPayee(address(this), DH2, PAYEE));
        assertFalse(enforcer.isKnownPayee(address(this), DH2, PAYEE2));
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        enforcer.beforeHook(terms, "", single, _exec(PAYEE, 0.1 ether, ""), DH2, DELEGATOR, REDEEMER);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        enforcer.beforeHook(terms, "", single, _exec(PAYEE2, 0.1 ether, ""), DH2, DELEGATOR, REDEEMER);

        // it needs its own co-sign, which approves the payee for the new mandate only
        q = _req(PAYEE, 0.01 ether, "");
        (q.delegationHash, q.nonce) = (DH2, 3);
        vm.expectEmit(address(enforcer));
        emit PayeeApproved(address(this), DH2, PAYEE);
        _cosign(terms, q);
        enforcer.beforeHook(terms, "", single, _exec(PAYEE, 0.1 ether, ""), DH2, DELEGATOR, REDEEMER);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        enforcer.beforeHook(terms, "", single, _exec(PAYEE2, 0.1 ether, ""), DH2, DELEGATOR, REDEEMER);
    }

    /// @notice (v1.1 #2) The same after a panic: the mandate re-signed at the new epoch starts without payees.
    function test_freshMandate_afterPanic_cannotAutoPayOldPayees() public {
        IPulseCosignEnforcer.PulseTerms memory t = _tokenTerms();
        t.newPayeeNeedsHuman = true;
        bytes memory oldTerms = _enc(t);
        _cosign(oldTerms, _req(TOKEN, 0, _transfer(PAYEE, 1e6)));
        _auto(oldTerms, _exec(TOKEN, 0, _transfer(PAYEE, 5e6)));

        _panicAs(DEVICE_PK, 1);
        vm.expectRevert(IPulseCosignEnforcer.StaleEpoch.selector);
        _auto(oldTerms, _exec(TOKEN, 0, _transfer(PAYEE, 5e6)));

        t.epoch = 1;
        bytes memory newTerms = _enc(t);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        enforcer.beforeHook(newTerms, "", single, _exec(TOKEN, 0, _transfer(PAYEE, 5e6)), DH2, DELEGATOR, REDEEMER);
        assertFalse(enforcer.isKnownPayee(address(this), DH2, PAYEE));
        assertTrue(enforcer.isKnownPayee(address(this), DH, PAYEE), "the old list dies with the old mandate");
    }

    // =================================================================================================== v1.1 #3 who becomes a payee

    /// @notice (v1.1 #3) A human-signed `approve` or `transferFrom` never makes its spender / recipient (or `from`) an
    ///         AUTO payee; a human-signed `transfer` to the same address does.
    function test_human_approveAndTransferFrom_neverWhitelist() public {
        IPulseCosignEnforcer.PulseTerms memory t = _tokenTerms();
        t.newPayeeNeedsHuman = true;
        bytes memory terms = _enc(t);

        bytes[3] memory datas =
            [_approve(PAYEE, 1e6), _transferFrom(DELEGATOR, PAYEE, 1e6), _transferFrom(PAYEE2, PAYEE, 1e6)];
        for (uint256 i; i < datas.length; ++i) {
            Req memory q = _req(TOKEN, 0, datas[i]);
            q.nonce = 10 + i;
            vm.recordLogs();
            bytes32 digest = _cosign(terms, q);
            assertEq(_countLogs(vm.getRecordedLogs(), PayeeApproved.selector), 0);
            assertEq(enforcer.approvalOf(address(this), digest).payee, PAYEE, "the record keeps the decoded payee");
        }
        assertFalse(enforcer.isKnownPayee(address(this), DH, PAYEE));
        assertFalse(enforcer.isKnownPayee(address(this), DH, PAYEE2));
        assertFalse(enforcer.isKnownPayee(address(this), DH, DELEGATOR));
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _auto(terms, _exec(TOKEN, 0, _transfer(PAYEE, 1e6)));
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _auto(terms, _exec(TOKEN, 0, _transfer(PAYEE2, 1e6)));

        // a human `transfer` to PAYEE does make it known
        vm.expectEmit(address(enforcer));
        emit PayeeApproved(address(this), DH, PAYEE);
        _cosign(terms, _req(TOKEN, 0, _transfer(PAYEE, 1e6)));
        _auto(terms, _exec(TOKEN, 0, _transfer(PAYEE, 1e6)));
    }

    /// @notice (v1.2) A HUMAN co-sign whitelists its payee if and only if the call is meterable for the mandate (AUTO
    ///         step 1: a native send with value > 0 under native terms; a `transfer` on terms.token with no native
    ///         value under ERC-20 terms), its amount is non-zero and its payee is non-zero. HumanCosigned and the
    ///         record still report the decoded payee and amount for every kind.
    function testFuzz_human_whitelistIffMeterableAndNonZero(WhitelistCase memory c, uint8 zeros) public {
        c.kind %= 5;
        // push the edge cases the rule is about (0 amount, 0 value, payee 0) in often
        if (zeros & 1 != 0) c.amount = 0;
        if (zeros & 2 != 0) c.value = 0;
        if (zeros & 4 != 0) c.payee = address(0);
        _checkWhitelistCase(c);
    }

    /// @dev One co-sign of kind `kind` (see `_kindRequest`) under native or ERC-20 terms, on the metered token or not.
    struct WhitelistCase {
        bool tokenTerms;
        uint8 kind;
        bool onMeteredToken;
        address payee;
        address from;
        uint256 amount;
        uint256 value;
    }

    function _checkWhitelistCase(WhitelistCase memory c) internal {
        Req memory q =
            _kindRequest(c.kind, c.onMeteredToken ? TOKEN : address(0xBAD70CE4), c.payee, c.from, c.amount, c.value);

        // independent reference of the rule
        bool meterable =
            c.tokenTerms ? (c.kind == 1 && q.target == TOKEN && q.value == 0) : (c.kind == 0 && q.value != 0);
        bool whitelists = meterable && c.amount != 0 && c.payee != address(0);
        address reported = c.kind == 4 ? address(0) : c.payee;

        (bytes memory args, bytes32 digest) = _sign(DEVICE_PK, q);
        vm.recordLogs();
        vm.expectEmit(address(enforcer));
        emit HumanCosigned(
            DH,
            DELEGATOR,
            REDEEMER,
            address(this),
            reported,
            (c.kind == 0 || c.kind == 4) ? q.value : c.amount,
            keyId,
            digest,
            q.presenceHash
        );
        _human(_enc(c.tokenTerms ? _tokenTerms() : _nativeTerms()), q, args);
        assertEq(_countLogs(vm.getRecordedLogs(), PayeeApproved.selector), whitelists ? 1 : 0, "PayeeApproved");
        assertEq(enforcer.isKnownPayee(address(this), DH, c.payee), whitelists, "known payee");
        assertFalse(enforcer.isKnownPayee(address(this), DH, c.from == c.payee ? address(0) : c.from));
        assertFalse(enforcer.isKnownPayee(address(this), DH, address(0)), "address(0) is never a known payee");
        assertEq(enforcer.approvalOf(address(this), digest).payee, reported);
        assertTrue(enforcer.nonceUsed(address(this), DH, q.nonce));
    }

    /// @notice The rule's truth table on fixed cases (the fuzz above covers the rest).
    function test_v12_whitelist_truthTable() public {
        // tokenTerms, kind, onMeteredToken, amount, value -> whitelists (payee PAYEE unless noted)
        WhitelistCase memory c;
        c.payee = PAYEE;
        c.from = DELEGATOR;
        uint256 snap = vm.snapshotState();
        bool[2] memory tt = [false, true];
        for (uint256 t; t < 2; ++t) {
            for (uint8 kind; kind < 5; ++kind) {
                for (uint256 v; v < 4; ++v) {
                    vm.revertToState(snap);
                    c.tokenTerms = tt[t];
                    c.kind = kind;
                    c.onMeteredToken = v & 1 == 0;
                    c.amount = v & 2 == 0 ? 5e6 : 0;
                    c.value = 0;
                    _checkWhitelistCase(c);
                    vm.revertToState(snap);
                    c.value = 1; // ERC-20 call carrying native value (for kind 0 the value is the amount)
                    _checkWhitelistCase(c);
                }
            }
        }
    }

    /// @dev kind 0 native send of `amount` to `payee`, 1 transfer, 2 approve, 3 transferFrom(from, payee), 4 unmetered
    ///      call; kinds 1-4 call `token` with native value `value`.
    function _kindRequest(uint8 kind, address token, address payee, address from, uint256 amount, uint256 value)
        internal
        view
        returns (Req memory)
    {
        if (kind == 0) return _req(payee, amount, "");
        if (kind == 1) return _req(token, value, _transfer(payee, amount));
        if (kind == 2) return _req(token, value, _approve(payee, amount));
        if (kind == 3) return _req(token, value, _transferFrom(from, payee, amount));
        return _req(token, value, abi.encodePacked(bytes4(0xdeadbeef), payee, amount)); // 56 bytes: unmetered
    }

    // =================================================================================================== v1.1 #5 autoBudget

    function _budget(bytes memory terms)
        internal
        view
        returns (uint256 spent, uint256 remaining, uint64 start, uint64 end)
    {
        return enforcer.autoBudget(address(this), DH, terms);
    }

    function _assertBudget(bytes memory terms, uint256 spent, uint256 remaining, uint256 start, uint256 end)
        internal
        view
    {
        (uint256 s, uint256 r, uint64 ps, uint64 pe) = _budget(terms);
        assertEq(s, spent, "spent");
        assertEq(r, remaining, "remaining");
        assertEq(ps, start, "periodStart");
        assertEq(pe, end, "periodEnd");
    }

    function test_autoBudget_nothingSpent() public view {
        _assertBudget(_enc(_nativeTerms()), 0, NATIVE_PERIOD_CAP, 0, 0);
        _assertBudget(_enc(_tokenTerms()), 0, TOKEN_PERIOD_CAP, 0, 0);
        IPulseCosignEnforcer.PulseTerms memory t = _nativeTerms();
        t.period = 0;
        _assertBudget(_enc(t), 0, NATIVE_PERIOD_CAP, 0, 0);
        t.periodAutoCap = 0;
        _assertBudget(_enc(t), 0, 0, 0, 0);
    }

    function test_autoBudget_appliesRollovers_aligned() public {
        bytes memory terms = _enc(_nativeTerms());
        uint256 p = PERIOD;
        _autoNative(terms, PAYEE, 1 ether);
        vm.warp(T0 + 10);
        _autoNative(terms, PAYEE, 0.5 ether);
        _assertBudget(terms, 1.5 ether, 1.5 ether, T0, T0 + p);
        vm.warp(T0 + p - 1);
        _assertBudget(terms, 1.5 ether, 1.5 ether, T0, T0 + p);

        // boundary: the view rolls over while the raw storage still holds the old period
        vm.warp(T0 + p);
        _assertBudget(terms, 0, NATIVE_PERIOD_CAP, T0 + p, T0 + 2 * p);
        (uint256 rawSpent, uint64 rawStart) = enforcer.periodSpent(address(this), DH);
        assertEq(rawSpent, 1.5 ether);
        assertEq(rawStart, T0);

        // several periods later the window is aligned to the first start, not to now
        vm.warp(T0 + 3 * p + p / 2);
        _assertBudget(terms, 0, NATIVE_PERIOD_CAP, T0 + 3 * p, T0 + 4 * p);
        _autoNative(terms, PAYEE, 1 ether);
        _assertBudget(terms, 1 ether, 2 ether, T0 + 3 * p, T0 + 4 * p);
        _autoNative(terms, PAYEE, 1 ether);
        _autoNative(terms, PAYEE, 1 ether);
        _assertBudget(terms, 3 ether, 0, T0 + 3 * p, T0 + 4 * p);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _autoNative(terms, PAYEE, 1);

        vm.warp(T0 + 4 * p - 1);
        _assertBudget(terms, 3 ether, 0, T0 + 3 * p, T0 + 4 * p);
        vm.warp(T0 + 4 * p);
        _assertBudget(terms, 0, NATIVE_PERIOD_CAP, T0 + 4 * p, T0 + 5 * p);
        _autoNative(terms, PAYEE, 1 ether);
        (rawSpent, rawStart) = enforcer.periodSpent(address(this), DH);
        assertEq(rawSpent, 1 ether);
        assertEq(rawStart, T0 + 4 * p);
    }

    function test_autoBudget_periodZero_neverRollsOver() public {
        IPulseCosignEnforcer.PulseTerms memory t = _nativeTerms();
        t.period = 0;
        bytes memory terms = _enc(t);
        _autoNative(terms, PAYEE, 1 ether);
        _assertBudget(terms, 1 ether, 2 ether, T0, 0);
        vm.warp(T0 + 3650 days);
        _autoNative(terms, PAYEE, 1 ether);
        _assertBudget(terms, 2 ether, 1 ether, T0, 0);
    }

    function test_autoBudget_humanSpendsDoNotCount() public {
        bytes memory terms = _enc(_nativeTerms());
        _cosign(terms, _req(PAYEE, 50 ether, ""));
        _assertBudget(terms, 0, NATIVE_PERIOD_CAP, 0, 0);
        _autoNative(terms, PAYEE, 1 ether);
        Req memory q = _req(PAYEE, 50 ether, "");
        q.nonce = 2;
        _cosign(terms, q);
        _assertBudget(terms, 1 ether, 2 ether, T0, T0 + PERIOD);
    }

    function test_autoBudget_perManagerAndMandate() public {
        bytes memory terms = _enc(_tokenTerms());
        _auto(terms, _exec(TOKEN, 0, _transfer(PAYEE, 60e6)));
        vm.warp(T0 + 1);
        vm.prank(MANAGER_B);
        enforcer.beforeHook(terms, "", single, _exec(TOKEN, 0, _transfer(PAYEE, 20e6)), DH, DELEGATOR, REDEEMER);
        vm.warp(T0 + 2);
        enforcer.beforeHook(terms, "", single, _exec(TOKEN, 0, _transfer(PAYEE, 30e6)), DH2, DELEGATOR, REDEEMER);

        (uint256 s, uint256 r, uint64 ps, uint64 pe) = enforcer.autoBudget(address(this), DH, terms);
        assertEq(abi.encode(s, r, ps, pe), abi.encode(60e6, 190e6, T0, T0 + PERIOD));
        (s, r, ps, pe) = enforcer.autoBudget(MANAGER_B, DH, terms);
        assertEq(abi.encode(s, r, ps, pe), abi.encode(20e6, 230e6, T0 + 1, T0 + 1 + PERIOD));
        (s, r, ps, pe) = enforcer.autoBudget(address(this), DH2, terms);
        assertEq(abi.encode(s, r, ps, pe), abi.encode(30e6, 220e6, T0 + 2, T0 + 2 + PERIOD));
        (s, r, ps, pe) = enforcer.autoBudget(ATTACKER, DH, terms);
        assertEq(abi.encode(s, r, ps, pe), abi.encode(0, TOKEN_PERIOD_CAP, 0, 0));
    }

    function test_autoBudget_invalidTerms_reverts() public {
        bytes memory good = _enc(_nativeTerms());
        uint256[6] memory lens = [uint256(0), 1, 256, 287, 289, 320];
        for (uint256 i; i < lens.length; ++i) {
            vm.expectRevert(IPulseCosignEnforcer.InvalidTerms.selector);
            enforcer.autoBudget(address(this), DH, _resize(good, lens[i]));
        }
        uint256[5] memory idx = [uint256(2), 3, 4, 5, 7];
        uint256[5] memory bad =
            [uint256(1) << 160, uint256(1) << 128, uint256(type(uint128).max) + 1, uint256(1) << 32, 2];
        for (uint256 i; i < idx.length; ++i) {
            vm.expectRevert(IPulseCosignEnforcer.InvalidTerms.selector);
            enforcer.autoBudget(address(this), DH, _setWord(good, idx[i], bad[i]));
        }
        vm.expectRevert(IPulseCosignEnforcer.InvalidTerms.selector);
        enforcer.autoBudget(address(this), DH, _setWord(good, 6, uint256(1) << 64)); // epoch
        vm.expectRevert(IPulseCosignEnforcer.InvalidTerms.selector);
        enforcer.autoBudget(address(this), DH, _setWord(good, 8, uint256(1) << 160)); // sentinel
    }

    /// @notice Queried with terms whose cap is below what was spent (not the mandate's terms), remaining is 0, not
    ///         an arithmetic panic.
    function test_autoBudget_capBelowSpent_remainingZero() public {
        bytes memory terms = _enc(_nativeTerms());
        _autoNative(terms, PAYEE, 1 ether);
        _autoNative(terms, PAYEE, 1 ether);
        IPulseCosignEnforcer.PulseTerms memory t = _nativeTerms();
        t.periodAutoCap = 1 ether;
        _assertBudget(_enc(t), 2 ether, 0, T0, T0 + PERIOD);
    }

    /// @notice periodEnd is clamped to uint64 max instead of wrapping when the window would end past 2^64 - 1.
    function test_autoBudget_periodEnd_clampedAtUint64Max() public {
        IPulseCosignEnforcer.PulseTerms memory t = _nativeTerms();
        t.period = type(uint32).max;
        bytes memory terms = _enc(t);
        uint256 late = uint256(type(uint64).max) - 1000;
        vm.warp(late);
        _autoNative(terms, PAYEE, 1);
        _assertBudget(terms, 1, NATIVE_PERIOD_CAP - 1, late, type(uint64).max);
    }

    /// @dev Independent reference for the AUTO budget: the windows are [first + k*P, first + (k+1)*P) from the first
    ///      accepted spend, and spent = the sum of accepted spends in the window containing now.
    struct BudgetModel {
        uint32 period;
        uint128 cap;
        uint256 first; // 0 = no accepted spend yet
        uint256 n;
        uint256[32] windowOf;
        uint256[32] amountOf;
    }

    function _refBudget(BudgetModel memory m) internal view returns (uint256 spent, uint256 start, uint256 end) {
        if (m.first == 0) return (0, 0, 0);
        uint256 w = m.period == 0 ? 0 : (block.timestamp - m.first) / m.period;
        for (uint256 i; i < m.n; ++i) {
            if (m.windowOf[i] == w) spent += m.amountOf[i];
        }
        start = m.first + w * m.period;
        end = m.period == 0 ? 0 : start + m.period;
    }

    /// @notice autoBudget matches an independent reference across random waits and rollovers, and predicts exactly
    ///         whether the next AUTO spend of `x` passes the period check (per-tx cap out of the way, ERC-20 terms so
    ///         x = 0 is a valid spend too).
    function testFuzz_autoBudget_predictsPeriodCheck(uint256 seed, uint32 period, uint128 cap) public {
        BudgetModel memory m;
        m.period = uint32(bound(period, 0, 30 days));
        m.cap = uint128(bound(cap, 0, uint256(1) << 127));
        IPulseCosignEnforcer.PulseTerms memory t = _tokenTerms();
        (t.period, t.perTxAutoCap, t.periodAutoCap) = (m.period, type(uint128).max, m.cap);
        bytes memory terms = _enc(t);

        for (uint256 i; i < 32; ++i) {
            _budgetStep(m, terms, uint256(keccak256(abi.encode(seed, i))));
        }
    }

    function _budgetStep(BudgetModel memory m, bytes memory terms, uint256 r) internal {
        // waits: none, within the window, or up to 5 windows ahead (several rollovers at once)
        uint256 span = m.period == 0 ? 3650 days : 5 * uint256(m.period);
        if (r % 3 != 0) vm.warp(block.timestamp + (r >> 8) % (span + 1));

        Budget memory b = _budgetOf(terms);
        (uint256 refSpent, uint256 refStart, uint256 refEnd) = _refBudget(m);
        assertEq(b.spent, refSpent, "spent vs reference");
        assertEq(b.remaining, m.cap - refSpent, "remaining vs reference");
        assertEq(b.start, refStart, "periodStart vs reference");
        assertEq(b.end, refEnd, "periodEnd vs reference");

        uint256 x = _pickAmount(b.remaining, m.cap, r);
        try enforcer.beforeHook(terms, "", single, _exec(TOKEN, 0, _transfer(PAYEE, x)), DH, DELEGATOR, REDEEMER) {
            assertTrue(x <= b.remaining, "passed although x > remaining");
            if (m.first == 0) m.first = block.timestamp;
            m.windowOf[m.n] = m.period == 0 ? 0 : (block.timestamp - m.first) / m.period;
            m.amountOf[m.n] = x;
            ++m.n;
            Budget memory a = _budgetOf(terms);
            assertEq(a.spent, b.spent + x, "spent after the spend");
            assertEq(a.remaining, b.remaining - x, "remaining after the spend");
            assertEq(a.start, b.start == 0 ? block.timestamp : b.start, "start after the spend");
            assertEq(a.end, m.period == 0 ? 0 : uint256(a.start) + m.period, "end after the spend");
        } catch (bytes memory err) {
            assertFalse(x <= b.remaining, "failed although x <= remaining");
            // forge-lint: disable-next-line(unsafe-typecast)
            assertEq(bytes4(err), IPulseCosignEnforcer.HumanRequired.selector);
            assertEq(abi.encode(_budgetOf(terms)), abi.encode(b), "a failed spend changes nothing");
        }
    }

    struct Budget {
        uint256 spent;
        uint256 remaining;
        uint64 start;
        uint64 end;
    }

    function _budgetOf(bytes memory terms) internal view returns (Budget memory b) {
        (b.spent, b.remaining, b.start, b.end) = enforcer.autoBudget(address(this), DH, terms);
    }

    /// @dev An amount at, just above, just below, far below or anywhere around the remaining budget.
    function _pickAmount(uint256 remaining, uint256 cap, uint256 r) internal pure returns (uint256) {
        uint256 pick = (r >> 128) % 5;
        if (pick == 0) return remaining;
        if (pick == 1) return remaining + 1;
        if (pick == 2) return remaining == 0 ? 0 : remaining - 1;
        if (pick == 3) return 0;
        return (r >> 64) % (cap + 2);
    }

    // =================================================================================================== v1.1 events

    /// @notice AutoSpend, HumanCosigned and PayeeApproved name the DelegationManager (the hook's msg.sender), in the
    ///         interface's field order.
    function test_events_carryTheManager() public {
        assertEq(AutoSpend.selector, IPulseCosignEnforcer.AutoSpend.selector);
        assertEq(HumanCosigned.selector, IPulseCosignEnforcer.HumanCosigned.selector);
        assertEq(PayeeApproved.selector, IPulseCosignEnforcer.PayeeApproved.selector);
        assertEq(AutoSpend.selector, keccak256("AutoSpend(bytes32,address,address,address,address,uint256,uint256)"));
        assertEq(
            HumanCosigned.selector,
            keccak256("HumanCosigned(bytes32,address,address,address,address,uint256,bytes32,bytes32,bytes32)")
        );
        assertEq(PayeeApproved.selector, keccak256("PayeeApproved(address,bytes32,address)"));

        bytes memory terms = _enc(_nativeTerms());
        Req memory q = _req(PAYEE, 5 ether, "");
        (bytes memory args, bytes32 digest) = _sign(DEVICE_PK, q);

        vm.recordLogs();
        vm.prank(MANAGER_B);
        enforcer.beforeHook(terms, "", single, _exec(PAYEE2, 0.3 ether, ""), DH, DELEGATOR, REDEEMER);
        vm.prank(MANAGER_B);
        _human(terms, q, args);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 3);

        // AutoSpend: topics (sig, delegationHash, delegator, redeemer), data (manager, payee, amount, periodSpent)
        assertEq(logs[0].topics.length, 4);
        assertEq(logs[0].topics[0], AutoSpend.selector);
        assertEq(logs[0].topics[1], DH);
        assertEq(logs[0].topics[2], bytes32(uint256(uint160(DELEGATOR))));
        assertEq(logs[0].topics[3], bytes32(uint256(uint160(REDEEMER))));
        assertEq(logs[0].data, abi.encode(MANAGER_B, PAYEE2, 0.3 ether, 0.3 ether));

        // PayeeApproved: topics (sig, manager, delegationHash, payee), no data
        assertEq(logs[1].topics.length, 4);
        assertEq(logs[1].topics[0], PayeeApproved.selector);
        assertEq(logs[1].topics[1], bytes32(uint256(uint160(MANAGER_B))));
        assertEq(logs[1].topics[2], DH);
        assertEq(logs[1].topics[3], bytes32(uint256(uint160(PAYEE))));
        assertEq(logs[1].data.length, 0);

        // HumanCosigned: data (manager, payee, amount, keyId, approvalDigest, presenceHash)
        assertEq(logs[2].topics.length, 4);
        assertEq(logs[2].topics[0], HumanCosigned.selector);
        assertEq(logs[2].topics[1], DH);
        assertEq(logs[2].data, abi.encode(MANAGER_B, PAYEE, 5 ether, keyId, digest, q.presenceHash));
    }

    function testFuzz_events_autoSpendNamesCaller(address manager, uint96 amount) public {
        amount = uint96(bound(amount, 1, NATIVE_PER_TX));
        vm.expectEmit(address(enforcer));
        emit AutoSpend(DH, DELEGATOR, REDEEMER, manager, PAYEE, amount, amount);
        vm.prank(manager);
        enforcer.beforeHook(_enc(_nativeTerms()), "", single, _exec(PAYEE, amount, ""), DH, DELEGATOR, REDEEMER);
    }

    // =================================================================================================== v1.2 known payees

    function _guarded(IPulseCosignEnforcer.PulseTerms memory t) internal pure returns (bytes memory) {
        t.newPayeeNeedsHuman = true;
        return _enc(t);
    }

    /// @dev Co-signs `q` under `terms` and asserts whether it whitelisted `payee` (PayeeApproved + isKnownPayee).
    function _cosignExpectWhitelist(bytes memory terms, Req memory q, address payee, bool expected) internal {
        vm.recordLogs();
        _cosign(terms, q);
        assertEq(_countLogs(vm.getRecordedLogs(), PayeeApproved.selector), expected ? 1 : 0, "PayeeApproved");
        assertEq(enforcer.isKnownPayee(address(this), q.delegationHash, payee), expected, "isKnownPayee");
    }

    /// @notice Positive: a co-signed `transfer` of the metered token with amount > 0 whitelists the recipient, and the
    ///         AUTO path then pays it.
    function test_v12_whitelist_meteredTokenTransfer() public {
        bytes memory terms = _guarded(_tokenTerms());
        Req memory q = _reqN(TOKEN, 0, _transfer(PAYEE, 1), 1); // 1 base unit is enough: it is a real payment
        vm.expectEmit(address(enforcer));
        emit PayeeApproved(address(this), DH, PAYEE);
        _cosign(terms, q);
        assertTrue(enforcer.isKnownPayee(address(this), DH, PAYEE));
        _auto(terms, _exec(TOKEN, 0, _transfer(PAYEE, TOKEN_PER_TX)));
    }

    /// @notice Positive: a co-signed native send > 0 under a native mandate whitelists the target.
    function test_v12_whitelist_nativeSendUnderNativeMandate() public {
        bytes memory terms = _guarded(_nativeTerms());
        vm.expectEmit(address(enforcer));
        emit PayeeApproved(address(this), DH, PAYEE);
        _cosign(terms, _reqN(PAYEE, 1, "", 1)); // 1 wei
        assertTrue(enforcer.isKnownPayee(address(this), DH, PAYEE));
        _autoNative(terms, PAYEE, NATIVE_PER_TX);
    }

    /// @notice (ENF1 / PROTOCOL-2) A 0-amount `transfer` of the metered token and a 0-value native send never
    ///         whitelist; the AUTO path keeps refusing the payee.
    function test_v12_noWhitelist_zeroAmount() public {
        bytes memory tokenTerms = _guarded(_tokenTerms());
        _cosignExpectWhitelist(tokenTerms, _reqN(TOKEN, 0, _transfer(PAYEE, 0), 1), PAYEE, false);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _auto(tokenTerms, _exec(TOKEN, 0, _transfer(PAYEE, 1e6)));

        bytes memory nativeTerms = _guarded(_nativeTerms());
        Req memory q = _reqN(PAYEE2, 0, "", 1);
        q.delegationHash = DH2;
        _cosignExpectWhitelist(nativeTerms, q, PAYEE2, false);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        enforcer.beforeHook(nativeTerms, "", single, _exec(PAYEE2, 1, ""), DH2, DELEGATOR, REDEEMER);
    }

    /// @notice (ENF1 / PROTOCOL-2 / INTEGRATION-3 / ATTACKER-1) A co-sign on another asset than the mandate's never
    ///         whitelists, whatever the amount: a native send under an ERC-20 mandate, a `transfer` of another token, a
    ///         `transfer` of the metered token carrying native value, and a token `transfer` under a native mandate.
    function test_v12_noWhitelist_crossAsset() public {
        bytes memory tokenTerms = _guarded(_tokenTerms());
        _cosignExpectWhitelist(tokenTerms, _reqN(PAYEE, 5 ether, "", 1), PAYEE, false); // MON under an mUSD mandate
        _cosignExpectWhitelist(tokenTerms, _reqN(address(0xBAD), 0, _transfer(PAYEE, 1e30), 2), PAYEE, false);
        _cosignExpectWhitelist(tokenTerms, _reqN(TOKEN, 1, _transfer(PAYEE, 5e6), 3), PAYEE, false); // native value
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        _auto(tokenTerms, _exec(TOKEN, 0, _transfer(PAYEE, 1e6)));

        bytes memory nativeTerms = _guarded(_nativeTerms());
        Req memory q = _reqN(TOKEN, 0, _transfer(PAYEE2, 5e6), 1); // mUSD under a MON mandate
        q.delegationHash = DH2;
        _cosignExpectWhitelist(nativeTerms, q, PAYEE2, false);
        vm.expectRevert(IPulseCosignEnforcer.HumanRequired.selector);
        enforcer.beforeHook(nativeTerms, "", single, _exec(PAYEE2, 1, ""), DH2, DELEGATOR, REDEEMER);
    }

    /// @notice A meterable, non-zero payment to address(0) whitelists nobody (payee != 0).
    function test_v12_noWhitelist_payeeZero() public {
        _cosignExpectWhitelist(_guarded(_nativeTerms()), _reqN(address(0), 1 ether, "", 1), address(0), false);
        _cosignExpectWhitelist(
            _guarded(_tokenTerms()), _reqN(TOKEN, 0, _transfer(address(0), 1e6), 2), address(0), false
        );
    }

    /// @notice A payee first co-signed with a non-whitelisting request still becomes known with a real payment
    ///         (PayeeApproved fires then, once).
    function test_v12_whitelist_afterNonMeterableCosign() public {
        bytes memory terms = _guarded(_tokenTerms());
        _cosignExpectWhitelist(terms, _reqN(PAYEE, 0, "", 1), PAYEE, false);
        _cosignExpectWhitelist(terms, _reqN(TOKEN, 0, _transfer(PAYEE, 0), 2), PAYEE, false);
        _cosignExpectWhitelist(terms, _reqN(TOKEN, 0, _transfer(PAYEE, 2e6), 3), PAYEE, true);
        vm.recordLogs();
        _cosign(terms, _reqN(TOKEN, 0, _transfer(PAYEE, 3e6), 4));
        assertEq(_countLogs(vm.getRecordedLogs(), PayeeApproved.selector), 0, "only the first time");
    }

    // =================================================================================================== v1.2 nonces

    /// @notice (PROTOCOL-1) The device signs the very same request twice (same nonce 7, fresh presence salt, so two
    ///         digests): only the first co-sign pays.
    function test_v12_nonce_sameRequestSignedTwice_replayed() public {
        bytes memory terms = _enc(_tokenTerms());
        Req memory first = _reqN(TOKEN, 0, _transfer(PAYEE, 400e6), 7);
        first.presenceHash = _presence(1001);
        Req memory second = _copy(first);
        second.presenceHash = _presence(1002);
        (bytes memory args1, bytes32 d1) = _sign(DEVICE_PK, first);
        (bytes memory args2, bytes32 d2) = _sign(DEVICE_PK, second);
        assertTrue(d1 != d2, "two digests");

        assertFalse(enforcer.nonceUsed(address(this), DH, 7));
        _human(terms, first, args1);
        assertTrue(enforcer.nonceUsed(address(this), DH, 7));
        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
        _human(terms, second, args2);
        assertFalse(enforcer.consumed(address(this), d2), "the second co-sign left no record");
    }

    /// @notice The nonce is single-use whatever the rest of the request: another payee, amount, redeemer or expiry.
    function test_v12_nonce_anyOtherRequestSameNonce_replayed() public {
        bytes memory terms = _enc(_nativeTerms());
        _cosign(terms, _reqN(PAYEE, 1 ether, "", 9));
        Req[] memory others = new Req[](4);
        others[0] = _reqN(PAYEE2, 1 ether, "", 9); // another payee
        others[1] = _reqN(PAYEE, 2 ether, "", 9); // another amount
        others[2] = _reqN(TOKEN, 0, _transfer(PAYEE, 1e6), 9); // another asset
        others[3] = _reqN(PAYEE, 1 ether, "", 9);
        others[3].redeemer = address(0x5AB); // another redeemer
        for (uint256 i; i < others.length; ++i) {
            (bytes memory args,) = _sign(DEVICE_PK, others[i]);
            vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
            _human(terms, others[i], args);
        }
        Req memory later = _reqN(PAYEE, 1 ether, "", 9);
        later.expiry += 1;
        (bytes memory a,) = _sign(DEVICE_PK, later);
        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
        _human(terms, later, a);
    }

    /// @notice Positive: the same nonce under a different mandate works (single-use per mandate).
    function test_v12_nonce_sameNonceDifferentMandate_ok() public {
        bytes memory terms = _enc(_nativeTerms());
        _cosign(terms, _reqN(PAYEE, 1 ether, "", 7));
        Req memory q = _reqN(PAYEE, 1 ether, "", 7);
        (q.delegationHash, q.delegator) = (DH2, DELEGATOR2);
        _cosign(terms, q);
        assertTrue(enforcer.nonceUsed(address(this), DH, 7));
        assertTrue(enforcer.nonceUsed(address(this), DH2, 7));
        assertFalse(enforcer.nonceUsed(address(this), DH, 8));
        assertFalse(enforcer.nonceUsed(MANAGER_B, DH, 7));
    }

    /// @notice Positive: a third party that calls beforeHook directly with the pending co-sign's args (nonce 7) only
    ///         burns nonce 7 for itself; the real manager's redemption with that nonce still goes through, and
    ///         another manager keeps its own nonces too.
    function test_v12_nonce_directBeforeHookByThirdParty_doesNotBurnManagersNonce() public {
        bytes memory terms = _enc(_tokenTerms());
        Req memory q = _reqN(TOKEN, 0, _transfer(PAYEE, 400e6), 7);
        (bytes memory args, bytes32 digest) = _sign(DEVICE_PK, q);

        vm.prank(ATTACKER);
        _human(terms, q, args);
        assertTrue(enforcer.nonceUsed(ATTACKER, DH, 7));
        assertFalse(enforcer.nonceUsed(address(this), DH, 7), "not burnt for the manager");

        // the attacker cannot even re-sign-and-reuse it for itself, but the manager redeems normally
        Req memory again = _copy(q);
        again.presenceHash = _presence(2);
        (bytes memory args2,) = _sign(DEVICE_PK, again);
        vm.prank(ATTACKER);
        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
        _human(terms, again, args2);

        _human(terms, q, args);
        assertTrue(enforcer.consumed(address(this), digest));
        assertTrue(enforcer.nonceUsed(address(this), DH, 7));
        vm.prank(MANAGER_B);
        _human(terms, again, args2);
        assertTrue(enforcer.nonceUsed(MANAGER_B, DH, 7));
    }

    /// @notice The nonce is marked only after P256.verify succeeds: a bad co-sign with nonce 5 leaves it free.
    function test_v12_nonce_markedOnlyAfterSignatureVerified() public {
        bytes memory terms = _enc(_nativeTerms());
        Req memory q = _reqN(PAYEE, 1 ether, "", 5);
        (bytes memory args,) = _sign(DEVICE_PK, q);
        (bytes32 r, bytes32 s) = _rs(args);

        (bytes memory otherKeyArgs,) = _sign(OTHER_PK, q);
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _human(terms, q, otherKeyArgs);
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _human(terms, q, _args(q, r, p256HighS(s)));
        vm.expectRevert(IPulseCosignEnforcer.BadCosign.selector);
        _human(terms, q, _args(q, bytes32(0), bytes32(0)));
        assertFalse(enforcer.nonceUsed(address(this), DH, 5), "a failed co-sign does not burn the nonce");

        _human(terms, q, args);
        assertTrue(enforcer.nonceUsed(address(this), DH, 5));
    }

    /// @notice A co-sign rejected before the nonce check (revoked, stale epoch, bad args, expired) never marks it.
    function test_v12_nonce_earlierFailuresDoNotMark() public {
        IPulseCosignEnforcer.PulseTerms memory t = _nativeTerms();
        t.epoch = 1;
        bytes memory terms = _enc(t);
        Req memory q = _reqN(PAYEE, 1 ether, "", 11);
        (bytes memory args,) = _sign(DEVICE_PK, q);

        vm.expectRevert(IPulseCosignEnforcer.InvalidArgs.selector);
        _human(terms, q, _setWord(args, 1, (uint256(1) << 64) | q.expiry));
        vm.warp(uint256(q.expiry) + 1);
        vm.expectRevert(IPulseCosignEnforcer.CosignExpired.selector);
        _human(terms, q, args);
        vm.warp(T0);
        _panicAs(DEVICE_PK, 2);
        vm.expectRevert(IPulseCosignEnforcer.StaleEpoch.selector);
        _human(terms, q, args);
        assertFalse(enforcer.nonceUsed(address(this), DH, 11));

        t.epoch = 2;
        terms = _enc(t);
        Req memory q2 = _reqN(PAYEE, 1 ether, "", 12);
        q2.delegationHash = DH2;
        (bytes memory args2,) = _sign(DEVICE_PK, q2);
        _revokeAs(DEVICE_PK, DH2);
        vm.expectRevert(IPulseCosignEnforcer.DelegationRevoked.selector);
        _human(terms, q2, args2);
        assertFalse(enforcer.nonceUsed(address(this), DH2, 12));

        _human(terms, q, args); // nonce 11 is still free under DH
        assertTrue(enforcer.nonceUsed(address(this), DH, 11));
    }

    /// @notice Check order: expiry, digest replay, nonce, signature. A used nonce with a garbage signature reverts
    ///         CosignReplayed (not BadCosign); a used nonce on an expired co-sign reverts CosignExpired.
    function test_v12_nonce_checkOrder() public {
        bytes memory terms = _enc(_nativeTerms());
        Req memory q = _reqN(PAYEE, 1 ether, "", 3);
        (bytes memory args,) = _sign(DEVICE_PK, q);
        _human(terms, q, args);

        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector); // the digest replay check
        _human(terms, q, args);

        Req memory fresh = _copy(q);
        fresh.presenceHash = _presence(7);
        vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector); // nonce before signature
        _human(terms, fresh, _args(fresh, bytes32(0), bytes32(0)));

        fresh.expiry = uint64(block.timestamp - 1);
        (bytes memory expiredArgs,) = _sign(DEVICE_PK, fresh);
        vm.expectRevert(IPulseCosignEnforcer.CosignExpired.selector); // expiry before the nonce
        _human(terms, fresh, expiredArgs);
    }

    /// @notice nonceUsed tracks exactly the nonces consumed (bitmap words and bit boundaries included).
    function test_v12_nonceUsed_bitmapBoundaries() public {
        bytes memory terms = _enc(_nativeTerms());
        uint256[7] memory used = [uint256(0), 1, 255, 256, 511, uint256(1) << 255, type(uint256).max];
        for (uint256 i; i < used.length; ++i) {
            _cosign(terms, _reqN(PAYEE, 1, "", used[i]));
        }
        for (uint256 i; i < used.length; ++i) {
            assertTrue(enforcer.nonceUsed(address(this), DH, used[i]));
        }
        uint256[7] memory free = [uint256(2), 254, 257, 510, 512, (uint256(1) << 255) + 1, type(uint256).max - 1];
        for (uint256 i; i < free.length; ++i) {
            assertFalse(enforcer.nonceUsed(address(this), DH, free[i]));
            _cosign(terms, _reqN(PAYEE, 1, "", free[i])); // each still usable once
        }
        for (uint256 i; i < used.length; ++i) {
            Req memory q = _reqN(PAYEE, 2, "", used[i]);
            (bytes memory args,) = _sign(DEVICE_PK, q);
            vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
            _human(terms, q, args);
        }
    }

    /// @notice Two co-signs under one (manager, mandate): the second passes if and only if its nonce differs.
    function testFuzz_v12_nonce_singleUsePerManagerAndMandate(uint256 n1, uint256 n2, uint256 v1, uint256 v2) public {
        bytes memory terms = _enc(_nativeTerms());
        _cosign(terms, _reqN(PAYEE, v1, "", n1));
        assertTrue(enforcer.nonceUsed(address(this), DH, n1));
        assertEq(enforcer.nonceUsed(address(this), DH, n2), n1 == n2);
        assertFalse(enforcer.nonceUsed(MANAGER_B, DH, n1));
        assertFalse(enforcer.nonceUsed(address(this), DH2, n1));

        Req memory q = _reqN(PAYEE2, v2, "", n2);
        q.presenceHash = _presence(v2);
        (bytes memory args,) = _sign(DEVICE_PK, q);
        if (n1 == n2) vm.expectRevert(IPulseCosignEnforcer.CosignReplayed.selector);
        _human(terms, q, args);
        assertTrue(enforcer.nonceUsed(address(this), DH, n2));
    }

    /// @notice The AUTO path neither reads nor writes co-sign nonces.
    function test_v12_nonce_autoPathUntouched() public {
        bytes memory terms = _enc(_nativeTerms());
        _autoNative(terms, PAYEE, 1);
        assertFalse(enforcer.nonceUsed(address(this), DH, 0));
        assertFalse(enforcer.nonceUsed(address(this), DH, 1));
        _cosign(terms, _reqN(PAYEE, 1, "", 1));
        _autoNative(terms, PAYEE, 1);
    }

    // =================================================================================================== utils

    function _setWordAt(bytes memory b, uint256 offset, uint256 word) internal pure returns (bytes memory out) {
        out = _resize(b, b.length);
        assembly {
            mstore(add(add(out, 0x20), offset), word)
        }
    }
}

/// @notice The whole behaviour suite again, with the RIP-7212 / EIP-7951 precompile (mock) at 0x0100, as on Monad.
contract PulseCosignEnforcerPrecompileTest is PulseCosignEnforcerTest {
    function setUp() public override {
        etchP256Precompile();
        super.setUp();
    }

    function test_precompileIsActive() public view {
        (bool ok, bytes memory ret) = P256_PRECOMPILE.staticcall(abi.encode(bytes32(0), bytes32(0), bytes32(0), px, py));
        assertTrue(ok);
        assertEq(ret.length, 0, "mock answers empty for an invalid signature");
        assertGt(P256_PRECOMPILE.code.length, 0);
    }
}

/// @notice Gas figures (gasleft deltas around the external call, enforcer storage cooled first). Run with -vv.
contract PulseCosignEnforcerGasTest is PulseCosignEnforcerBase {
    function _measureAuto(bytes memory terms, bytes memory exec, bytes32 dh) internal returns (uint256 used) {
        vm.cool(address(enforcer));
        uint256 g = gasleft();
        enforcer.beforeHook(terms, "", single, exec, dh, DELEGATOR, REDEEMER);
        used = g - gasleft();
    }

    function _measureHuman(bytes memory terms, Req memory q) internal returns (uint256 used) {
        (bytes memory args,) = _sign(DEVICE_PK, q);
        bytes memory exec = _exec(q.target, q.value, q.callData);
        vm.cool(address(enforcer));
        uint256 g = gasleft();
        enforcer.beforeHook(terms, args, single, exec, q.delegationHash, q.delegator, q.redeemer);
        used = g - gasleft();
    }

    function test_gas_auto() public {
        bytes memory native = _enc(_nativeTerms());
        bytes memory pay = _exec(PAYEE, 1, "");
        emit log_named_uint("AUTO native, first spend (new period slot)", _measureAuto(native, pay, DH));
        emit log_named_uint("AUTO native, next spend", _measureAuto(native, pay, DH));

        IPulseCosignEnforcer.PulseTerms memory t = _nativeTerms();
        t.sentinel = address(sentinel);
        t.newPayeeNeedsHuman = true;
        bytes memory guarded = _enc(t);
        _cosign(guarded, _req(PAYEE, 1, "")); // PAYEE becomes known
        emit log_named_uint("AUTO native, sentinel + known payee, next spend", _measureAuto(guarded, pay, DH));

        IPulseCosignEnforcer.PulseTerms memory tt = _tokenTerms();
        tt.sentinel = address(sentinel);
        tt.newPayeeNeedsHuman = true;
        bytes memory tokenGuarded = _enc(tt);
        bytes memory transfer_ = _exec(TOKEN, 0, _transfer(PAYEE, 1e6));
        Req memory q = _req(TOKEN, 0, _transfer(PAYEE, 1e6));
        q.delegationHash = DH2;
        _cosign(tokenGuarded, q); // known payees are per mandate: PAYEE becomes known under DH2 too
        emit log_named_uint(
            "AUTO ERC-20 transfer, sentinel + known payee, first spend", _measureAuto(tokenGuarded, transfer_, DH2)
        );
        emit log_named_uint(
            "AUTO ERC-20 transfer, sentinel + known payee, next spend", _measureAuto(tokenGuarded, transfer_, DH2)
        );
    }

    /// @dev v1.2: every co-sign under one mandate needs its own nonce. Nonces are stored as a bitmap of 256 nonces per
    ///      slot, so the first nonce of a 256-nonce word writes a fresh slot and the next ones in that word do not.
    function _humanFigures(string memory label) internal {
        bytes memory terms = _enc(_nativeTerms());
        Req memory q = _req(PAYEE, 1, "");
        emit log_named_uint(
            string.concat(label, ": HUMAN native, new payee (nonce 1: new nonce word)"), _measureHuman(terms, q)
        );
        q.nonce = 2;
        emit log_named_uint(
            string.concat(label, ": HUMAN native, known payee (nonce 2: same nonce word)"), _measureHuman(terms, q)
        );
        q.nonce = 256;
        emit log_named_uint(
            string.concat(label, ": HUMAN native, known payee (nonce 256: new nonce word)"), _measureHuman(terms, q)
        );
        q = _req(TOKEN, 0, _transfer(PAYEE2, 5e6));
        q.nonce = 3;
        emit log_named_uint(
            string.concat(label, ": HUMAN ERC-20 transfer (token terms), new payee (nonce 3: same nonce word)"),
            _measureHuman(_enc(_tokenTerms()), q)
        );
    }

    function test_gas_human_solidityFallback() public {
        _humanFigures("Solidity P256 fallback");
    }

    function test_gas_human_mockPrecompile() public {
        etchP256Precompile();
        _humanFigures("mock precompile (runs the Solidity verifier)");
    }

    /// @dev Everything but the curve maths: add the real precompile's 6,900 gas to get the Monad figure.
    function test_gas_human_constantPrecompileStub() public {
        vm.etch(P256_PRECOMPILE, address(new P256AcceptAllStub()).code);
        _humanFigures("accept-all stub (enforcer-only cost)");
    }

    function test_gas_p256VerifyAlone() public {
        bytes32 h = keccak256("gas");
        (bytes32 r, bytes32 s) = p256Sign(DEVICE_PK, h);
        uint256 g = gasleft();
        bool ok = P256.verifySolidity(h, r, s, px, py);
        emit log_named_uint("P256.verifySolidity alone", g - gasleft());
        assertTrue(ok);
    }

    function test_gas_killSwitch() public {
        (bytes32 r, bytes32 s) = p256Sign(DEVICE_PK, _revokeDigest(DH));
        uint256 g = gasleft();
        enforcer.revoke(px, py, DH, r, s);
        emit log_named_uint("revoke (Solidity P256)", g - gasleft());
        (r, s) = p256Sign(DEVICE_PK, _panicDigest(1));
        g = gasleft();
        enforcer.panic(px, py, 1, r, s);
        emit log_named_uint("panic (Solidity P256)", g - gasleft());
    }
}
