// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { Test } from "forge-std/Test.sol";
import { IERC20Errors } from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { MockUSD } from "../src/MockUSD.sol";

contract MockUSDTest is Test {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    MockUSD internal usd;
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");

    function setUp() public {
        usd = new MockUSD();
    }

    function test_metadata() public view {
        assertEq(usd.name(), "MockUSD (Ripar demo)");
        assertEq(usd.symbol(), "mUSD");
        assertEq(usd.decimals(), 6);
        assertEq(usd.totalSupply(), 0);
        assertEq(usd.FAUCET_MAX(), 1_000e6);
    }

    function test_noOwner() public view {
        // no ERC-173 owner(), no admin surface at all
        (bool ok,) = address(usd).staticcall(abi.encodeWithSignature("owner()"));
        assertFalse(ok);
    }

    function test_faucet_max() public {
        vm.expectEmit(true, true, false, true, address(usd));
        emit Transfer(address(0), alice, 1_000e6);
        vm.prank(bob); // anyone may call, for anyone
        usd.faucet(alice, 1_000e6);
        assertEq(usd.balanceOf(alice), 1_000e6);
        assertEq(usd.totalSupply(), 1_000e6);
    }

    function test_faucet_aboveCap_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(MockUSD.FaucetCapExceeded.selector, 1_000e6 + 1, 1_000e6));
        usd.faucet(alice, 1_000e6 + 1);
        vm.expectRevert(abi.encodeWithSelector(MockUSD.FaucetCapExceeded.selector, type(uint256).max, 1_000e6));
        usd.faucet(alice, type(uint256).max);
        assertEq(usd.totalSupply(), 0);
    }

    function test_faucet_zeroAndRepeated() public {
        usd.faucet(alice, 0);
        assertEq(usd.balanceOf(alice), 0);
        for (uint256 i; i < 5; ++i) {
            usd.faucet(alice, 1_000e6);
        }
        assertEq(usd.balanceOf(alice), 5_000e6); // the cap is per call
    }

    function test_faucet_zeroAddress_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InvalidReceiver.selector, address(0)));
        usd.faucet(address(0), 1);
    }

    function testFuzz_faucet(address to, uint256 amount) public {
        vm.assume(to != address(0));
        if (amount > 1_000e6) {
            vm.expectRevert(abi.encodeWithSelector(MockUSD.FaucetCapExceeded.selector, amount, 1_000e6));
            usd.faucet(to, amount);
        } else {
            usd.faucet(to, amount);
            assertEq(usd.balanceOf(to), amount);
            assertEq(usd.totalSupply(), amount);
        }
    }

    function test_transfer() public {
        usd.faucet(alice, 100e6);
        vm.expectEmit(true, true, false, true, address(usd));
        emit Transfer(alice, bob, 40e6);
        vm.prank(alice);
        assertTrue(usd.transfer(bob, 40e6));
        assertEq(usd.balanceOf(alice), 60e6);
        assertEq(usd.balanceOf(bob), 40e6);
        assertEq(usd.totalSupply(), 100e6);
    }

    function test_transfer_insufficient_reverts() public {
        usd.faucet(alice, 1e6);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, alice, 1e6, 1e6 + 1));
        usd.transfer(bob, 1e6 + 1);
    }

    function test_approveAndTransferFrom() public {
        usd.faucet(alice, 500e6);
        vm.expectEmit(true, true, false, true, address(usd));
        emit Approval(alice, bob, 200e6);
        vm.prank(alice);
        assertTrue(usd.approve(bob, 200e6));
        assertEq(usd.allowance(alice, bob), 200e6);

        vm.prank(bob);
        assertTrue(usd.transferFrom(alice, carol, 150e6));
        assertEq(usd.balanceOf(carol), 150e6);
        assertEq(usd.balanceOf(alice), 350e6);
        assertEq(usd.allowance(alice, bob), 50e6);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientAllowance.selector, bob, 50e6, 51e6));
        usd.transferFrom(alice, carol, 51e6);
    }

    function test_infiniteApproval_notDecremented() public {
        usd.faucet(alice, 10e6);
        vm.prank(alice);
        usd.approve(bob, type(uint256).max);
        vm.prank(bob);
        usd.transferFrom(alice, bob, 10e6);
        assertEq(usd.allowance(alice, bob), type(uint256).max);
    }

    function test_erc20TransferCalldata_matchesEnforcerDecoding() public {
        // what an agent sends through the delegation: transfer(address,uint256) = 0xa9059cbb, 68 bytes
        bytes memory cd = abi.encodeCall(IERC20.transfer, (bob, 1e6));
        assertEq(bytes4(cd), bytes4(0xa9059cbb));
        assertEq(cd.length, 68);
        usd.faucet(alice, 1e6);
        vm.prank(alice);
        (bool ok,) = address(usd).call(cd);
        assertTrue(ok);
        assertEq(usd.balanceOf(bob), 1e6);
    }

    function testFuzz_transfer(uint256 minted, uint256 sent) public {
        minted = bound(minted, 0, 1_000e6);
        sent = bound(sent, 0, minted);
        usd.faucet(alice, minted);
        vm.prank(alice);
        usd.transfer(bob, sent);
        assertEq(usd.balanceOf(alice), minted - sent);
        assertEq(usd.balanceOf(bob), sent);
        assertEq(usd.totalSupply(), minted);
    }
}
