// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title MockUSD
/// @notice TESTNET ONLY. A worthless demo stablecoin for the Ripar demo: 6 decimals (matching firmware/src/tokens.cpp)
///         and a public faucet anyone can call, at most 1,000 mUSD per call. No owner, no admin, no value.
///         Never deploy it on a mainnet.
contract MockUSD is ERC20 {
    /// @notice The most a single faucet call mints: 1,000 mUSD (6 decimals).
    uint256 public constant FAUCET_MAX = 1_000e6;

    /// @notice faucet() asked for more than FAUCET_MAX.
    error FaucetCapExceeded(uint256 amount, uint256 max);

    constructor() ERC20("MockUSD (Ripar demo)", "mUSD") { }

    /// @notice 6, like USDC / AUSD.
    function decimals() public pure override returns (uint8) {
        return 6;
    }

    /// @notice TESTNET ONLY: mints `amount` (base units, at most FAUCET_MAX) to `to`. Anyone may call, any number of
    ///         times.
    /// @param to     the recipient (not the zero address)
    /// @param amount base units to mint, at most 1_000e6
    function faucet(address to, uint256 amount) external {
        if (amount > FAUCET_MAX) revert FaucetCapExceeded(amount, FAUCET_MAX);
        _mint(to, amount);
    }
}
