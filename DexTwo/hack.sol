// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "./DexTwo.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v3.4.0/contracts/token/ERC20/IERC20.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v3.4.0/contracts/token/ERC20/ERC20.sol";

contract Test {
    constructor() public {}

    function balanceOf(address sender) public pure returns (uint256) {
        return 1;
    }

    function transferFrom(
        address sender,
        address getter,
        uint256 amount
    ) public pure returns (bool) {
        return true;
    }
}
