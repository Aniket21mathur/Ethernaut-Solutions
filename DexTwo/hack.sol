// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "./hadcoins.sol";
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

// await contract.swap("0xb19424ae78Ee74A6207E69B9e4D88a8A9c695E47", "0x96D050054b99c4682226F908F615E5DD00597bB9", 1)
// await contract.swap("0xb19424ae78Ee74A6207E69B9e4D88a8A9c695E47", "0x87Cc0a307378fE1Fc3683a547143508ce149c16d", 1)
