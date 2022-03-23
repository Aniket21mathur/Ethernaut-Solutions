// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "./hadcoins.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v3.4.0/contracts/token/ERC20/IERC20.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v3.4.0/contracts/token/ERC20/ERC20.sol";

contract Test {
    constructor() public {}

    function getAbi() public pure returns (bytes memory) {
        return abi.encodeWithSignature("forDestruction()");
    }

    function forDestruction() public {
        selfdestruct(payable(address(this)));
    }
}
