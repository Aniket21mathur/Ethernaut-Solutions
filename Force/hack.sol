// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Test {
    address payable public owner;

    constructor() public {
        owner = msg.sender;
    }

    function selfDestroMe(address attackingContractAddress) public payable {
        address payable addr = payable(attackingContractAddress);
        selfdestruct(addr);
    }

    receive() external payable {}
}
