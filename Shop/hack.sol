// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "./hadcoins.sol";

contract Test {
    Shop public shp;
    uint256 counter = 0;

    constructor() public {
        shp = Shop(0xC0cfe0098085BB0b7206b40d3e7abD657E2183ab);
    }

    function price() external view returns (uint256) {
        bool sold = shp.isSold();
        if (!sold) return 100;
        else return 50;
    }

    function callBuy() public {
        shp.buy();
    }
}
