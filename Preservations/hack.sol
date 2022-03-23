// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

// import "./hadcoins.sol";

// The tx.origin global variable refers to the original external
// account that started the transaction while msg.sender refers to the
// immediate account (it could be external or another contract account)
// that invokes the function. The tx.origin variable will always refer to
// the external account while msg.sender can be a contract or external account.
// If there are multiple function invocations on multiple contracts,
// tx.origin will always refer to the account that started the transaction
// irrespective of the stack of contracts invoked

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
