// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "./hadcoins.sol";

// The tx.origin global variable refers to the original external
// account that started the transaction while msg.sender refers to the
// immediate account (it could be external or another contract account)
// that invokes the function. The tx.origin variable will always refer to
// the external account while msg.sender can be a contract or external account.
// If there are multiple function invocations on multiple contracts,
// tx.origin will always refer to the account that started the transaction
// irrespective of the stack of contracts invoked
// import 'https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v3.0.0/contracts/token/ERC20/ERC20.sol';

contract Test {
    NaughtCoin public naughtCoin;

    constructor() public {
        naughtCoin = NaughtCoin(0x21fbaeE432a4C99837c086A10b525344FB80331B);
        naughtCoin.transfer(0x136801a295932bEcE62ef615bEFC3DE0259D565F, 0);
    }
}
