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
    address public _origin = 0xE505051D14fcb647fb646886BF0Ebef3De80a54c;

    constructor() public {}

    function setTime() public view returns (address) {
        return
            address(
                uint160(
                    uint256(
                        keccak256(
                            abi.encodePacked(
                                bytes1(0xd6),
                                bytes1(0x94),
                                _origin,
                                bytes1(0x01)
                            )
                        )
                    )
                )
            );
    }
}
