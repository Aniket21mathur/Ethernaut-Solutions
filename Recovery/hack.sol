// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Test {
    address public _origin = 0xE505051D14fcb647fb646886BF0Ebef3De80a54c;

    constructor() public {}

    function getContractAddress() public view returns (address) {
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
