## [L-01] Not returning excess ETH when updating price of Pyth Oracles
The [`PythOracle.getAndUpdatePrice() function`](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/oracles/PythOracle.sol#L59-L69) receives ETH, and the amount that is actually needed is computed during the execution by calling the `pyth.getUpdateFee() function`.
A user could send more eth than what it turns out to be necessary to update the price on the Pyth Oracle. The problem is that the function doesn't return the unspent ETH, and there is not way to pull that ETH from the PythOracle contract, thus, any excess ETH will get stuck in the contract.

**Fix:**
At the end of the execution, compute if is required to do any refunds, if so, send the unspent ETH to the caller.
```
function getAndUpdatePrice(
    bytes calldata priceUpdateData
) external payable returns (IOracle.Price memory) {
    ...
    _pyth.updatePriceFeeds{value: fee}(priceUpdates);

    //@audit => Mechanism to refund any unspent ETH
+   uint256 excessETH = msg.value - fee;
+   if(excessETH != 0) {
+       payable(msg.sender).call{value: excessETH}("");
+   }

    return _getPriceInternal(0);

}
```

## [L-02] Not enough Sanity checks to validate the data pulled from the Pyth Oracle
[Any sanity check is performed to the data pulled from the Pyth Oracle](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/oracles/PythOracle.sol#L38-L53). In case the Oracle returns wrong data, there is no way to sanitize it to prevent any impacts to the protocol's contracts.

**Fix:**
I'd recommend to sanitize the data pulled from the Pyth Oracle, specially the price and expo params.
I found a good implementation about sanitizing these parameters [on this contract](https://github.com/euler-xyz/euler-price-oracle/blob/eeb1847df7d9d58029de37225dabf963bf1a65e6/src/adapter/pyth/PythOracle.sol#L81-L84), this could give a clearer idea of how to sanitize these data.


## [L-03] Privileged functions on the StrategyLeverageSettings contract are callable only by the Governor instead of the Owner
The functions [`setMaxLoanToValue()`](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/strategies/StrategyLeverageSettings.sol#L84), [`setLoanToValue()`](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/strategies/StrategyLeverageSettings.sol#L116), [`setNrLoops()`](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/strategies/StrategyLeverageSettings.sol#L158) are protected with the `onlyGovernor` modifier. The inline comments on those functions states the caller must be the `owner` of the contract, not the governor.

Using the `onlyGovernor` modifier, those functions are only callable by the governor, which contradicts the inline comments.

**Fix:**
If the caller is really meant to be the owner, update the modifier to `onlyOwner`. 
If the inline comments are wrong, update them and state that the caller must be the governor.


## [L-04] Price updates made on the last not-stale block would be threated as if the price would already be stale, causign calls to revert because of `priceOutdated`.
When the [`StrategyLeverage._getPosition() function`](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/strategies/StrategyLeverage.sol#L453-L460) validates if the oracle's lastUpdate was made within a valid time range or not, the validation incorrectly excludes the last valid block on the time range. If the update was made on the last block, the check causes the tx to be reverted.

```
> StrategyLeverage.sol

    function _getPosition(
        uint256 priceMaxAge
    ) internal view returns (uint256 totalCollateralInEth, uint256 totalDebtInEth) {
        ...
    
        if (collateralBalance != 0) {            
            I...
            if (
                !(priceMaxAge == 0 ||
                //@audit-issue => Using `>=` operator would cause the price to be considered outdated if the lastUpdate was made on the block `block.timestamp - priceMaxAge`!
                    (priceMaxAge > 0 && (ethPrice.lastUpdate >= (block.timestamp - priceMaxAge))) ||
                    (priceMaxAge > 0 &&
                        (collateralPrice.lastUpdate >= (block.timestamp - priceMaxAge))))
            ) {
                revert PriceOutdated();
            }
            ...
        }
        ...
    }
```

**Fix:**
Update the `>=` operator to `>` operator to make sure that the last block is also considered a valid block before determining that the price is outdated.


## [L-05] Unnecessary approval of steth to uniRouter in the StrategyAAVEv3WSTETH contract.
When the [`StrategyAAVEv3WSTETH` is initialized](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/strategies/StrategyAAVEv3WSTETH.sol#L38-L57), it grants infinite approval to the UniRouter to spend stETH on its behalf.
The problem is that the StrategyAAVEv3WSTETH contract never really swaps stETH, it only swaps wsteth <=> weth, but never steth.

```
> StrategyAAVEv3WSTETH.sol

    function initializeWstETH(
        ...
    ) public initializer {
        ...
        //@audit-issue => Aproving the UniRouter infinite allowance for the stETH token.
        if (!stETH().approve(uniRouterA(), 2 ** 256 - 1)) revert FailedToApproveAllowance();
    }
```

**Fix:**
Remove the approval of stETH to the UniRouter, it is not required.


## [L-06] Contracts are incompatible with ERC20 on-fee transfer tokens
The current implementation is incompatible with tokens that charges fees on-transfer. 
If an on-fee token would be used in the contracts, the logic to take flashloan and repays them would be broken because the Strategy contracts won't have enough tokens to repay the flashloan.
The problem is that the current implementation doesn't compute the exact amount of tokens receiver for a transfer, the current implementation assumes that the received amount of tokens are exactly the same amount of tokens transferred.

**Fix:**
The fix for this problem to support ERC20 on-transfer is quite complex, it is not enough to compute exact amount of received tokens for a transfer, it would be also required to compute the amount of tokens to borrow as a flashloan, the exact amount of collateral that would need to be withdrawn from Aave to cover all the trasnfers that are executed as part of a deposit/withdraw/harvesting execution.

I think the most viable solution for now would be to limit the usage of the Strategy contracts to not use ERC20 on-fee transfer tokens.


## [L-07] Incorrect operator causes tx to revert when validating the value of loanToValue in calculateLeverageRatio() function
`loanToValue` could be set to be `PERCENTAGE_PRECISION`, if the `maxToLoan` is set as `PERCENTAGE_PRECISION`.
If `loanToValue` is set as `PERCENTAGE_PRECISION`, any call to [`UseLeverage.calculateLeverageRatio() function`](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/hooks/UseLeverage.sol#L19-L25) would revert because of incorrectly using the operator `>=`, which would cause tx to revert because `loanToValue` would be == `PERCENTAGE_PRECISION`.

```
> UseLeverage.sol

    function calculateLeverageRatio(
        ...
    ) public pure returns (uint256) {
       ...
       ///@audit-issue => If loanToValue is set as `PERCENTAGE_PRECISION`, tx would revert here!
        if (loanToValue == 0 || loanToValue >= PERCENTAGE_PRECISION) revert InvalidLoanToValue();
        ...
    }

```

**Fix:**
The fix is to update the operator `>=` for `>`


## [L-08] Not allowed to prevent liquidations by rebalancing the vault while vault is paused
User's funds are at risk in case of market turbulence that causes the loanToValue ratio to spike and the underlying debt on Aave to grow to a point where the Strategy's collateral could be liquidated.
If the vault is paused, and, it is necessary to rebalance the vault to prevent liquidations on Aave, the rebalance would revert because the [`Vault.rebalance() function`](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/Vault.sol#L130-L134) has the `whenNotPaused` modifier.

**Fix:**
I'd recommend to allow this function to be callable even if the contract is paused, in this way, any user can rebalance the vault and prevent any suddent unexpected liquidation on Aave.