---
sponsor: "BakerFi"
slug: "2024-05-bakerfi"
date: "2024-06-24"
title: "BakerFi Invitational"
findings: "https://github.com/code-423n4/2024-05-bakerfi-findings/issues"
contest: 378
---

# Overview

## About C4

Code4rena (C4) is an open organization consisting of security researchers, auditors, developers, and individuals with domain expertise in smart contracts.

A C4 audit is an event in which community participants, referred to as Wardens, review, audit, or analyze smart contract logic in exchange for a bounty provided by sponsoring projects.

During the audit outlined in this document, C4 conducted an analysis of the BakerFi smart contract system written in Solidity. The audit took place between May 20—June 3 2024.

## Wardens

In Code4rena's Invitational audits, the competition is limited to a small group of wardens; for this audit, 5 wardens contributed reports:

  1. [bin2chen](https://code4rena.com/@bin2chen)
  2. [rvierdiiev](https://code4rena.com/@rvierdiiev)
  3. [0xStalin](https://code4rena.com/@0xStalin)
  4. [t0x1c](https://code4rena.com/@t0x1c)
  5. [zhaojie](https://code4rena.com/@zhaojie)

This audit was judged by [0xleastwood](https://code4rena.com/@leastwood).

Final report assembled by [liveactionllama](https://twitter.com/liveactionllama).

# Summary

The C4 analysis yielded an aggregated total of 12 unique vulnerabilities. Of these vulnerabilities, 4 received a risk rating in the category of HIGH severity and 8 received a risk rating in the category of MEDIUM severity.

Additionally, C4 analysis included 3 reports detailing issues with a risk rating of LOW severity or non-critical.

All of the issues presented here are linked back to their original finding.

# Scope

The code under review can be found within the [C4 BakerFi audit repository](https://github.com/code-423n4/2024-05-bakerfi), and is composed of 33 smart contracts written in the Solidity programming language and includes 1,683 lines of Solidity code.

# Severity Criteria

C4 assesses the severity of disclosed vulnerabilities based on three primary risk categories: high, medium, and low/non-critical.

High-level considerations for vulnerabilities span the following key areas when conducting assessments:

- Malicious Input Handling
- Escalation of privileges
- Arithmetic
- Gas use

For more information regarding the severity criteria referenced throughout the submission review process, please refer to the documentation provided on [the C4 website](https://code4rena.com), specifically our section on [Severity Categorization](https://docs.code4rena.com/awarding/judging-criteria/severity-categorization).

# High Risk Findings (4)
## [[H-01] `ETHOracle.getLatestPrice` needs to convert to 18 decimals](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/47)
*Submitted by [bin2chen](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/47)*

In `ETHOracle.sol`, `getPrecision()` is defined as `10 ** 18`, but the actual oracle used is 8-decimals.

<https://data.chain.link/feeds/arbitrum/mainnet/eth-usd>

This data feeds' decimals is 8.

```solidity
/**
 *  ETH/USD Oracle using chainlink data feeds
 * 
 *  For more information about the feed go to 
@> *  https://data.chain.link/feeds/arbitrum/mainnet/eth-usd
 * 
 **/
contract ETHOracle is IOracle {
    IChainlinkAggregator private immutable _ethPriceFeed;
@>  uint256 private constant _PRECISION = 10 ** 18;
....
    function getLatestPrice() public view override returns (IOracle.Price memory price) {
        (, int256 answer, uint256 startedAt, uint256 updatedAt,) = _ethPriceFeed.latestRoundData();
        if ( answer<= 0 ) revert InvalidPriceFromOracle();        
        if ( startedAt ==0 || updatedAt == 0 ) revert InvalidPriceUpdatedAt();    

@>      price.price = uint256(answer);  //@audit 8 decimals
        price.lastUpdate = updatedAt;
    }
```

`PythOracle` is used to get prices for other tokens, also `getPrecision() == 18`.

```solidity
contract PythOracle is IOracle {
...
    uint256 private constant _PRECISION = 18;

    function _getPriceInternal(uint256 age) private view returns (IOracle.Price memory outPrice) {
        PythStructs.Price memory price = age == 0 ? 
            _pyth.getPriceUnsafe(_priceID): 
            _pyth.getPriceNoOlderThan(_priceID, age);

        if (price.expo >= 0) {
            outPrice.price =
                uint64(price.price) *
                uint256(10 ** (_PRECISION + uint32(price.expo)));
        } else {
            outPrice.price =
                uint64(price.price) *
                uint256(10 ** (_PRECISION - uint32(-price.expo)));
        }
        outPrice.lastUpdate = price.publishTime;
    }
```

Since a different precision is used, then the calculation of `totalCollateralInEth` at `StrategyLeverage` will be wrong.

```solidity
    function _getPosition(
        uint256 priceMaxAge
    ) internal view returns (uint256 totalCollateralInEth, uint256 totalDebtInEth) {
...
        totalCollateralInEth = 0;
        totalDebtInEth = 0;

        (uint256 collateralBalance,  uint256 debtBalance ) = _getMMPosition();
    
        if (collateralBalance != 0) {            
            IOracle.Price memory ethPrice = priceMaxAge == 0 ?
                _ethUSDOracle.getLatestPrice():
                _ethUSDOracle.getSafeLatestPrice(priceMaxAge);
            IOracle.Price memory collateralPrice = priceMaxAge == 0 ? 
                _collateralOracle.getLatestPrice():
                _collateralOracle.getSafeLatestPrice(priceMaxAge);
            if (
                !(priceMaxAge == 0 ||
                    (priceMaxAge > 0 && (ethPrice.lastUpdate >= (block.timestamp - priceMaxAge))) ||
                    (priceMaxAge > 0 &&
                        (collateralPrice.lastUpdate >= (block.timestamp - priceMaxAge))))
            ) {
                revert PriceOutdated();
            }
@>          totalCollateralInEth = (collateralBalance * collateralPrice.price) / ethPrice.price;
        }
        if (debtBalance != 0) {
            totalDebtInEth = debtBalance;
        }
    }
```

### Impact

Incorrect calculation of `totalCollateralInEth`, affecting borrowing judgment, e.g. overvaluation overborrowing, etc.

### Recommended Mitigation

Convert to 18 decimals.

**[hvasconcelos (BakerFi) confirmed](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/47#event-13081999578)**

**[ickas (BakerFi) commented](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/47#issuecomment-2167741709):**
 > Fixed → https://github.com/baker-fi/bakerfi-contracts/pull/40



***

## [[H-02] Vault is vulnerable to first depositor inflation attack](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/39)
*Submitted by [0xStalin](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/39), also found by [bin2chen](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/46) and [rvierdiiev](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/22)*

First depositor can manipulate the price of the shares at will, forcing new depositors to deposit more ETH for the same amount of shares that the first depositor paid.

### Proof of Concept

Before diving into the details of how this attack is performed, let's understand how the Vault determines the amount of shares to mint for a deposited amount of ETH.

1.  When doing a deposit, [the Vault creates a new variable of `Rebase` type by passing the resultant values of calling `_totalAssets()` and `totalSupply()` functions](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/Vault.sol#L203). By inspecting the `Rebase` struct, we know that the `totalAssets()` will be the `elastic` portion, and the `totalSupply()` will be the `base`. Or in other words:

*   `assets` are elastic
*   `shares` are the base

2.  Now, let's see what values are returned on each of the two functions that are called when the `total` variable of `Rebase` type is created.

*   [`_totalAssets()`](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/Vault.sol#L289-L291) represents the amount of assets owned by the strategy. By `own` it means the difference between the collateral value in ETH and all the WETH debt. For example, if the total collateral value in ETH is 100 ETH, and the total WETH debt is 70 WETH, then, the `totalAssets` would return 30 ETH. See below the exact code that is used to calculate the totalAssets:

```
> Vault.sol

function _totalAssets(uint256 priceMaxAge) private view returns (uint256 amount) {
    //@audit-info => totalAssets is difference between totalCollateralInETh - totalDebtInEth owned by the Strategy!
    amount = _strategy.deployed(priceMaxAge);
}

> StrategyLeverage.sol
function deployed(uint256 priceMaxAge) public view returns (uint256 totalOwnedAssets) {

    //@audit-info => totalCollateralInEth is the value of the aTokenCollateral owned by the Strategy worth in ETH
    //@audit-info => totalDebtInETH is the WETH debt in Aave that was taken to repay the flashloans used for leverage!
    (uint256 totalCollateralInEth, uint256 totalDebtInEth) = _getPosition(priceMaxAge);

    //@audit-info => The returned value from the `deployed()` is the difference between totalCollateralInETh -totalDebtInEth
    totalOwnedAssets = totalCollateralInEth > totalDebtInEth
        ? (totalCollateralInEth - totalDebtInEth)
        : 0;
}

function _getPosition(
    uint256 priceMaxAge
) internal view returns (uint256 totalCollateralInEth, uint256 totalDebtInEth) {
    totalCollateralInEth = 0;
    totalDebtInEth = 0;

    //@audit-info => debtBalance is the amount of WETH DebtToken owned by the Strategy contract!
    //@audit-info => collateralBalance is the amount of Collateral aToken owned by the Strategy contract
    (uint256 collateralBalance,  uint256 debtBalance ) = _getMMPosition();

    if (collateralBalance != 0) {            
        ...

        //@audit-info => Computes the value of the aTokenCollateral worth in ETH
        totalCollateralInEth = (collateralBalance * collateralPrice.price) / ethPrice.price;
    }
    if (debtBalance != 0) {
        totalDebtInEth = debtBalance;
    }
}

> StrategyAAVEv3.sol
function _getMMPosition() internal virtual override view returns ( uint256 collateralBalance, uint256 debtBalance ) {
    DataTypes.ReserveData memory wethReserve = (aaveV3().getReserveData(wETHA()));
    DataTypes.ReserveData memory colleteralReserve = (aaveV3().getReserveData(ierc20A()));

    //@audit-info => debtBalance is the amount of WETH DebtToken owned by the Strategy contract!
    debtBalance = IERC20(wethReserve.variableDebtTokenAddress).balanceOf(address(this));

    //@audit-info => collateralBalance is the amount of Collateral aToken owned by the Strategy contract
    collateralBalance = IERC20(colleteralReserve.aTokenAddress).balanceOf(
        address(this)
    );
}

```

*   `totalSupply()` represents all the existing shares that have been minted for all the deposits that have been made in the Vault.

3.  Then, the execution runs a couple of checks to verify that the `total` Rebase variable's state is correct, and then it proceeds to call the [`StrategyLeverage.deploy() function`](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/strategies/StrategyLeverage.sol#L236-L266), where it will do a leveraged deposit of the Strategy's collatelar (wstETH, rETH, cbETH) in Aave. To leverage the deposit, the Strategy requests a WETH flashloan on Balancer, swaps the borrowed and original deposit funds for collateral, deposits all the swapped collateral into Aave, and then it opens a WETH borrow for the exact amount to repay the flashloan to Balancer.

*   [The strategy returns to the vault the value in ETH of the funds that were deployed after the leverage.](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/strategies/StrategyLeverage.sol#L261)

4.  Finally, with the returned value of the [`StrategyLeverage.deploy() function`](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/strategies/StrategyLeverage.sol#L236-L266), the Vault computes the amount of shares to mint to the receiver for the deposited funds. [The formula that is used to determine the shares](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/Vault.sol#L223-L224) is `shares = (assets * totalSupply()) / totalAssets()`, where `assets` is the amount of collateral in ETH deployed after leverage.

```

    > Vault.sol

    function deposit(
        address receiver
    )
        ...
    {
        ...

        //@audit-info => Step 1, creates a variable of Rebase type by passing as parameters the totalAssets() and totalSupply() of the Vault!
        Rebase memory total = Rebase(_totalAssets(maxPriceAge), totalSupply());
        
        ...

        //@audit-info => Step 3, the deposited amount is deployed on the Strategy!
        bytes memory result = (address(_strategy)).functionCallWithValue(
            abi.encodeWithSignature("deploy()"),
            msg.value
        );

        uint256 amount = abi.decode(result, (uint256));

        //@audit-info => Step 4, Computes the amount of shares to mint for the amount that was deployed after leverage on the Strategy
        shares = total.toBase(amount, false);
        _mint(receiver, shares);
        emit Deposit(msg.sender, receiver, msg.value, shares);
    }
```

Now, time to analyze how the attack is performed:

1.  Alice is the first depositor in the Vault;
2.  **Alice deposits 10 wei of ETH**
3.  **Since Alice is the first depositor (totalSupply is 0 && totalAssets is 0), she gets 10 weis of a share (10 wei)**
4.  **Alice then sends 99999999999999999999 (100e18 - 1) aCollateralToken to the Strategy**; Where `aCollateralToken` is the aToken that Aave mints when the strategy deploys/supplies collateral to it.

*   **There are now 10 weis of shares and a total of 100e18 aCollateralToken as totalAssets**: Alice is the only depositor in the vault, she's holding 10 weis of shares, and the `totalAssets` is 100e18 aCollateralToken. For ease of calculations, suppose collateral per ETH is 1:1.

5.  **Bob deposits 19 ETH and gets only 1 share** due to the rounding down in the calculation to compute the shares: `19e18 * 10 / 100e18 == 10;`
6.  **Each Share will redeem**: `totalAssets / totalShares` == 119e18 / 11 => **10.81e18 ETH in aCollateralToken**
7.  **The 10 wei of shares owned by Alice can claim: 108.1e18 ETH**. Meaning, Alice can steal \~8 ETH from Bob's deposit.
8.  **The 1 wei of Shares owned by Bob can only claim: 10.81 ETH**. Meaning, Bob automatically lost \~8 ETH from the 19 ETH he just deposited.

The root cause that makes this attack possible is that the Vault's shares and assets are not initialized/seeded when the Vault is created & the fact that the totalAssets is dependant on the total aCollateralTokens the associated Strategy to the Vault is holding on its balance.

*   This allows an attacker to inflate the share-assets rate by transfering aCollateralToken directly to the Strategy. By doing this direct transfer, those aCollateralTokens will inflate the rate of the initial deposit made by the attacker, causing real depositors to deposit at an inflated rate, from which an attacker will profit by withdrawing the initial shares he minted for himself and withdrawing all his deposited (and direct transfered) aCollateralTokens + a portion of the deposited value from real depositors.

### Recommended Mitigation Steps

Consider either of these options:

*   Consider seeding the pools during deployment. This needs to be done in the deployment transactions to avoiding front-running attacks. The amount needs to be high enough to reduce the rounding error.
*   Consider sending first 1000 wei of shares to the zero address. This will significantly increase the cost of the attack by forcing an attacker to pay 1000 times of the share price they want to set. For a well-intended user, 1000 wei of shares is a negligible amount that won't diminish their share significantly.
*   Implement the concept of [virtual shares, similar to the ERC4626 OZ contract](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/extensions/ERC4626.sol#L30-L37). [More info about this concept here](https://docs.openzeppelin.com/contracts/4.x/erc4626#defending_with_a_virtual_offset).

**[hvasconcelos (BakerFi) confirmed](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/39#event-13082007649)**

**[ickas (BakerFi) commented](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/39#issuecomment-2168303642):**
 > Fixed → https://github.com/baker-fi/bakerfi-contracts/pull/45



***

## [[H-03] When harvesting a strategy and adjusting the debt, all the leftover collateral that is not used to swap the withdrawn collateral from Aave for WETH to repay the flashloan will be locked and lost in the Strategy contract](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/38)
*Submitted by [0xStalin](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/38), also found by [bin2chen](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/34) and [rvierdiiev](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/3)*

### Impact

Collateral can be locked and lost in the Strategy contract.

### Proof of Concept

When harvesting a strategy and adjusting the debt to maintain the loan to value of the strategy, the strategy does the following steps:

1.  Computes the deltaDebt required to readjust the loan to value within the accepted boundaries.
2.  Takes a WETH flashloan on Balancer for the exact deltaDebt amount.
3.  Repays WETH on Aave for the exact amount that was flashloaned borrowed on Balancer.
4.  Uses the UniQuoterV2 to compute the amount of collateral needed to repay the flashloan (including the flashloan fees).
5.  Withdraws collateral from Aave for exact amount computed by the UniQuoterV2.
6.  Does an `EXACT_OUTPUT` swap on Uniswap. It requests to receive the exact `debtAmount + fees` (to repay the flashloan) in exchange for at most the withdrawn amount of collateral from Aave.
7.  Does a couple of extra checks and finally the flashloan is repaid.

The problem identified on this report is caused due to some issues in the steps 4 & 6. Let's dive into it.

The ***first part of the problem*** is caused due to how the UniQuoter is invoked. [The `fee` of the pool that is sent to the UniQuoter is hardcoded to be `500`](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/strategies/StrategyLeverage.sol#L545-L547), which represents a pool of (0.05\% fee). This can cause two problems:

1.  The execution can be reverted if there is not an existing pool for the COLLATERAL/WETH at a 0.05\% fee. The UniQuoter will receive the call and will derive the address of the pool based on the tokenIn, tokenOut and fee. **If there is not a pool for the 0.05\% fee (500), the call will be reverted and the whole harvesting execution will blown up.**

2.  The second problem is when the `swapFeeTier` is different than 500, or in other words, that the fee of the UniPool that is configured for the strategy is different than 500 (0.05\%), for example, if the strategy is configured to work with a pool with a fee of 0.01\% (100).

*   In this case, the execution won't revert, but the computed amount will be bigger than what is really required. For example:
    *   The `debtAmount + fee` to repay the flashloan is 100WETH.
    *   The UniQuoter will compute how much collateral is required to get 100WETH by swapping the collateral on a UniPool with a 0.05\% fee. to make calculations easier, assume collateral and weth have a 1:1 conversion.
        *   100 collateral + 0.05\% fee charged by the pool ===> 100 + 0.5 ===> 100.5 Collateral.
    *   Then, the execution will withdraw from Aave the computed amount by the UniQutoer (100.5).
    *   Now, once the Strategy has the 100.5 collateral on its balance, the execution will do a swap requesting 100 WETH to repay the flashloan. When requesting the swap, the fees of the pool where the swap will be actually executed is set by using the `swapFeeTier`. Assume the Strategy is configured to work with the UniPool with the lowest fee available (0.01\%).
        *   To do an `EXACT_OUTPUT` swap on a pool with 0.01\% fee for 100 WETH, the required amount of tokenIn (collateral) will be:
            *   100 WETH + 0.01\% fee charged by the pool ===> 100 + 0.1 ===> 100.1 Collateral.
        *   This means, **after doing the swap for WETH to repay the flashloan, the Strategy will have on its balance a total of 0.4 leftover collateral that was not used during the swap.**

[`StrategyLeverage._payDebt() function`](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/strategies/StrategyLeverage.sol#L542-L568)

```
    function _payDebt(uint256 debtAmount, uint256 fee) internal {
      ...

      // Get a Quote to know how much collateral i require to pay debt
      (uint256 amountIn, , , ) = uniQuoter().quoteExactOutputSingle(
          //@audit-issue => The computed `amountIn` is based on a pool with fees of 0.05%!
          IQuoterV2.QuoteExactOutputSingleParams(ierc20A(), wETHA(), debtAmount + fee, 500, 0)
      );    
      
      //@audit-info => Withdraws the exact computed `amountIn` by the UniQuoter
      _withdraw(ierc20A(), amountIn, address(this) );

      uint256 output = _swap(
          ISwapHandler.SwapParams(
              ierc20A(),
              wETHA(),
              ISwapHandler.SwapType.EXACT_OUTPUT,
              amountIn,
              debtAmount + fee,
              //@audit-info => The swap is performed on a pool with this fees
              //@audit-issue => When this value is lower than 500 (Using a pool with a lower fee), not all the withdrawn collateral will be used for the swap!
              _swapFeeTier,
              bytes("")
          )
      );
      ...
    }
```

Now comes the ***second part of the problem***, [the Strategy checks if there is any leftover collateral after the swap, and if there is any, it does a self transfer for the leftover amount](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/hooks/UseSwapper.sol#L95-L97). This can cause one of these two problems:

1.  The most problematic is that the leftover collateral will simply be left in the Strategy, it won't be re-supplied to Aave, neither pull out of the Strategy, it will be simply left in the Strategy's balance, from where it will be irrecoverable. Meaning, the leftover collateral will be locked in the Strategy contract.

2.  Depending on the Collateral's contract, there are some ERC20s that reverts the execution if they receive a self-transfer of tokens.

[`UseSwapper._swap() function`](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/hooks/UseSwapper.sol#L57-L101)

```
    function _swap(
        ISwapHandler.SwapParams memory params
    ) internal override returns (uint256 amountOut) {
        ...

        // Exact Input
        if (params.mode == ISwapHandler.SwapType.EXACT_INPUT) {
            ...
            // Exact Output
        } else if (params.mode == ISwapHandler.SwapType.EXACT_OUTPUT) {
          //@audit-info => Does an EXACT_OUTPUT swap
          //@audit-info => `amountIn` represents the exact amount of collateral that was required to swap the requested amount of WETH to repay the flashloan!
            uint256 amountIn = _uniRouter.exactOutputSingle(
                IV3SwapRouter.ExactOutputSingleParams({
                    tokenIn: params.underlyingIn,
                    tokenOut: params.underlyingOut,
                    fee: fee,
                    recipient: address(this),
                    amountOut: params.amountOut,
                    amountInMaximum: params.amountIn,
                    sqrtPriceLimitX96: 0
                })
            );
          
          //@audit-issue => Self transfering the leftover collateral after the swap. This leftover collateral will be left in the Strategy's balance, causing it to be unnusable.
            if (amountIn < params.amountIn) {
                IERC20(params.underlyingIn).safeTransfer(address(this), params.amountIn - amountIn);
            }
            
            ...
        }
    }
```

To recapitulate the most important points, the biggest impact because of the two problems on steps 4 & 6 is when the UniPool configured for the strategy uses a lower fee than 0.05\% (500). In this case, the leftover collateral after doing the `EXACT_OUTPUT` swap for the required amount of WETH to repay the flashloan will be left and locked in the Strategy.

### Tools Used

Manual Audit, [Uniswap Pool's Explorer](https://app.uniswap.org/explore/pools/ethereum?chain=mainnet), & [UniV2Quoter contract](https://github.com/Uniswap/v3-periphery/blob/main/contracts/lens/QuoterV2.sol#L197-L228)

### Recommended Mitigation Steps

To address this problem, I'd recommend to apply the two below suggestions.

1.  Do not set a hardcoded value for the pool fee when calling the UniQuoter, instead, send the same value of the configured pool (`swapFeeTier`).
2.  Instead of doing the self transfer of the leftover collateral after the swap, opt to re-supply it to Aave. In this way, that leftover collateral can still be managed by the Strategy.

**[0xleastwood (judge) decreased severity to Medium and commented](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/38#issuecomment-2166514308):**
 > This seems to predominantly impact yield in two ways:
> - Harvest function fails to be callable, but users can still withdraw collateral.
> - Harvest does not fail but there is some value leakage that happens over time.
> 
> Neither of these impact user's funds directly so `medium` severity seems right.

**[0xStalin (warden) commented](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/38#issuecomment-2166958207):**
 > Hello Judge @0xleastwood - I'd like to clarify the second point raised in your comment to downgrade the severity of this report to medium:<br>
> 
> > Harvest does not fail but there is some value leakage that happens over time.<br>
> Neither of these impact user's funds directly so medium severity seems right.
> 
> Actually, when harvest does not fail, and causes the leftover collateral to be left sitting on the protocol, those funds are actually the funds deposited by the users. While it is true that the leakage happens over time, those funds are user funds, not only yield.
> 
> I'd like to ask if you could take a second look at your verdict for the severity of this report and if you would consider re-assigning the original severity based on this clarification.

**[0xleastwood (judge) increased severity to Medium and commented](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/38#issuecomment-2182020097):**
 > @0xStalin - I see what you mean, even though the amount is somewhat on the smaller side, a debt adjustment will leave some excess collateral stuck as it rebalances to maintain a target LTV.

**[hvasconcelos (BakerFi) confirmed](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/38#event-13239505929)**

**[ickas (BakerFi) commented](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/38#issuecomment-2167784451):**
 > Fixed → https://github.com/baker-fi/bakerfi-contracts/pull/42



***

## [[H-04] Multiple swap lack slippage protection](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/32)
*Submitted by [bin2chen](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/32), also found by [bin2chen](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/48), [0xStalin](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/44), [rvierdiiev](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/26), and [t0x1c](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/17)*

The current protocol requires swapping tokens in multiple places, such as `weth -> ierc20A` or `ierc20A -> weth`.

Primarily, these swaps are executed using the `_swap()` method.

```solidity
    function _swap(
        ISwapHandler.SwapParams memory params
    ) internal override returns (uint256 amountOut) {
        if (params.underlyingIn == address(0)) revert InvalidInputToken();
        if (params.underlyingOut == address(0)) revert InvalidOutputToken();
        uint24 fee = params.feeTier;
        if (fee == 0) revert InvalidFeeTier();

        // Exact Input
        if (params.mode == ISwapHandler.SwapType.EXACT_INPUT) {
            amountOut = _uniRouter.exactInputSingle(
                IV3SwapRouter.ExactInputSingleParams({
                    tokenIn: params.underlyingIn,
                    tokenOut: params.underlyingOut,
                    amountIn: params.amountIn,
@>                  amountOutMinimum: 0,   //@audit miss set params.amountOut
                    fee: fee,
                    recipient: address(this),
                    sqrtPriceLimitX96: 0
                })
            );
            if (amountOut == 0) {
                revert SwapFailed();
            }
            emit Swap(params.underlyingIn, params.underlyingOut, params.amountIn, amountOut);
            // Exact Output
        } else if (params.mode == ISwapHandler.SwapType.EXACT_OUTPUT) {
            uint256 amountIn = _uniRouter.exactOutputSingle(
                IV3SwapRouter.ExactOutputSingleParams({
                    tokenIn: params.underlyingIn,
                    tokenOut: params.underlyingOut,
                    fee: fee,
                    recipient: address(this),
                    amountOut: params.amountOut,
                    amountInMaximum: params.amountIn,
                    sqrtPriceLimitX96: 0
                })
            );
            if (amountIn < params.amountIn) {
                IERC20(params.underlyingIn).safeTransfer(address(this), params.amountIn - amountIn);
            }
            emit Swap(params.underlyingIn, params.underlyingOut, amountIn, params.amountOut);
            amountOut = params.amountOut;
        }
    }
```

This method does not set `amountOutMinimum`.

And when call same miss set `Amount Out`.

```solidity
abstract contract StrategyLeverage is
    function _convertFromWETH(uint256 amount) internal virtual returns (uint256) {
        // 1. Swap WETH -> cbETH/wstETH/rETH
        return
            _swap(
                ISwapHandler.SwapParams(
                    wETHA(), // Asset In
                    ierc20A(), // Asset Out
                    ISwapHandler.SwapType.EXACT_INPUT, // Swap Mode
                    amount, // Amount In
                    //@audit miss slippage protection
@>                  0, // Amount Out 
                    _swapFeeTier, // Fee Pair Tier
                    bytes("") // User Payload
                )
            );
    }
```

These methods do not have slippage protection.

<https://docs.uniswap.org/contracts/v3/guides/swaps/single-swaps>

> amountOutMinimum: we are setting to zero, but this is a significant risk in production. For a real deployment, this value should be calculated using our SDK or an onchain price oracle - this helps protect against getting an unusually bad price for a trade due to a front running sandwich or another type of price manipulation

Include：`UseSwapper._swap()`/ `_convertFromWETH()`/`_convertToWETH()`/`_payDebt()`

### Impact

Front running sandwich or another type of price manipulation.

### Recommended Mitigation

1.  `_swap()` need set `amountOutMinimum = params.amountOut`

```diff
    function _swap(
        ISwapHandler.SwapParams memory params
    ) internal override returns (uint256 amountOut) {
        if (params.underlyingIn == address(0)) revert InvalidInputToken();
        if (params.underlyingOut == address(0)) revert InvalidOutputToken();
        uint24 fee = params.feeTier;
        if (fee == 0) revert InvalidFeeTier();

        // Exact Input
        if (params.mode == ISwapHandler.SwapType.EXACT_INPUT) {
            amountOut = _uniRouter.exactInputSingle(
                IV3SwapRouter.ExactInputSingleParams({
                    tokenIn: params.underlyingIn,
                    tokenOut: params.underlyingOut,
                    amountIn: params.amountIn,
-                   amountOutMinimum: 0,
+                  amountOutMinimum: params.amountOut
                    fee: fee,
                    recipient: address(this),
                    sqrtPriceLimitX96: 0
                })
            );
            if (amountOut == 0) {
                revert SwapFailed();
            }
```

2.  Call `_swap()` need set `params.amountOut` calculating the allowed slippage value accurately.

**[hvasconcelos (BakerFi) confirmed](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/32#event-13082084164)**

**[ickas (BakerFi) commented](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/32#issuecomment-2167742316):**
 > Fixed → https://github.com/baker-fi/bakerfi-contracts/pull/41



***

 
# Medium Risk Findings (8)
## [[M-01] All supplied WETH to Aave as a deposit by a Strategy will be irrecoverable](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/41)
*Submitted by [0xStalin](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/41), also found by [zhaojie](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/28)*

### Impact

WETH supplied to Aave will be lost.

### Proof of Concept

When a strategy pays debt on Aave it does a swap of the withdrawn collateral from Aave in exchange for WETH. After the swap is completed, it checks [if there are any weth leftovers after the swap, if so, it deposits them back](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/strategies/StrategyLeverage.sol#L562-L566). The problem with this approach is that the strategy doesn't have any means to pull WETH out of Aave, the strategy is only capable of withdrawing the collateral from Aave, but not WETH.

```
    function _payDebt(uint256 debtAmount, uint256 fee) internal {
      ...

      //@audit-info => output represents the received amount of WETH for the swap
      uint256 output = _swap(
          ISwapHandler.SwapParams(
              ierc20A(),
              wETHA(),
              ISwapHandler.SwapType.EXACT_OUTPUT,
              amountIn,
              debtAmount + fee,
              _swapFeeTier,
              bytes("")
          )
      );

      //@audit-info => Checks if there are any WETH leftovers
      // When there are leftovers from the swap, deposit then back
      uint256 wethLefts = output > (debtAmount + fee) ? output - (debtAmount + fee) : 0;

      //@audit-issue => If any leftover WETH, it deposits them onto Aave!
      //@audit-issue => Once the WETH is deposited in Aave, the Strategy won't be able to pull it out.
      if (wethLefts > 0) {
          _supply(wETHA(), wethLefts);
      }
      emit StrategyUndeploy(msg.sender, debtAmount);
    }
```

The strategy uses the [`StrategyAAVEv3._withdraw() function`](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/strategies/StrategyAAVEv3.sol#L126-L129) to withdraw an asset from Aave, but, in the places where this function is called, the only assets requested to be withdrawn is the Collateral.

*   in the [`StrategyLeverage._payDebt()`](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/strategies/StrategyLeverage.sol#L549)
*   in the [`StrategyLeverage._repayAndWithdraw()`](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/strategies/StrategyLeverage.sol#L701)

### Recommended Mitigation Steps

Instead of supplying the `wethLefts`, use the excess WETH to repay more WETH debt on Aave, in this way, those extra WETHs won't be lost on Aave because the strategy doesn't have any means to withdraw them.

*   By using the extra WETH to repay more debt, the loan to value is brought down even to a healthier level.

```
    function _payDebt(uint256 debtAmount, uint256 fee) internal {
      ...
      ...
      ...

      //@audit => Instead of supplying WETH to Aave, use it to repay more debt
      if (wethLefts > 0) {
    -     _supply(wETHA(), wethLefts);
    +     _repay(wETHA(), wethLefts);
      }
      emit StrategyUndeploy(msg.sender, debtAmount);
    }
```

**[hvasconcelos (BakerFi) confirmed](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/41#event-13082103117)**

**[ickas (BakerFi) commented](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/41#issuecomment-2176097220):**
 > Fixed → https://github.com/baker-fi/bakerfi-contracts/pull/42



***

## [[M-02] Vault can be DoS](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/37)
*Submitted by [zhaojie](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/37), also found by [0xStalin](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/43) and [rvierdiiev](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/23)*

### Impact

When `totalSupply = 0`, the attacker donates 1wei token, causing the number of shares to remain 0 at deposit time.

### Proof of Concept

The `toBase` function only determines whether `total.elastic(_totalAssets)` is 0, not whether `totalSupply` is 0.

```solidity
    function toBase(Rebase memory total, uint256 elastic,bool roundUp
    ) internal pure returns (uint256 base) {
@       if (total.elastic == 0) {
            base = elastic;
        } else {
            //total.base = totalSupply ; total.elastic = _totalAssets
            base = (elastic * total.base) / total.elastic;
            if (roundUp && (base * total.elastic) / total.base < elastic) {
                base++;
            }
        }
    }
```

When `totalSupply=0`, if `_totalAssets > 0`, `toBase` always returns 0.

An attacker can make a donation of `_totalAssets > 0`, the `toBase` function will then compute base through a branch in the else statement, since `totalSupply=0`.
`base = 0 * elastic / total.elastic = 0`,

As a result, the number of deposit shares is always 0, and the protocol will not work.

```solidity
    function deposit(address receiver) ....{
        .....
        shares = total.toBase(amount, false);
        _mint(receiver, shares);
        emit Deposit(msg.sender, receiver, msg.value, shares);
    }
```

An attacker can send Collateral token to the `StrategyAAVEv3(address(this))` contract,

`_totalAssets = collateralBalance - debtBalance`

```solidity
    function _getMMPosition() internal virtual override view returns ( uint256 collateralBalance, uint256 debtBalance ) {
        DataTypes.ReserveData memory wethReserve = (aaveV3().getReserveData(wETHA()));
        DataTypes.ReserveData memory colleteralReserve = (aaveV3().getReserveData(ierc20A()));
        debtBalance = IERC20(wethReserve.variableDebtTokenAddress).balanceOf(address(this));
        collateralBalance = IERC20(colleteralReserve.aTokenAddress).balanceOf(address(this));
    }
```

### Tools Used

VSCode, Manual

### Recommended Mitigation Steps

```diff
    function toBase(Rebase memory total, uint256 elastic,bool roundUp
    ) internal pure returns (uint256 base) {
-        if (total.elastic == 0) {
+        if (total.elastic == 0 || total.base == 0) {
            base = elastic;
        } else {
            //total.base = totalSupply ; total.elastic = _totalAssets
            base = (elastic * total.base) / total.elastic;
            if (roundUp && (base * total.elastic) / total.base < elastic) {
                base++;
            }
        }
    }
```

**[hvasconcelos (BakerFi) confirmed](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/37#event-13082012690)**

**[0xleastwood (judge) decreased severity to Medium and commented](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/37#issuecomment-2161802494):**
 > Thinking about this more, continuous DoS of vault deployment only lasts until it is fixed and does not seem to have any impact on user funds. Downgrading to `medium` severity.

**[ickas (BakerFi) commented](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/37#issuecomment-2167841018):**
 > Fixed → https://github.com/baker-fi/bakerfi-contracts/pull/44



***

## [[M-03] `StrategyLeverage.harvest` doesn't account flashloan fee](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/36)
*Submitted by [rvierdiiev](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/36)*

`StrategyLeverage.harvest` function checks position state. In case if position LTV is bigger than max LTV, then [extra debt is repaid](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/strategies/StrategyLeverage.sol#L395) to decrease LTV back to normal.

In order to repay part of debt, flashloan is taken and contract [should pay fee for it](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/strategies/StrategyLeverage.sol#L342).

So overall after adjusting our debt is decreased with `deltaDebt` but our collateral is decreased with `deltaDebt + fee`.

The problem is that this is not reflected in the [`newDeployedAmount` calculation](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/strategies/StrategyLeverage.sol#L397-L399) as it thinks that both collateral and debt were decreased by `deltaDebt`.

As result of this, `newDeployedAmount` is bigger than it is in reality (in reality it is `newDeployedAmount - fee`), which means that later when some profit accrued, protocol [may not receive it](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/strategies/StrategyLeverage.sol#L408-L416). For example if `profit is < fee`, then protocol won't receive it and if `profit is > fee`, then protocol will receive management fee based on `profit - fee` amount.

### Impact

Protocol may receive smaller amount of fees.

### Tools Used

VsCode

### Recommended Mitigation Steps

Make `_adjustDebt` returns `fee` as well and use it to decrease collateral.

**[hvasconcelos (BakerFi) confirmed](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/36#event-13082109842)**

**[ickas (BakerFi) commented](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/36#issuecomment-2173146433):**
 > Fixed → https://github.com/baker-fi/bakerfi-contracts/pull/48



***

## [[M-04] `deposit()` `afterDeposit` calculation formula is incorrect](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/29)
*Submitted by [bin2chen](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/29), also found by [bin2chen](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/30), [0xStalin](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/40), [rvierdiiev](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/20), and [zhaojie](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/8)*

In `Vault.deposit()`, we will limit the user's maximum deposit cannot exceed `settings().getMaxDepositInETH()`.

```solidity
    function deposit(
        address receiver
    )
        external
        payable
        override
        nonReentrant
        whenNotPaused
        onlyWhiteListed
        returns (uint256 shares)
    {
        if (msg.value == 0) revert InvalidDepositAmount();
        uint256 maxPriceAge = settings().getPriceMaxAge();
        Rebase memory total = Rebase(_totalAssets(maxPriceAge), totalSupply());
        if (
            // Or the Rebase is unititialized
            !((total.elastic == 0 && total.base == 0) ||
                // Or Both are positive
                (total.base > 0 && total.elastic > 0))
        ) revert InvalidAssetsState();
        // Verify if the Deposit Value exceeds the maximum per wallet
        uint256 maxDeposit = settings().getMaxDepositInETH();
        if (maxDeposit > 0) {
            uint256 afterDeposit = msg.value +
@>              ((balanceOf(msg.sender) * _tokenPerETH(maxPriceAge)) / 1e18);
            if (afterDeposit > maxDeposit) revert MaxDepositReached();
        }

....


    function _tokenPerETH(uint256 priceMaxAge) internal view returns (uint256) {
        uint256 position = _totalAssets(priceMaxAge);
        if (totalSupply() == 0 || position == 0) {
            return 1 ether;
        }
@>      return (totalSupply() * 1 ether) / position;
    }
```

The code above uses `(balanceOf(msg.sender) * _tokenPerETH(maxPriceAge) / 1e18` to calculate the current ETH deposit.

Based on the definition of the `_tokenPerETH()` method, this formula is incorrect.

It should be `balanceOf(msg.sender) * 1e18 / _tokenPerETH(maxPriceAge)`.

### Impact

An incorrect calculation formula can result in exceeding `getMaxDepositInETH` or prematurely triggering a `MaxDepositReached` revert. Users may not be able to deposit properly.

### Recommended Mitigation

```diff
    function deposit(
        address receiver
    )
...
        // Verify if the Deposit Value exceeds the maximum per wallet
        uint256 maxDeposit = settings().getMaxDepositInETH();
        if (maxDeposit > 0) {
            uint256 afterDeposit = msg.value +
-               ((balanceOf(msg.sender) * _tokenPerETH(maxPriceAge)) / 1e18);
+               ((balanceOf(msg.sender) * 1e18) / _tokenPerETH(maxPriceAge));
            if (afterDeposit > maxDeposit) revert MaxDepositReached();
        }
```

**[hvasconcelos (BakerFi) confirmed](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/29#event-13082145261)**

**[ickas (BakerFi) commented](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/29#issuecomment-2173175101):**
 > Fixed → https://github.com/baker-fi/bakerfi-contracts/pull/49



***

## [[M-05] Protocol receives less harvest fees](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/21)
*Submitted by [rvierdiiev](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/21)*

In case position has grown, then protocol receives performance fee.

<https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/Vault.sol#L153-L158>

```solidity
                    uint256 feeInEthScaled = uint256(balanceChange) *
                        settings().getPerformanceFee();
                    uint256 sharesToMint = (feeInEthScaled * totalSupply()) /
                        _totalAssets(maxPriceAge) /
                        PERCENTAGE_PRECISION;
                    _mint(settings().getFeeReceiver(), sharesToMint);
```

We will check how shares amount is calculated and why it's less than it should be.

Suppose that `totalSupply() == 100000` and `_totalAssets(maxPriceAge) == 100100`, so we earned 100 eth as additional profit. `balanceChange == 100` and performance fee is 10\%, which is 10 eth.

`sharesToMint = 10 * 100000 / 100100 = 9.99001`

This means that with `9.990001` shares protocol should be able to grab 10 eth fee, which is indeed like that if we convert `9.99001 * 100100 / 100000 = 10`.

The problem is that minting is done later, which means that `totalSupply()` will increase with `9.99001` shares. So if we calculate fees amount now we will get a smaller amount: `9.99001 * 100100 / 100009.99001 = 9.999001`

### Impact

Protocol receives smaller amount of fees.

### Tools Used

VsCode

### Recommended Mitigation Steps

The formula should be adjusted to count increase of total supply.

**[hvasconcelos (BakerFi) acknowledged](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/21#event-13082152004)**



***

## [[M-06] Min and maxAnswer never checked for oracle price feed](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/16)
*Submitted by [t0x1c](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/16)*

Chainlink aggregators have a built-in circuit breaker if the price of an asset goes outside of a predetermined price band. The result is that if an asset experiences a huge drop in value (i.e. LUNA crash) the price of the oracle will continue to return the minPrice instead of the actual price of the asset. This would allow user to continue borrowing with the asset but at the wrong price. This is exactly what happened to [Venus on BSC when LUNA imploded](https://rekt.news/venus-blizz-rekt/). However, the protocol misses to implement such a check.

[Link to code](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/oracles/EthOracle.sol#L31):

```js
    function getLatestPrice() public view override returns (IOracle.Price memory price) {
@-->    (, int256 answer, uint256 startedAt, uint256 updatedAt,) = _ethPriceFeed.latestRoundData();
        if ( answer<= 0 ) revert InvalidPriceFromOracle();        
        if ( startedAt ==0 || updatedAt == 0 ) revert InvalidPriceUpdatedAt();    

        price.price = uint256(answer);
        price.lastUpdate = updatedAt;
    }
```

### Similar past issues

*   [Risk of Incorrect Asset Pricing by StableOracle in Case of Underlying Aggregator Reaching minAnswer](https://github.com/sherlock-audit/2023-05-USSD-judging/issues/598)
*   [ChainlinkAdapterOracle will return the wrong price for asset if underlying aggregator hits minAnswer](https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/18)

### Recommended Mitigation Steps

Add logic along the lines of:

```js
    require(answer >= minPrice && answer <= maxPrice, "invalid price");
```

Min and max prices can be gathered using [one of these ways](https://medium.com/cyfrin/chainlink-oracle-defi-attacks-93b6cb6541bf#99af:\~:text=Developers%20%26%20Auditors%20can%20find%20Chainlink%E2%80%99s%20oracle%20feed).

**[hvasconcelos (BakerFi) confirmed](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/16#event-13082176790)**

**[ickas (BakerFi) commented](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/16#issuecomment-2168492073):**
 > Fixed → https://github.com/baker-fi/bakerfi-contracts/pull/46



***

## [[M-07] Rounding-down of `flashFee` can result in calls to flash loan to revert](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/11)
*Submitted by [t0x1c](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/11), also found by [bin2chen](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/31)*

The [BalancerFlashLender::flashFee()](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/flashloan/BalancerFlashLender.sol#L63) function returns a rounded-down fee. This `fee` is then [later used](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/strategies/StrategyLeverage.sol#L247-L249) across the protocol while providing spend approval to the flash loan provider. This can result in an approval less than that expected by the provider and hence cause the call to flash loan to revert. This is because [flash loan providers calculate their fee by rounding up in their favour](https://docs.uniswap.org/contracts/v2/guides/smart-contract-integration/using-flash-swaps#single-token), instead of rounding down:

```js
File: contracts/core/flashloan/BalancerFlashLender.sol

    function flashFee(address, uint256 amount) external view override returns (uint256) {
        uint256 perc = _balancerVault.getProtocolFeesCollector().getFlashLoanFeePercentage();
        if (perc == 0 || amount == 0) {
            return 0;
        }

@--->   return (amount * perc) / _BALANCER_MAX_FEE_PERCENTAGE;
    }
```

and

```js
File: contracts/core/strategies/StrategyLeverage.sol

    function deploy() external payable onlyOwner nonReentrant returns (uint256 deployedAmount) {
        if (msg.value == 0) revert InvalidDeployAmount();
        // 1. Wrap Ethereum
        address(wETHA()).functionCallWithValue(abi.encodeWithSignature("deposit()"), msg.value);
        // 2. Initiate a WETH Flash Loan
        uint256 leverage = calculateLeverageRatio(
            msg.value,
            getLoanToValue(),
            getNrLoops()
        );
        uint256 loanAmount = leverage - msg.value;
@--->   uint256 fee = flashLender().flashFee(wETHA(), loanAmount);
        //§uint256 allowance = wETH().allowance(address(this), flashLenderA());
@--->   if(!wETH().approve(flashLenderA(), loanAmount + fee)) revert FailedToApproveAllowance();
        if (
            !flashLender().flashLoan(
                IERC3156FlashBorrowerUpgradeable(this),
                wETHA(),
                loanAmount,
                abi.encode(msg.value, msg.sender, FlashLoanAction.SUPPLY_BOORROW)
            )
        ) {
            revert FailedToRunFlashLoan();
        }

        deployedAmount = _pendingAmount;
        _deployedAmount = _deployedAmount + deployedAmount;
        emit StrategyAmountUpdate(_deployedAmount);
        // Pending amount is not cleared to save gas
        // _pendingAmount = 0;
    }
```

### Impact

Flash loan call reverts for many amount and fee percentage combinations.

### Recommended Mitigation Steps

Round up in favour of the protocol. A library like solmate can be used which has `mulDivUp`:

```diff
    function flashFee(address, uint256 amount) external view override returns (uint256) {
        uint256 perc = _balancerVault.getProtocolFeesCollector().getFlashLoanFeePercentage();
        if (perc == 0 || amount == 0) {
            return 0;
        }

-       return (amount * perc) / _BALANCER_MAX_FEE_PERCENTAGE;
+       return amount.mulDivUp(perc, _BALANCER_MAX_FEE_PERCENTAGE);
    }
```

**[hvasconcelos (BakerFi) confirmed](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/11#event-13082208773)**

**[ickas (BakerFi) commented](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/11#issuecomment-2173045272):**
 > Fixed → https://github.com/baker-fi/bakerfi-contracts/pull/47



***

## [[M-08] `BalancerFlashLender#receiveFlashLoan` does not validate the `originalCallData`](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/2)
*Submitted by [zhaojie](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/2), also found by [rvierdiiev](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/27)*

### Impact

`receiveFlashLoan` does not validate the `originalCallData`. The attacker can pass any parameters into the `receiveFlashLoan` function and execute any Strategy instruction :`_supplyBorrow` `_repayAndWithdraw` `_payDeb`.

### Proof of Concept

The `StrategyLeverage#receiveFlashLoan` function only validates whether the msg.sender is `_balancerVault`, but does not validate the `originalCallData`:

```solidity
   function receiveFlashLoan(address[] memory tokens,
        uint256[] memory amounts, uint256[] memory feeAmounts, bytes memory userData
    ) external {
 @>     if (msg.sender != address(_balancerVault)) revert InvalidFlashLoadLender();
        if (tokens.length != 1) revert InvalidTokenList();
        if (amounts.length != 1) revert InvalidAmountList();
        if (feeAmounts.length != 1) revert InvalidFeesAmount();

        //@audit originalCallData is not verified
        (address borrower, bytes memory originalCallData) = abi.decode(userData, (address, bytes));
        address asset = tokens[0];
        uint256 amount = amounts[0];
        uint256 fee = feeAmounts[0];
        // Transfer the loan received to borrower
        IERC20(asset).safeTransfer(borrower, amount);

@>      if (IERC3156FlashBorrowerUpgradeable(borrower).onFlashLoan(borrower,
                tokens[0], amounts[0], feeAmounts[0], originalCallData
            ) != CALLBACK_SUCCESS
        ) {
            revert BorrowerCallbackFailed();
        }
        ....
    }
```

`_balancerVault.flashLoan` can specify the recipient:

```solidity
    _balancerVault.flashLoan(address(this), tokens, amounts, abi.encode(borrower, data));
```

An attacker can initiate flashLoan from another contract and specify the recipient as `BalancerFlashLender`. `_balancerVault` will call the `balancerFlashlender#receiveFlashLoan` function.
Since the caller of the receiveFlashLoan function is `_balancerVault`, this can be verified against `msg.sender`.

The `StrategyLeverage#onFlashLoan` function parses the instructions to be executed from `originalCallData(FlashLoanData)` and executes them.

```solidity
    function onFlashLoan(address initiator,address token,uint256 amount, uint256 fee, bytes memory callData
    ) external returns (bytes32) {
        if (msg.sender != flashLenderA()) revert InvalidFlashLoanSender();
        if (initiator != address(this)) revert InvalidLoanInitiator();
        // Only Allow WETH Flash Loans
        if (token != wETHA()) revert InvalidFlashLoanAsset();
        //loanAmount = leverage - msg.value;
@>      FlashLoanData memory data = abi.decode(callData, (FlashLoanData));
        if (data.action == FlashLoanAction.SUPPLY_BOORROW) {
            _supplyBorrow(data.originalAmount, amount, fee);
            // Use the Borrowed to pay ETH and deleverage
        } else if (data.action == FlashLoanAction.PAY_DEBT_WITHDRAW) {
            // originalAmount = deltaCollateralInETH
            _repayAndWithdraw(data.originalAmount, amount, fee, payable(data.receiver));
        } else if (data.action == FlashLoanAction.PAY_DEBT) {
            _payDebt(amount, fee);
        }
        return _SUCCESS_MESSAGE;
    }
```

So the attacker, by calling the `_balancerVault` flashLoan function, designated `recipient` for `BalancerFlashLender`, `borrower` for `StrategyLeverage`.
An attacker can invoke the `_supplyBorrow` `_repayAndWithdraw` `_payDeb` function in `StrategyLeverage` with any `FlashLoanData` parameter.

### Tools Used

VSCode, Manual

### Recommended Mitigation Steps

1.  `BalancerFlashLender#flashLoan` function to record the parameters called via hash.
2.  Verify the hash value in the `receiveFlashLoan` function.

**[hvasconcelos (BakerFi) confirmed](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/2#event-13082089390)**

**[0xleastwood (judge) decreased severity to Medium and commented](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/2#issuecomment-2168578441):**
 > After further discussion, I agree that `_repayAndWithdraw()` would fail when a zero amount repayment is made, so the only action that is really possible is `_supplyBorrow()` which would require some funds to already be in the contract. Unlikely for this to ever be the case because the contract doesn't normally hold funds that aren't being put to use in some way, but do correct me if this assumption is incorrect.
> 
> So I'm not sure how this issue can be exploited even if I do agree that it is an issue. For the time being, I will downgrade this to `medium` severity because it is obvious this is not intended behavour even if it may not lead to funds being lost.

**[0xleastwood (judge) commented](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/2#issuecomment-2182014419):**
 > This is clearly unintended behaviour and should be fixed even if it is not currently exploitable. I believe `medium` severity is still justified.

**[ickas (BakerFi) commented](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/2#issuecomment-2173881854):**
 > Fixed → https://github.com/baker-fi/bakerfi-contracts/pull/50

*Note: for full discussion, please see the warden's [original submission](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/2).*



***

# Low Risk and Non-Critical Issues

For this audit, 3 reports were submitted by wardens detailing low risk and non-critical issues. The [report highlighted below](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/15) by **t0x1c** received the top score from the judge.

*The following wardens also submitted reports: [0xStalin](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/45) and [bin2chen](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/49).*

## [[01] Unhandled Chainlink revert can lock price oracle access](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/15)

Chainlink's multisigs can immediately block access to price feeds at will. Therefore, to prevent denial of service scenarios, it is recommended to query Chainlink price feeds using a defensive approach with Solidity’s try/catch structure. In this way, if the call to the price feed fails, the caller contract is still in control and can handle any errors safely and explicitly.

Refer to <https://blog.openzeppelin.com/secure-smart-contract-guidelines-the-dangers-of-price-oracles/> for more information regarding potential risks to account for when relying on external price feed providers.

[Link to code](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/oracles/EthOracle.sol#L31):

```js
    function getLatestPrice() public view override returns (IOracle.Price memory price) {
@-->    (, int256 answer, uint256 startedAt, uint256 updatedAt,) = _ethPriceFeed.latestRoundData();
        if ( answer<= 0 ) revert InvalidPriceFromOracle();        
        if ( startedAt ==0 || updatedAt == 0 ) revert InvalidPriceUpdatedAt();    

        price.price = uint256(answer);
        price.lastUpdate = updatedAt;
    }
```

### Similar past issues

*   [Unhandled chainlink revert would lock all price oracle access](https://github.com/code-423n4/2022-07-juicebox-findings/issues/59)
*   [If a token's oracle goes down or price falls to zero, liquidations will be frozen](https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/161)

### Recommended Mitigation Steps

Surround the call to `latestRoundData()` with try/catch instead of calling it directly and provide a graceful alternative/exit.

**[0xleastwood (judge) decreased severity to Low/Non-Critical and commented](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/15#issuecomment-2164037526):**
 > I would not consider this `medium` severity because the likelihood is extremely low. Downgrading to `QA`.

**[hvasconcelos (BakerFi) acknowledged](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/15#event-13203313318)**


***

## [[02] `rebalance()` calculates `sharesToMint` by rounding-down against the protocol's favour](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/5)

The [Vault::rebalance()](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/Vault.sol#L260-L264) function rounds-down the `sharesToMint` against the protocol's favour. It ought to be rounded-up to avoid loss of funds for the protocol.

```js
                    uint256 feeInEthScaled = uint256(balanceChange) *
                        settings().getPerformanceFee();
                    uint256 sharesToMint = (feeInEthScaled * totalSupply()) /
                        _totalAssets(maxPriceAge) /
                        PERCENTAGE_PRECISION;
                    _mint(settings().getFeeReceiver(), sharesToMint);
```

### Impact

Loss of funds for the protocol.

### Recommended Mitigation Steps

Round up in favour of the protocol. A library like solmate can be used which has `mulDivUp`:

```diff
-                   uint256 sharesToMint = (feeInEthScaled * totalSupply()) /
-                       _totalAssets(maxPriceAge) /
-                       PERCENTAGE_PRECISION;
+                   uint256 sharesToMint = feeInEthScaled.mulDivUp(totalSupply(), _totalAssets(maxPriceAge) * PERCENTAGE_PRECISION);
```

**[hvasconcelos (BakerFi) confirmed](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/5#event-13082234364)**

**[0xleastwood (judge) decreased severity to Low/Non-Critical and commented](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/5#issuecomment-2166472501):**
 > This is not `medium` severity, there is minimal rounding here that does not cause significant leakage of funds. Downgrading to `QA` because rounding should always be done in favour of the protocol.
> 
> While this is not ideal in any way, no specific attack has been outlined abusing this inconsistency.

**[ickas (BakerFi) commented](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/5#issuecomment-2176057735):**
 > Fixed → https://github.com/baker-fi/bakerfi-contracts/pull/52


***

## [[03] User can withdraw in multiple calls with small amount to escape fee](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/4)

The [Vault::withdraw()](https://github.com/code-423n4/2024-05-bakerfi/blob/main/contracts/core/Vault.sol#L260-L264) function rounds-down the fee against the protocol's favour and hence a user can split their withdraw tx into multiple small ones such that `fee` evaluates to zero in each call. On less expensive chains like Arbitrum or Optimism, this strategy would be beneficial for them.

```js
        // Withdraw ETh to Receiver and pay withdrawal Fees
        if (settings().getWithdrawalFee() != 0 && settings().getFeeReceiver() != address(0)) {
@---->      fee = (amount * settings().getWithdrawalFee()) / PERCENTAGE_PRECISION;
            payable(msg.sender).sendValue(amount - fee);
            payable(settings().getFeeReceiver()).sendValue(fee);
```

### Proof of Concept

- Assume `settings().getWithdrawalFee()` to be `1e4`.
- `PERCENTAGE_PRECISION` is defined by the protocol as `1e9`.
- Scenario1 (normal user):
    - `amount` = 1e5
    - Will have to pay a fee of `(1e5 * 1e4) / 1e9 = 1`
- Scenario2 (malicious user):
    - Using 2 txs of `0.5e5` each
    - In each tx `amount` = 0.5e5
    - In each tx will have to pay a fee of `(0.5e5 * 1e4) / 1e9 = 0`
Hence no fee paid by the malicious user.

### Impact

Loss of fee for the protocol.

### Recommended Mitigation Steps

Round up in favour of the protocol. A library like solmate can be used which has `mulDivUp`:

```diff
-       fee = (amount * settings().getWithdrawalFee()) / PERCENTAGE_PRECISION;
+       fee = amount.mulDivUp(settings().getWithdrawalFee(), PERCENTAGE_PRECISION);
```

**[0xleastwood (judge) decreased severity to Low/Non-Critical and commented](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/4#issuecomment-2164034553):**
 > Not reasonable to expect this to be profitable even with low gas costs.
> 
> Downgrading to QA for above reasons.

**[hvasconcelos (BakerFi) confirmed](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/4#event-13082238029)**

**[ickas (BakerFi) commented](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/4#issuecomment-2175790044):**
 > Fixed → https://github.com/baker-fi/bakerfi-contracts/pull/51


***

# Disclosures

C4 is an open organization governed by participants in the community.

C4 audits incentivize the discovery of exploits, vulnerabilities, and bugs in smart contracts. Security researchers are rewarded at an increasing rate for finding higher-risk issues. Audit submissions are judged by a knowledgeable security researcher and solidity developer and disclosed to sponsoring developers. C4 does not conduct formal verification regarding the provided code but instead provides final verification.

C4 does not provide any guarantee or warranty regarding the security of this project. All smart contract software should be used at the sole risk and responsibility of users.
