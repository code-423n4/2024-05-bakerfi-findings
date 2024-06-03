## Findings Summary

| Label | Description |
| - | - |
| [L-01] | withdraw() returns the wrong amount , it without subtract fee|
| [L-02] |  No check for active Sequencer in L2 Oracle|
| [L-03] |getAndUpdatePrice doesn't return the exceeded eth |

## [L-01] withdraw() returns the wrong amount , it without subtract fee
The amount returned by `Vault.withdraw()` needs to subtract fee
But the current implementation doesn't
```solidity
     * @return amount The amount of Ether withdrawn after fees.
     *
     * Emits a {Withdraw} event after successfully handling the withdrawal.
     */
    function withdraw(
        uint256 shares
    ) external override nonReentrant onlyWhiteListed whenNotPaused returns (uint256 amount) {
...
        uint256 withdrawAmount = (shares * _totalAssets(settings().getPriceMaxAge())) /
            totalSupply();
        if (withdrawAmount == 0) revert NoAssetsToWithdraw();
        amount = _strategy.undeploy(withdrawAmount);
        uint256 fee = 0;
        _burn(msg.sender, shares);
        // Withdraw ETh to Receiver and pay withdrawal Fees
        if (settings().getWithdrawalFee() != 0 && settings().getFeeReceiver() != address(0)) {
            fee = (amount * settings().getWithdrawalFee()) / PERCENTAGE_PRECISION;
            payable(msg.sender).sendValue(amount - fee);
            payable(settings().getFeeReceiver()).sendValue(fee);
        } else {
            payable(msg.sender).sendValue(amount);
        }     
        emit Withdraw(msg.sender, amount - fee, shares); 
    }
@>   @audit return amount without subtract fee
```
impact:

If there is a third-party integration, getting a return value that is too large will result in a `revert`

suggest:
```diff
    function withdraw(
        uint256 shares
    ) external override nonReentrant onlyWhiteListed whenNotPaused returns (uint256 amount) {
...
        uint256 withdrawAmount = (shares * _totalAssets(settings().getPriceMaxAge())) /
            totalSupply();
        if (withdrawAmount == 0) revert NoAssetsToWithdraw();
        amount = _strategy.undeploy(withdrawAmount);
        uint256 fee = 0;
        _burn(msg.sender, shares);
        // Withdraw ETh to Receiver and pay withdrawal Fees
        if (settings().getWithdrawalFee() != 0 && settings().getFeeReceiver() != address(0)) {
            fee = (amount * settings().getWithdrawalFee()) / PERCENTAGE_PRECISION;
            payable(msg.sender).sendValue(amount - fee);
            payable(settings().getFeeReceiver()).sendValue(fee);
        } else {
            payable(msg.sender).sendValue(amount);
        }     
        emit Withdraw(msg.sender, amount - fee, shares); 
    }
+  return amount - fee
```

## [L-02]  No check for active Sequencer in L2 Oracle

Chainlink recommends that all Optimistic L2 oracles consult the Sequencer Uptime Feed to ensure that the sequencer is live before trusting the data returned by the oracle. it is skipped in all Oracle.sol.

## impact
If the Arbitrum Sequencer goes down, oracle data will not be kept up to date, and thus could become stale. However, users are able to continue to interact with the protocol directly through the L1 optimistic rollup contract. You can review Chainlink docs on [L2 Sequencer Uptime Feeds](https://docs.chain.link/docs/data-feeds/l2-sequencer-feeds/) for more details on this.

As a result, users may be able to use the protocol while oracle feeds are stale. This could cause many problems

## [L-03] getAndUpdatePrice doesn't return the exceeded eth
in `getAndUpdatePrice()`.
If `msg.value > fee` doesn't return the excess eth to the user it stays in the contract.
```solidity
    function getAndUpdatePrice(
        bytes calldata priceUpdateData
    ) external payable returns (IOracle.Price memory) {
        if ( priceUpdateData.length == 0 ) revert InvalidPriceUpdate();
        bytes[] memory priceUpdates = new bytes[](1);
        priceUpdates[0] = priceUpdateData;
        uint256 fee = _pyth.getUpdateFee(priceUpdates);
        if (msg.value < fee) revert NoEnoughFee();
@>      _pyth.updatePriceFeeds{value: fee}(priceUpdates);
        return _getPriceInternal(0);
    }
```
Recommendation:
Refund of excess eth
