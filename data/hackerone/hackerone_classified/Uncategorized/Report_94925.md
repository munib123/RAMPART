# HackerOne Report: Balance Manipulation - BUG
**Report ID:** 94925
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
Hello once again,

I have discovered another balance manipulation bug. This time it is much more simpler, but basically has the same outcome. 

EXPLANATION: When you create basic standard Vault and transfer money from your Main Wallet to the vault the balance doesn't "lock up", which means that even when the transfer is pending to the vault you are still freely able to transfer the balance to other btc wallets from your main wallet. Once you approve the transfer to Vault your balance would go into Negative resulting in balance manipulation.

If you have any more questions/concerns feel free to ask.


Thanks,

████████.

## Discussion & Remediation Timeline
