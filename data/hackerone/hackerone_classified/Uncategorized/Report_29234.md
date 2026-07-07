# HackerOne Report: Credit Card Validation Issue
**Report ID:** 29234
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
Hi Coinbase, I'm not sure if this counts as a bug, but it definitely counts as a vulerability.  The issue is in your credit card verification for instant purchases.  The system does not (or rarely) check the validity of a credit card after it is added.  This allows me to make instant buy purchases, without the need for a working credit card.

After I add my credit card, I can cancel it, either specifically to exploit coinbase, or another situation (like if it gets stolen) where one would cancel their card.  The system currently has no way to determine if a credit card is still active after it is validated the first time.  I still can instant buy, and if my bank transfer either maliciously or non-maliciously fails, the credit card will also fail.

This leads to a potential loss of funds and I believe it is in scope.  Please let me know if this is incorrect.

Thanks,

Whit

## Discussion & Remediation Timeline
