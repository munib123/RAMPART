# HackerOne Report: ads.twitter.com xss
**Report ID:** 27511
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Cross-Site Scripting vulnerability exists in card[name] parameter when creating/cloning a card via script https://ads.twitter.com/accounts/18ce53wrkma/cards/new?card_type=7. 
Here is the simple test vector: </title><script>alert(document.cookie)</script><title>
After the card is created XSS becomes persistent and can be triggered via https://ads.twitter.com/accounts/18ce53wrkma/cards/show?url_id=42qj.

## Discussion & Remediation Timeline
