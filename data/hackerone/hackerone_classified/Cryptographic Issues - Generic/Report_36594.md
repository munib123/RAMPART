# HackerOne Report: New Device Confirmation, token is valid until not used. 
**Report ID:** 36594
**Vulnerability Class:** Cryptographic Issues - Generic

## Vulnerability Information & PoC
New Device Confirmation token sends to the logged in user from unconfirmed device. Now If Click on Account or Settings or Profile email of new token will send to that person and same if user click multiple times, more and more confirmation emails user received. On each reload each confirmation token send to the user's email. Now All Tokens are Valid.

User will use any one of them, but others are still valid. So It should expire after sometime.

I have checked by reloading multiple times and all tokens are valid.


## Discussion & Remediation Timeline
