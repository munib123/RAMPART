# HackerOne Report: CSRF login
**Report ID:** 547
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
1) Attacker creates a fake account and changes e-mail
2) The e-mail confirmation link can now be used to CSRF login someone into the fake account, then monitor actions performed by the victim or even interact with him.




## Discussion & Remediation Timeline
