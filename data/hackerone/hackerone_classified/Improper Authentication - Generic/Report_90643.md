# HackerOne Report: No email verification during registration
**Report ID:** 90643
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
When you register for a new account, there is no verification link sent to the email for confirmation. The account is directly activated and can be used without confirming the email.

This is vulnerable as anyone can use anyone's email without verification. and one with valid email owner cant signup with his own email as someone else already took it before him.




## Discussion & Remediation Timeline
