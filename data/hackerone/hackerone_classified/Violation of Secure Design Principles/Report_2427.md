# HackerOne Report: XSRF token problem
**Report ID:** 2427
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Your web application generates XSRF token values inside cookies which is not a best practice for web applications as revelation of cookies can reveal XSRF Tokens as well. Authenticity tokens should be kept separate from cookies and should be isolated to change operations in the account only.

## Discussion & Remediation Timeline
