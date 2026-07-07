# HackerOne Report: Stored xss in user name
**Report ID:** 47343
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
In prev report i showed xss in user name thru cookie, there is another place where this name shows and fired xss.
After send auth request open https://mobilevikings.be/en/account/authorization/overview/ in account who send request and press "Remove authorization" and got another way to fire xss payload.
param x:authorization-to-first-name is properly sanitized but probably when it goes to modal window it unsanitize.

## Discussion & Remediation Timeline
