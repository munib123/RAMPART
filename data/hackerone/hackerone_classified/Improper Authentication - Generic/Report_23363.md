# HackerOne Report: Forgot Password Issue
**Report ID:** 23363
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
Hi,

The application authenticates user before the password is changed by the user.

POC:
1. User attempts password reset
2. User gets verification link
3. User access link and gets authenticated automatically before performing any password change



## Discussion & Remediation Timeline
