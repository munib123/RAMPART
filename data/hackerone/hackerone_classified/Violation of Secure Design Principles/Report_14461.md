# HackerOne Report: Password reset link doesn't expire.
**Report ID:** 14461
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
The password reset link sent by Factlink doesn't expire even after a long period of time. As Factlink account can be created 'without confirming' email id, so, this should be patched for the best practice.

## Discussion & Remediation Timeline
