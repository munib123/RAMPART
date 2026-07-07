# HackerOne Report: Non Validation of session after password reset
**Report ID:** 15852
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
After a password reset link is requested and a user's password is then changed, not all existing sessions are logged out automatically. 
Logging in with the new password doesn't invalidate the older session either: I could browse mavenlink using two sessions (in two different browsers) which were initiated using two different passwords.

## Discussion & Remediation Timeline
