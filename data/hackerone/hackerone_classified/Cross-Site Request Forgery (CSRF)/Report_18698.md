# HackerOne Report: Resubmitted with POC #18685 Password reset CSRF
**Report ID:** 18698
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
Hey there
I found out that an attacker can use the password reset link to forge requests because there is no CSRF token in that particular request to validate that request. You should always have a CSRF token in the password reset request.


## Discussion & Remediation Timeline
