# HackerOne Report: Issue with password change
**Report ID:** 38343
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
When a password is changed in user's profile, then a notification about password change is sent to the user (email). This is good. 

However, user not always gets a notification about password change - when a password is changed via password reset link, then such a notification is not send to the user.


## Discussion & Remediation Timeline
