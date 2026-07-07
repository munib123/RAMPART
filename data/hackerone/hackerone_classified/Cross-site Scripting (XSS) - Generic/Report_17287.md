# HackerOne Report: email field doesn't filtered against XSS
**Report ID:** 17287
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi,
Pre-configuration, create new contact in Gmail with mail a"><img src=y onerror=prompt(...);>

1. Go to Invites.
2. Click on Invite Gmail Friends.
3. Accept the pop up.
4. XSS will activate on the email field.


Few issues continue during this issue:
1. When you click on this email address you get failure on AJAX functionally.
2. If you try to do the same scenario I describe the system throw Error
The website encountered an unexpected error. Please try again later.

Sasi


## Discussion & Remediation Timeline
