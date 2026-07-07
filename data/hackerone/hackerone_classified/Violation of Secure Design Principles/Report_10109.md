# HackerOne Report: Flooding mailbox of user
**Report ID:** 10109
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
There seems to be no prevention from sending multiple password reset links to a selected e-mail. As a result mailbox of the user can be flooded with these mails. I would recommend to add CAPTCHA in forgot password functionality.

## Discussion & Remediation Timeline
