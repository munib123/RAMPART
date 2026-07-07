# HackerOne Report: Password Reset Bug
**Report ID:** 8082
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Possible account takeover using the forgot password link even after the email address and password changed.

Steps to Reproduce
===================================

Create an account in hackerone E.g john@example.com
After account verification logout from the account
Reset the password for john@example.com where we get the password reset link but do not use this link.

Now login again and change the email from john@exmaple.com to teena@example.com .

A verification email will be sent to teena. After successful verification we can logout.

Now this hackerone.com account belongs to teena@example.com and now teena can change the password.

But at this point ( after password change ) all the password reset links generated before should no longer be valid but in hackerone its still valid

Now we can try using the forgot password reset link which we have kept in john@exmaple.com and see if we can take over the account.

## Discussion & Remediation Timeline
