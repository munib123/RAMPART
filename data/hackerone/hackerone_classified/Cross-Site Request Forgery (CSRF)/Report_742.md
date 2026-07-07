# HackerOne Report: A password reset page does not properly validate the authenticity token at the server side.
**Report ID:** 742
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
1. Go to https://hackerone.com/users/password/new and request a new password.
2. go to email, and click on the link.
3. put the new password, submit and intercept the request; remove the authenticity token from the request and now forward it to the server.
4. you will see request still got completed and user logged in. The token did not verify on the server side.

## Discussion & Remediation Timeline
