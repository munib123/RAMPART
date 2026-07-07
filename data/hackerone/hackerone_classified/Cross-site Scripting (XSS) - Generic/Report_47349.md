# HackerOne Report: Stored xss in user name (2) affected another user.
**Report ID:** 47349
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Again we have to users:
A - attacker
B - victim

User A (attacker) has name - name<script>alert(1)</script> and add auth to user B (victim).
User B receive a letter and get remider about new request on website. And open it
https://mobilevikings.com/account/requests/
And probably press "Accept" and got xss fired.
x:confirm parameter is the reason of this issue.

## Discussion & Remediation Timeline
