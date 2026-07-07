# HackerOne Report: information disclosure
**Report ID:** 13939
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Use Google chrome  35.0.1916.114m for reproduction  
1. go to https://app.simplenote.com/
2. login into the app.
3. Now press logout, and press back button on browser. You will see the session back.This is the information disclosure vulnerability.

I recommend checking for a valid, authenticated session and if there isn't one redirect to the login page.

## Discussion & Remediation Timeline
