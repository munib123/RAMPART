# HackerOne Report: XSS via Email
**Report ID:** 7919
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
This one was easy.

Someone needs send an email with **Subject** line : *"><img src=x onerror=alert(document.cookie);>* to the team email, mine was **kfvm@mail.respond.ly**

So once the email arrives it will execute Javascript (See attachment)

## Discussion & Remediation Timeline
