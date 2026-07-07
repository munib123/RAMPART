# HackerOne Report: OAuth Bug
**Report ID:** 9460
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
I read the bug of @melvin and I also try to bypass this
https://app.respond.ly/_oauth/twitter/?requestTokenAndRedirect=https://hackerone.com

so I made a bypassing tehcnique but didnt work 
https://app.respond.ly/_oauth/twitter/?requestTokenAndRedirect=//hackerone.com

But I think I found a bug 
This is the Screen shot: http://prntscr.com/3cu58e

When a user authorizes their twitter to connect with the URL above they will encounter that error.

## Discussion & Remediation Timeline
