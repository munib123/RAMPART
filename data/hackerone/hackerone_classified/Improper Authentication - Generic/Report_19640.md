# HackerOne Report: Session Hijacking attack (Different Scenario)
**Report ID:** 19640
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
Hey 
I was able to replay a cookie of a current active session and hijack that by replaying the cookie. Now this is different from any conventional vanilla session hijacking because it works even when the user is not logged in. But the condition is that the victim's session must be active at the time of replay
1. Capture a cookie from one account using tamper data just note that you learn the Referer and X-XHR-Referer values

2. Open a new windows click on the same link without logging in. For example in the victim account i clicked on "bugs" so here in order to replay the cookie i have to click on bugs again. Replay the X-XHR value with the other one. Replay the session cookie and you are in. You hacked the account.

I hope this impresses you because i have been trying hard to get you guys impressed. Although i have managed to do with the other ones :)
Waiting for your reply

## Discussion & Remediation Timeline
