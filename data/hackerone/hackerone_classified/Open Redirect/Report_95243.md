# HackerOne Report: Following a User Actually Follows Another User
**Report ID:** 95243
**Vulnerability Class:** Open Redirect

## Vulnerability Information & PoC
I can display a web intent page to a victim that appears to prompt them to follow one user, but actually ends up following a completely different user when they click "follow". The following is a proof of concept:

https://twitter.com/intent/follow?screen_name=twitter&screen_name=ericrtest3&user_id=113483807

This is somewhat related to the last bug I submitted (see #95217), albeit the impact is more dramatic. This can be used by malicious users such as spammers and social engineers to trick a user into following them.

## Discussion & Remediation Timeline
