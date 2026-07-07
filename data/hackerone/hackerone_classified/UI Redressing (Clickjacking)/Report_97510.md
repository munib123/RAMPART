# HackerOne Report: Following a User After Favoriting Actually Follows Another User (related to #95243)
**Report ID:** 97510
**Vulnerability Class:** UI Redressing (Clickjacking)

## Vulnerability Information & PoC
Hi,

There appears to be a bug similar to #95243 which affects following a user after favoriting one of their tweets via an Intent dialog.

The following is a proof of concept:

https://twitter.com/intent/favorite/?tweet_id=661625230297821184&screen_name=ericrtest3

The screen_name param submits with the favorite form and ends up getting injected into the follow param on the resulting page.

This isn't quite as bad as the previous vulnerability I found, since it requires an additional step (favoriting a tweet) to exploit. However, the impact is exactly the same as the last vulnerability, in that the user has no idea that they're actually following a completely different user.

Please let me know if you have any other questions.

## Discussion & Remediation Timeline
