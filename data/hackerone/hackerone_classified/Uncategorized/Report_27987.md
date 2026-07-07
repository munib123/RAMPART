# HackerOne Report: Window Opener Property Bug
**Report ID:** 27987
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
The bug mentioned in #23386 is not yet correctly patched I believe.

See, if a user sets his/her profile's website link to a similar page as mentioned in #23386. I mean a page that can manipulate the window.opener property would be able to accomplish similar results as in #23386

**Proof-of-Concept**:

1. Login to HackerOne
2. Navigate to https://hackerone.com/settings/profile/edit
3. Set *Website* to https://demo.prakharprasad.com/ga.html
4. Once someone visits this link from a profile page  (eg. https://hackerone.com/<username->), his opener HackerOne window will be hijacked.

Let me know if you have any questions.

Thanks,
Prakhar Prasad


## Discussion & Remediation Timeline
