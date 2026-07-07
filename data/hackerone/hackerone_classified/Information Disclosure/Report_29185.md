# HackerOne Report: "early preview" programs disclosure
**Report ID:** 29185
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Hi,

There is a really small issue, but I think it should be fixed.

If you open https://hackerone.com/facebook as guest user (not logged), you will be redirected to https://hackerone.com/users/sign_in, so it shows that facebook page exists and it's private.

Correct redirection should be to #404 page like eg. https://hackerone.com/privateprogram

Cheers,
Kacper.

## Discussion & Remediation Timeline
