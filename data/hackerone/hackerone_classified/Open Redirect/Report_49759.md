# HackerOne Report: Open Redirect leak of authenticity_token lead to full account take over.
**Report ID:** 49759
**Vulnerability Class:** Open Redirect

## Vulnerability Information & PoC
Hey guys
URL: https://mobile.twitter.com/messages/follow?recipient=/example.com
when I click 'Follow'
I will send my POST request to https://example.com
witch contains my authenticity_token
that can be used for anything like tweeting, following, sending messages, changing username.,.,.etc
it can be used too to Add a mobile number, and then steal the account by recovering it by the mobile number.
Thank You.

## Discussion & Remediation Timeline
