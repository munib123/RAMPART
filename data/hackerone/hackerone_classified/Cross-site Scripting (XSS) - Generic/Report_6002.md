# HackerOne Report: Stored XSS in Slack.com
**Report ID:** 6002
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Steps: 

Go to your respective URL Mine is https://dezignburg.slack.com/account/photo

now Change your photo using Facebook

But before that create a Album in your Facebook naming it as "><img src=x onerror=alert(document.cookie)>

And you will get this error: http://prntscr.com/37eecd

If you need a video just tell me

## Discussion & Remediation Timeline
