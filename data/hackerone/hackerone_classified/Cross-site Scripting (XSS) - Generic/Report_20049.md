# HackerOne Report: Cross-site Scripting in mailing (username)
**Report ID:** 20049
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
There appears to be a Cross-site Scripting vulnerability related to [my previous report](https://hackerone.com/reports/2735) in the newsletter mailing. See my attached screenshot.

The steps to exploit and the impact are the same as in the previous report, but to exploit this specific XSS an attacker would have to register an account with someone else's e-mail address. 

Because the previous issue is fixed, this implies that there is no global sanitation for e-mails. I recommend checking all mailing scripts/tools for proper sanitation of variables (like the username).

## Discussion & Remediation Timeline
