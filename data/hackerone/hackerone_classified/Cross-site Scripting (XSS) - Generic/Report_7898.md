# HackerOne Report: Persistent Cross-site scripting vulnerability settings.
**Report ID:** 7898
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hello,

I created an account with as group name `"><img src=x onerror=alert(4)>`, after that I went to settings and found a Cross-site scripting vulnerability located at that page.

The url for me : https://app.respond.ly/6sjp/settings/account

I have a proof of concept in the attachment.

best regards

Olivier Beg

## Discussion & Remediation Timeline
