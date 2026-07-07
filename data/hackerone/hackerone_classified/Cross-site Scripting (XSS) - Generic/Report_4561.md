# HackerOne Report: Stored XSS in Slackbot Direct Messages
**Report ID:** 4561
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Whenever a new team is created, Slackbot uses automated profile completion by asking a few questions from the user like the first name, last name, skype account etc. But instead of providing the correct details we provide `<javascript:alert(document.cookie);>` as input then Slackbot will cause the data go inside the anchor tag `<a href=javascript:alert(document.cookie);>...</a>` so clicking on the link will trigger XSS.

Video POC: https://www.dropbox.com/s/7fmbe4jnd923pd0/Dumbbot-XSS.mov

## Discussion & Remediation Timeline
