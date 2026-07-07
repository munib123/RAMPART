# HackerOne Report: XSS in Localize.io
**Report ID:** 7890
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
During signup I used "></code><svg/onload=prompt(1)> as my password.Just after pressing sign up I was forwarded to a new page,where that page was showing my username and asked to click to view my password.When I clicked the javascript executed.
Attachment: xss.png

## Discussion & Remediation Timeline
