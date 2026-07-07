# HackerOne Report: XSS in gist integration
**Report ID:** 11073
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
1. Create a gist called:
"><svg onload=alert(1)>
2. have gist integration enabled and put a link in a slack chat
3. Visit the 'raw' or 'new window' pages for this gist, for example: https://outpost.slack.com/files/zemnmez/F029MDY33/___svg_onload_alert_1__



## Discussion & Remediation Timeline
