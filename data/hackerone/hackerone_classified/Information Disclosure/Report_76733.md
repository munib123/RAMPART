# HackerOne Report: Using GET method for account login with CSRF token leaking to external sites Via Referer.
**Report ID:** 76733
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
HI

At the time of login, the values are present in URL along with the CSRF token.  Also this URL is leaking to external sites in HTTP REFRERER. 

Here are some of those sites:
dxzc9stvaxhhy.cloudfront.net
bam.nr-data.net
ssl.google-analytics.com
usage.trackjs.com
api.mixpanel.com


## Discussion & Remediation Timeline
