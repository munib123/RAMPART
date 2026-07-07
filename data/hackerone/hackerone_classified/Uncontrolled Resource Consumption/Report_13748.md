# HackerOne Report: Potential denial of service in hackerone.com/teams/new
**Report ID:** 13748
**Vulnerability Class:** Uncontrolled Resource Consumption

## Vulnerability Information & PoC
While creating a new team, if I set the bounty to a large value (over 1,000,000 digits) and send the request the website hangs for about a minute and a half, then pops up an error page saying there is an error on your end.

## Discussion & Remediation Timeline
