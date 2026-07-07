# HackerOne Report: Clickjacking
**Report ID:** 21110
**Vulnerability Class:** UI Redressing (Clickjacking)

## Vulnerability Information & PoC
Hi,

You have no implementation of Clickjacking attacks on your mobile version. I have set up a user agent switcher and tried to support my claim with regards to the mobile website.

For proof of concept: <iframe src="https://m.mavenlink.com/#/workspaces/new"></iframe>

For mitigation, you may want to add the HTTP header XFRAMEOPTIONS and set it to DENY.

Attached below is a screenshot. Thanks!


## Discussion & Remediation Timeline
