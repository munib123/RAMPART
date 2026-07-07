# HackerOne Report: x-frame options-sameorigin warning
**Report ID:** 7945
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
As the x-frame options set to same-origin it still may be vulnerable to clickjacking attacks how?
by using this code
<iframe src="link " sandbox="allow-top-navigation allow-same-origin allow-scripts"></iframe>

Better explanation: http://www.skeletonscribe.net/2012/06/x-frame-options-sameorigin-warning.html

## Discussion & Remediation Timeline
