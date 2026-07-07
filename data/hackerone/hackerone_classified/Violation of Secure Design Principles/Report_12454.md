# HackerOne Report: Browser cross-site scripting filter misconfiguration
**Report ID:** 12454
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Issue detail :-
No X-XSS-Protection header was set in the response. This means that the browser uses default behaviour that detection of a cross-site scripting attack never prevents rendering.

Remediation detail
The following header should be set:

X-XSS-Protection: 1; mode=block

Issue background :-
Cross-site scripting (XSS) filters in browsers check if the URL contains possible harmful XSS payloads and if they are reflected in the response page. If such a condition is recognized, the injected code is changed in a way, that it is not executed anymore to prevent a succesful XSS attack. The downside of these filters is, that the browser has no possibility to distinguish between code fragments which were reflected by a vulnerable web application in an XSS attack and these which are already present on the page. In the past, these filters were used by attackers to deactivate JavaScript code on the attacked web page. Sometimes the XSS filters itself are vulnerable in a way, that web applications which were protected properly against XSS attacks became vulnerable under certain conditions.

Remediation background :-
It is considered as better practice to instruct the browser XSS filter to never render the web page if an XSS attack is detected.

## Discussion & Remediation Timeline
