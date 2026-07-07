# HackerOne Report: OPTIONS Method Enabled
**Report ID:** 8184
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
HTTP OPTIONS method is enabled on the web server of Localize. The OPTIONS method provides a list of the methods that are supported by the web server, it represents a request for information about the communication options available on the request/response chain identified by the Request-URI.

This vulnerability affects the Web Server of InvisionApp!

Attack details:

Methods allowed: GET,HEAD,POST,OPTIONS 

The OPTIONS method may expose sensitive information that may help an malicious user to prepare more advanced attacks.

Fix:It's recommended to disable OPTIONS Method on the web server.


## Discussion & Remediation Timeline
