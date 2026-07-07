# HackerOne Report: javascript: and mailto: links are allowed on users' profiles
**Report ID:** 4184
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
For user's Profile settings, you accept website URLs like mailto:hello@foo.com and even javascript:alert(1).  The Content Security Policy directive in Chrome catches the JavaScript one, but older browsers will almost certainly execute the code, allowing for session stealing or XSS code execution attacks when the link is clicked.

Your JS prints "Website is not valid.", but hitting return still submits it.


## Discussion & Remediation Timeline
