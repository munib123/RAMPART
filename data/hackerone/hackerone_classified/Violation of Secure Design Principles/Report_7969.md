# HackerOne Report: HTTP Strict transport security policy not enabled
**Report ID:** 7969
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
HTTP Strict Transport Security (HSTS) is an opt-in security enhancement that is specified by a web application through the use of a special response header. Once a supported browser receives this header that browser will prevent any communications from being sent over HTTP to the specified domain and will instead send all communications over HTTPS. It also prevents HTTPS click through prompts on browsers.

## Discussion & Remediation Timeline
