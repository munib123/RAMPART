# HackerOne Report: HTTP Strict Transport Security (HSTS) Policy Not Enabled
**Report ID:** 11945
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Dear Team,

Step-by-step instructions on how to reproduce the problem:

It was found the application is vulnerable to HTTP Strict Transport Security (HSTS) Policy Not Enabled.

HTTP Strict Transport Security (HSTS) is an opt-in security enhancement that is specified by a web application through the use of a special response header. Once a supported browser receives this header that browser will prevent any communications from being sent over HTTP to the specified domain and will instead send all communications over HTTPS. It also prevents HTTPS click through prompts on browsers.

## Discussion & Remediation Timeline
