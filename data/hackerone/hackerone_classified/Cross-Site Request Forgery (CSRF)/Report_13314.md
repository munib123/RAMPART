# HackerOne Report: CRLF Injection
**Report ID:** 13314
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
Is it possible for a remote attacker to inject custom HTTP headers. For example, an attacker can inject session cookies or HTML code. This may conduct to vulnerabilities like XSS (cross-site scripting) or session fixation.

PoC
https://crowdin.khanacademy.org/page/in-context-localization?email=%0d%0a%20InjectedBy:BigBear

## Discussion & Remediation Timeline
