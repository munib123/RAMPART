# Nuclei Template: Content-Security-Policy Bypass - jQuery CDN
**Template ID:** jquery-cdn-csp-bypass
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`jquery-cdn-csp-bypass.yaml`)

## Vulnerability Information & PoC

## Description
CSP policy allows jQuery CDN which enables arbitrary JavaScript execution through vulnerable jQuery versions using parseHTML or $.get functions.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
```

## References
- https://www.doyler.net/security-not-included/csp-bypass-via-jquery
- https://github.com/jquery/jquery/issues/2432
- https://bugs.jquery.com/ticket/11974
