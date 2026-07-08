# Vulnerability: Content-Security-Policy "script-src" Wildcard Detected
**Classification:** CSP
**Source:** Nuclei Template (`csp-script-src-wildcard.yaml`)

## Description
Detected a wildcard (*) within the script-src directive of the Content-Security-Policy. This allowed scripts to load from any origin, weakening the CSP and increasing XSS risk.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

