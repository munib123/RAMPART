# Vulnerability: Content-Security-Policy Bypass - jQuery CDN
**Classification:** CWE-79
**Source:** Nuclei Template (`jquery-cdn-csp-bypass.yaml`)

## Description
CSP policy allows jQuery CDN which enables arbitrary JavaScript execution through vulnerable jQuery versions using parseHTML or $.get functions.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

