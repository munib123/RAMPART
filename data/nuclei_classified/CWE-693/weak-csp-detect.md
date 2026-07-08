# Vulnerability: Weak Content Security Policy - Detect
**Classification:** CWE-693
**Source:** Nuclei Template (`weak-csp-detect.yaml`)

## Description
Detected misconfigured CSP directives containing unsafe and overly permissive keywords that weakened resource loading restrictions. This configuration allowed high-risk script behaviors, resulting in reduced protection against XSS attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

