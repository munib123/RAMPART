# Vulnerability: Content-Security-Policy Bypass - Google Storage
**Classification:** CWE-79
**Source:** Nuclei Template (`google-storage-csp-bypass.yaml`)

## Description
CSP policy allows Google Storage (storage.googleapis.com) enabling malicious JavaScript execution by loading attacker-controlled files from whitelisted domain.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

