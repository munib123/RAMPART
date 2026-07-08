# Vulnerability: Bazarr Login - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bazarr-login.yaml`)

## Description
Bazarr login page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

