# Vulnerability: Budibase Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`budibase-login-detect.yaml`)

## Description
Budibase login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/builder/auth/login
```

