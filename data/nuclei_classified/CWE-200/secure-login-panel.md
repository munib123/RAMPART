# Vulnerability: Secure Login Service Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`secure-login-panel.yaml`)

## Description
Secure Login Service login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login/sls/auth
```

