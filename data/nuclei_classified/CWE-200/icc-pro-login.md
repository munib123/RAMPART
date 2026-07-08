# Vulnerability: ICC PRO Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`icc-pro-login.yaml`)

## Description
ICC PRO login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Account/Login
```

