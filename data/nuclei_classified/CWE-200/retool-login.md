# Vulnerability: Retool Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`retool-login.yaml`)

## Description
Retool login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth/login
```

