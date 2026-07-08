# Vulnerability: CAS Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cas-login.yaml`)

## Description
CAS login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cas/login
```

