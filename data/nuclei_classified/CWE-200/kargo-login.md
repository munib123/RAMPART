# Vulnerability: Kargo Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kargo-login.yaml`)

## Description
Kargo login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

