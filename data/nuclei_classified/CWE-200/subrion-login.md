# Vulnerability: Subrion Admin Panel Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`subrion-login.yaml`)

## Description
Subrion Admin Panel login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/panel
```

