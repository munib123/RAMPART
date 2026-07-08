# Vulnerability: Bytebase Auth - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bytebase-auth-panel.yaml`)

## Description
Bytebase authentication interface was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth
```

