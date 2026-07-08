# Vulnerability: Code-Server Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`code-server-login.yaml`)

## Description
Code-Server login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

