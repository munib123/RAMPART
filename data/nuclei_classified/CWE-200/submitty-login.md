# Vulnerability: Submitty Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`submitty-login.yaml`)

## Description
Submitty login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/authentication/login
```

