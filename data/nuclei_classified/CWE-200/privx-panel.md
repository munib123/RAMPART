# Vulnerability: SSH PrivX Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`privx-panel.yaml`)

## Description
SSH PrivX login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth/login
```

