# Vulnerability: Qualtrics Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`qualtrics-login.yaml`)

## Description
Qualtrics login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

