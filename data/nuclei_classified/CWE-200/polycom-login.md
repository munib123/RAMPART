# Vulnerability: Polycom Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`polycom-login.yaml`)

## Description
Polycom login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.html
```

