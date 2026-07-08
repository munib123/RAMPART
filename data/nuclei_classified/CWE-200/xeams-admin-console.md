# Vulnerability: Xeams Admin Console Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`xeams-admin-console.yaml`)

## Description
Xeams Admin Console login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/FrontController
```

