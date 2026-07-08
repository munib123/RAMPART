# Vulnerability: Claris FileMaker Server Admin Console - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`claris-filemaker-panel.yaml`)

## Description
Claris FileMaker Server Admin Console panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin-console/signin
```

