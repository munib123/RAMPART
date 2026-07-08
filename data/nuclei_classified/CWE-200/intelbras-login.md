# Vulnerability: Intelbras Router Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`intelbras-login.yaml`)

## Description
Intelbras router logjn panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.html
```

