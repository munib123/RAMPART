# Vulnerability: Slocum Fleet Mission Control Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`slocum-login.yaml`)

## Description
Slocum Fleet Mission Control login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sfmc/login
```

