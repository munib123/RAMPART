# Vulnerability: Webroot Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`webroot-login.yaml`)

## Description
Webroot login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Login
```

