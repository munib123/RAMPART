# Vulnerability: MeterSphere Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`metersphere-login.yaml`)

## Description
MeterSphere login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/favicon.ico
GET {{BaseURL}}/login
```

