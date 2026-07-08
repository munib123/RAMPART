# Vulnerability: XNAT Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`xnat-login.yaml`)

## Description
XNAT login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/app/template/Login.vm
```

