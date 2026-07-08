# Vulnerability: Icinga Web 2 Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`icinga-web-login.yaml`)

## Description
Icinga Web 2 login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/authentication/login
```

