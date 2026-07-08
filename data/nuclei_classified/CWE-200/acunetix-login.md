# Vulnerability: Acunetix Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`acunetix-login.yaml`)

## Description
Acunetix login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#/login
```

