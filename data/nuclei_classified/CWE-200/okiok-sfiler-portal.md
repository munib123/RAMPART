# Vulnerability: OKIOK S-Filer Portal Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`okiok-sfiler-portal.yaml`)

## Description
OKIOK S-Filer Portal login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sfiler/Login.action
```

