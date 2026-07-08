# Vulnerability: Versa Director Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`versa-director-login.yaml`)

## Description
Versa Director login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/versa/login
```

