# Vulnerability: Adobe Connect Central Login Panel
**Classification:** CWE-200
**Source:** Nuclei Template (`adobe-connect-central-login.yaml`)

## Description
An Adobe Connect Central login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/system/login
```

