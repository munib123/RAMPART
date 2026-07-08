# Vulnerability: Appsmith User Login - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`appsmith-web-login.yaml`)

## Description
Appsmith user login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/user/login
```

