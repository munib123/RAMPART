# Vulnerability: Kettle - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`kettle-default-login.yaml`)

## Description
Kettle contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

