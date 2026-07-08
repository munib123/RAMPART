# Vulnerability: Lutron - Default Account
**Classification:** CWE-1391
**Source:** Nuclei Template (`lutron-default-login.yaml`)

## Description
Multiple Lutron devices contain a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login?login={{username}}&password={{password}}
```

