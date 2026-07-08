# Vulnerability: X-UI - Default Login
**Classification:** CWE-798
**Source:** Nuclei Template (`xui-default-login.yaml`)

## Description
X-UI contains default credentials. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
POST {{BaseURL}}/login
```

