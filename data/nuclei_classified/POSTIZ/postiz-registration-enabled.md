# Vulnerability: Postiz - User Registration Enabled
**Classification:** POSTIZ
**Source:** Nuclei Template (`postiz-registration-enabled.yaml`)

## Description
Postiz registration page is exposed and allows public account creation. Unrestricted registration may allow unauthorized users to create accounts.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth
```

