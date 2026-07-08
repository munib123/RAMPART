# Vulnerability: Coolify Register User Account - Enabled
**Classification:** COOLIFY
**Source:** Nuclei Template (`coolify-register-account.yaml`)

## Description
Exposed Coolify user register page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/register
```

