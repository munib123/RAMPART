# Vulnerability: Grav Register Admin User - Detect
**Classification:** GRAV
**Source:** Nuclei Template (`grav-register-admin.yaml`)

## Description
Exposed Grav admin user register page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin
```

