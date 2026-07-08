# Vulnerability: Glowroot Anonymous User
**Classification:** MISCONFIG
**Source:** Nuclei Template (`unauthenticated-glowroot.yaml`)

## Description
Anonymous user access allows to understand the host internals

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/backend/admin/users?username=anonymous
```

