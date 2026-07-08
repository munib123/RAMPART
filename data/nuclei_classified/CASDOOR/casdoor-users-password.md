# Vulnerability: Casdoor get-users Account Password Disclosure
**Classification:** CASDOOR
**Source:** Nuclei Template (`casdoor-users-password.yaml`)

## Description
Casdoor get-users Account Password is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/get-users?p=123&pageSize=123
```

