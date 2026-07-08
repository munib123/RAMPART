# Vulnerability: ASUS RT-N16 - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`asus-rtn16-default-login.yaml`)

## Description
ASUS RT-N16 contains a default login vulnerability. Default admin login password 'admin' was found.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

