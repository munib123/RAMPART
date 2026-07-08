# Vulnerability: ASUS WL-520GU - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`asus-wl520GU-default-login.yaml`)

## Description
ASUS WL-520GU contains a default login vulnerability. The default admin login password 'admin' was found.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

