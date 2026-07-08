# Vulnerability: Datagerry - Default Login
**Classification:** DATAGERRY
**Source:** Nuclei Template (`datagerry-default-login.yaml`)

## Description
Datagerry was using default username and password was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /rest/auth/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"user_name":"{{username}}","password":"{{password}}"}
```

