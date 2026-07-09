# Nuclei Template: Dragonfly - Default Login
**Template ID:** dragonfly-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`dragonfly-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Dragonfly was using the default username, and the password was discovered.

## Steps to reproduce / Exploit Payload
```http
POST /api/v1/users/signin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json;charset=UTF-8

{"name":"{{username}}","password":"{{password}}"}
```

