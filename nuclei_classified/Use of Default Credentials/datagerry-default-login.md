# Nuclei Template: Datagerry - Default Login
**Template ID:** datagerry-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`datagerry-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Datagerry was using default username and password was discovered.

## Steps to reproduce / Exploit Payload
```http
POST /rest/auth/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"user_name":"{{username}}","password":"{{password}}"}
```

