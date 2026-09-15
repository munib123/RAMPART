# Nuclei Template: Sato - Default Login
**Template ID:** sato-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`sato-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Sato using default credentials was discovered.

## Steps to reproduce / Exploit Payload
```http
POST /WebConfig/lua/auth.lua HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: {{BaseURL}}

group={{username}}&pw={{password}}
```

