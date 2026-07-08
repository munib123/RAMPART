# Vulnerability: Sato - Default Login
**Classification:** SATO
**Source:** Nuclei Template (`sato-default-login.yaml`)

## Description
Sato using default credentials was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /WebConfig/lua/auth.lua HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: {{BaseURL}}

group={{username}}&pw={{password}}
```

