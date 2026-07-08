# Vulnerability: RustDesk Web Client - Default login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`rustdesk-webclient-default-login.yaml`)

## Description
Detected RustDesk Web Client Admin Console was using default credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/admin/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}","platform":"windows","captcha":"","captcha_id":""}
```

