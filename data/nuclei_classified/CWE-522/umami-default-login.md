# Vulnerability: Umami Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`umami-default-login.yaml`)

## Description
Umami default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/auth/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json; charset=utf-8

{"username":"{{username}}","password":"{{password}}"}
```

