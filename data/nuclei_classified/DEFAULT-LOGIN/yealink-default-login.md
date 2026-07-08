# Vulnerability: Yealink CTP18 - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`yealink-default-login.yaml`)

## Description
Yealink CTP18 Default Administrator Credentials Discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/auth/login?p=Login&t=1 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Accept: application/json, text/plain, */*

username={{username}}&pwd={{password}}
```

