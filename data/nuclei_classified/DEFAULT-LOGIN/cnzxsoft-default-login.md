# Vulnerability: Cnzxsoft System - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`cnzxsoft-default-login.yaml`)

## Description
Cnzxsoft Golden Shield Information Security Management System has a default weak password.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /?q=common/login  HTTP/1.1
Host: {{Hostname}}
Cookie: check_code=ptbh
Content-Type: application/x-www-form-urlencoded

name={{username}}&password={{password}}&checkcode=ptbh&doLoginSubmit=1
```

