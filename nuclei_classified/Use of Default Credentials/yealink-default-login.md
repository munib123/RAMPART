# Nuclei Template: Yealink CTP18 - Default Login
**Template ID:** yealink-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`yealink-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Yealink CTP18 Default Administrator Credentials Discovered.

## Steps to reproduce / Exploit Payload
```http
POST /api/auth/login?p=Login&t=1 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Accept: application/json, text/plain, */*

username={{username}}&pwd={{password}}
```

## References
- https://support.yealink.com
