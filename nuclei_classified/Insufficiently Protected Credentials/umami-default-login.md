# Nuclei Template: Umami Default Login
**Template ID:** umami-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`umami-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Umami default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /api/auth/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json; charset=utf-8

{"username":"{{username}}","password":"{{password}}"}
```

## References
- https://umami.is/docs/login
