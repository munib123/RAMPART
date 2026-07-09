# Nuclei Template: Supershell - Default Login
**Template ID:** supershell-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`supershell-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Supershell is a WEB management platform that integrates the reverse_ssh service.

## Steps to reproduce / Exploit Payload
```http
POST /supershell/login/auth HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}"}
```

## References
- https://github.com/tdragon6/Supershell
- https://www.ctfiot.com/129689.html
