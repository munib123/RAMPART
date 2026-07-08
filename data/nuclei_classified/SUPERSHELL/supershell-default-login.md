# Vulnerability: Supershell - Default Login
**Classification:** SUPERSHELL
**Source:** Nuclei Template (`supershell-default-login.yaml`)

## Description
Supershell is a WEB management platform that integrates the reverse_ssh service.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /supershell/login/auth HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}"}
```

