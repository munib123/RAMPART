# Nuclei Template: PowerShell Universal - Default Login
**Template ID:** powershell-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`powershell-default-login.yaml`)

## Vulnerability Information & PoC

## Description
PowerShell Universal default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /api/v1/signin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}"}
```

## References
- https://ironmansoftware.com/powershell-universal
