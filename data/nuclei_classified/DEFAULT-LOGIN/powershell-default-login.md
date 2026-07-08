# Vulnerability: PowerShell Universal - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`powershell-default-login.yaml`)

## Description
PowerShell Universal default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/v1/signin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}"}
```

