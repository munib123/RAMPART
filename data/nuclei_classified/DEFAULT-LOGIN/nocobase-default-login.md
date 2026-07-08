# Vulnerability: NocoBase - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`nocobase-default-login.yaml`)

## Description
NocoBase default login was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{path}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"account": "{{username}}", "password": "{{password}}"}
```

