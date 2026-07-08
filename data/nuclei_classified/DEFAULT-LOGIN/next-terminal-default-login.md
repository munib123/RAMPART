# Vulnerability: Next Terminal - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`next-terminal-default-login.yaml`)

## Description
Next Terminal default login was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}","remember":false}
```

