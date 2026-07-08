# Vulnerability: Emqx Default Admin Login
**Classification:** CWE-522
**Source:** Nuclei Template (`emqx-default-login.yaml`)

## Description
Emqx default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{path}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}"}
```

