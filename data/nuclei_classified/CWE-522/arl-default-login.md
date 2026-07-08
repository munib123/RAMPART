# Vulnerability: ARL Default Admin Login
**Classification:** CWE-522
**Source:** Nuclei Template (`arl-default-login.yaml`)

## Description
An ARL default admin login was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/user/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json; charset=UTF-8

{"username":"{{username}}","password":"{{password}}"}
```

