# Vulnerability: OpenCATS - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`opencats-default-login.yaml`)

## Description
OpenCATS contains a default admin login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /index.php?m=login&a=attemptLogin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}
```

