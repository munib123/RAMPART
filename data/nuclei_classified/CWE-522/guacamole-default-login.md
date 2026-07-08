# Vulnerability: Guacamole Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`guacamole-default-login.yaml`)

## Description
Guacamole default admin login credentials were detected.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/tokens HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Origin: {{Hostname}}
Referer: {{Hostname}}

username={{username}}&password={{password}}
```

