# Vulnerability: NPS Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`nps-default-login.yaml`)

## Description
NPS default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login/verify HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: {{Hostname}}/login/index

username={{username}}&password={{password}}
```

