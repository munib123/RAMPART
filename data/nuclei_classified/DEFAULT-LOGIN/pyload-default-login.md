# Vulnerability: PyLoad Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`pyload-default-login.yaml`)

## Description
PyLoad Default Credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

do=login&username={{username}}&password={{password}}&submit=Login
```

