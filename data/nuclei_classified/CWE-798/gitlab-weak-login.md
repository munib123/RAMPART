# Vulnerability: Gitlab Default Login
**Classification:** CWE-798
**Source:** Nuclei Template (`gitlab-weak-login.yaml`)

## Description
Gitlab default login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /oauth/token HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/plain, */*
Referer: {{BaseURL}}
content-type: application/json

{"grant_type":"password","username":"{{username}}","password":"{{password}}"}
```

