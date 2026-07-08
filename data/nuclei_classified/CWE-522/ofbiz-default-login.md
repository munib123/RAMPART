# Vulnerability: Apache OfBiz Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`ofbiz-default-login.yaml`)

## Description
Apache OfBiz default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /control/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

USERNAME={{username}}&PASSWORD={{password}}&FTOKEN=&JavaScriptEnabled=Y
```

