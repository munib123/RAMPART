# Vulnerability: ipTIME Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`iptime-default-login.yaml`)

## Description
ipTIME default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /sess-bin/login_handler.cgi HTTP/1.1
Host: {{Hostname}}
Referer: {{BaseURL}}/sess-bin/login_session.cgi

username={{username}}&passwd={{password}}
```

