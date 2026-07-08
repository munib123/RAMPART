# Vulnerability: Grafana Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`grafana-default-login.yaml`)

## Description
Grafana default admin login credentials were detected.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Referer: {{BaseURL}}
content-type: application/json

{"user":"{{username}}","password":"{{password}}"}
```

