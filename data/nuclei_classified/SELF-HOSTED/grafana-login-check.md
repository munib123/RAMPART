# Vulnerability: Grafana Login Check
**Classification:** SELF-HOSTED
**Source:** Nuclei Template (`grafana-login-check.yaml`)

## Description
Checks for a valid login on self hosted Grafana instance.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}
accept: application/json, text/plain, */*
DNT: 1
content-type: application/json
Origin: {{BaseURL}}
Referer: {{BaseURL}}/login
Cookie: redirect_to=%2F

{"user":"{{username}}","password":"{{password}}"}
```

