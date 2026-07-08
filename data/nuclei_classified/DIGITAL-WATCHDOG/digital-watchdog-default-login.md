# Vulnerability: Digital Watchdog - Default Login
**Classification:** DIGITAL-WATCHDOG
**Source:** Nuclei Template (`digital-watchdog-default-login.yaml`)

## Description
Digital Watchdog default login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /web/rest/v1/login/sessions HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{user}}","password":"{{pass}}","setCookie":true}
```

