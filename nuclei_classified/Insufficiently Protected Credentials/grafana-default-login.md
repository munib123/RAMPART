# Nuclei Template: Grafana Default Login
**Template ID:** grafana-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`grafana-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Grafana default admin login credentials were detected.

## Steps to reproduce / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Referer: {{BaseURL}}
content-type: application/json

{"user":"{{username}}","password":"{{password}}"}
```

## References
- https://grafana.com/docs/grafana/latest/administration/configuration/#disable_brute_force_login_protection
- https://stackoverflow.com/questions/54039604/what-is-the-default-username-and-password-for-grafana-login-page
- https://github.com/grafana/grafana/issues/14755
