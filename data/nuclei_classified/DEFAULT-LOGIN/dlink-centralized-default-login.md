# Vulnerability: D-Link AC Centralized Management System - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`dlink-centralized-default-login.yaml`)

## Description
D-Link AC Centralized Management System default login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login.cgi  HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

user={{username}}&password={{password}}
```

