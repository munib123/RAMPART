# Nuclei Template: D-Link AC Centralized Management System - Default Login
**Template ID:** dlink-centralized-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`dlink-centralized-default-login.yaml`)

## Vulnerability Information & PoC

## Description
D-Link AC Centralized Management System default login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /login.cgi  HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

user={{username}}&password={{password}}
```

