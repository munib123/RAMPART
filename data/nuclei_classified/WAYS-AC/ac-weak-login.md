# Vulnerability: AC Centralized Management System - Default password
**Classification:** WAYS-AC
**Source:** Nuclei Template (`ac-weak-login.yaml`)

## Description
AC Centralized Management System default login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

user={{username}}&password={{ password }}&Submit=%E7%99%BB%E5%BD%95
```

