# Nuclei Template: OpenCATS - Default Login
**Template ID:** opencats-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`opencats-default-login.yaml`)

## Vulnerability Information & PoC

## Description
OpenCATS contains a default admin login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST /index.php?m=login&a=attemptLogin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}
```

