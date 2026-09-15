# Nuclei Template: Guacamole Default Login
**Template ID:** guacamole-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`guacamole-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Guacamole default admin login credentials were detected.

## Steps to reproduce / Exploit Payload
```http
POST /api/tokens HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Origin: {{Hostname}}
Referer: {{Hostname}}

username={{username}}&password={{password}}
```

## References
- https://wiki.debian.org/Guacamole#:~:text=You%20can%20now%20access%20the,password%20are%20both%20%22guacadmin%22
