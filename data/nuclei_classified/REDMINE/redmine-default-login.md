# Vulnerability: Redmine - Default Admin Credentials
**Classification:** REDMINE
**Source:** Nuclei Template (`redmine-default-login.yaml`)

## Description
Detected Redmine project management application was found to have been using the default administrator credentials (admin:admin). An attacker could have gained full administrative access to manage projects, users, and system settings.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /login HTTP/1.1
Host: {{Hostname}}

POST /login HTTP/1.1
Host: {{Hostname}}
Cookie: {{session}}

authenticity_token={{url_encode(csrf_token)}}&username={{username}}&password={{password}}&login=Login
```

