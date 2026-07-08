# Vulnerability: Rocket LMS - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`rocketlms-default-login.yaml`)

## Description
Rocket LMS default credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
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

