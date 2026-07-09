# Nuclei Template: Lutron - Default Account
**Template ID:** lutron-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** Critical
**CWE:** CWE-1391
**Source:** Nuclei Template (`lutron-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Multiple Lutron devices contain a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/login?login={{username}}&password={{password}}
```

## References
- https://www.lutron.com
- https://vulners.com/openvas/OPENVAS:1361412562310113206
