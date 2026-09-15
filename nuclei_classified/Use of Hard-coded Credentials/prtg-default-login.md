# Nuclei Template: PRTG Network Monitor - Hardcoded Credentials
**Template ID:** prtg-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`prtg-default-login.yaml`)

## Vulnerability Information & PoC

## Description
PRTG Network Monitor contains a hardcoded credential vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST /public/checklogin.htm HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

loginurl=&username={{username}}&password={{password}}
```

## References
- https://www.paessler.com/manuals/prtg/login
