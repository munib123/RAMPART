# Nuclei Template: Wildfly - Default Admin Login
**Template ID:** wildfly-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`wildfly-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Wildfly default admin login credentials were successful.

## Steps to reproduce / Exploit Payload
```http
GET /management HTTP/1.1
Host: {{Hostname}}
```

## References
- https://docs.wildfly.org/26.1/#administrator-guides
