# Nuclei Template: ToolJet - Default Login
**Template ID:** tooljet-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`tooljet-default-login.yaml`)

## Vulnerability Information & PoC

## Description
ToolJet contains a default login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST /api/authenticate HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"email":"{{username}}","password":"{{password}}"}
```

## References
- https://docs.tooljet.com/docs/contributing-guide/setup/docker/
