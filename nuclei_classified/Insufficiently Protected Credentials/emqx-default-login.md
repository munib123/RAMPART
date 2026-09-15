# Nuclei Template: Emqx Default Admin Login
**Template ID:** emqx-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`emqx-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Emqx default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST {{path}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}"}
```

