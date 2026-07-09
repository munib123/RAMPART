# Nuclei Template: Alibaba Canal Default Login
**Template ID:** canal-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`canal-default-login.yaml`)

## Vulnerability Information & PoC

## Description
An Alibaba Canal default login was discovered.

## Steps to reproduce / Exploit Payload
```http
POST /api/v1/user/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"username":"{{user}}","password":"{{pass}}"}
```

## References
- https://github.com/alibaba/canal/wiki/ClientAdapter
