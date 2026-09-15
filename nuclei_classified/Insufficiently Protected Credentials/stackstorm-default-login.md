# Nuclei Template: StackStorm Default Login
**Template ID:** stackstorm-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`stackstorm-default-login.yaml`)

## Vulnerability Information & PoC

## Description
A StackStorm default admin login was discovered.

## Steps to reproduce / Exploit Payload
```http
POST /auth/tokens HTTP/1.1
Host: {{BaseURL}}
Content-Type: application/json
Authorization: Basic {{base64(username + ':' + password)}}
```

## References
- https://github.com/StackStorm/st2-docker
