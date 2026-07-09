# Nuclei Template: AlphaWeb XE Default Login
**Template ID:** alphaweb-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** Medium
**CWE:** CWE-522
**Source:** Nuclei Template (`alphaweb-default-login.yaml`)

## Vulnerability Information & PoC

## Description
An AlphaWeb XE default login was discovered.

## Steps to reproduce / Exploit Payload
```http
GET /php/node_info.php HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
Referer: {{BaseURL}}
```

## References
- https://wiki.zenitel.com/wiki/AlphaWeb
