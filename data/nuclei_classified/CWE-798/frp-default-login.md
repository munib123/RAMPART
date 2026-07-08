# Vulnerability: FRP Default Login
**Classification:** CWE-798
**Source:** Nuclei Template (`frp-default-login.yaml`)

## Description
FRP default login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /api/proxy/tcp HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

