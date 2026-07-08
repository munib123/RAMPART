# Vulnerability: StackStorm Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`stackstorm-default-login.yaml`)

## Description
A StackStorm default admin login was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /auth/tokens HTTP/1.1
Host: {{BaseURL}}
Content-Type: application/json
Authorization: Basic {{base64(username + ':' + password)}}
```

