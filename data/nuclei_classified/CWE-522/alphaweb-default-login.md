# Vulnerability: AlphaWeb XE Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`alphaweb-default-login.yaml`)

## Description
An AlphaWeb XE default login was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /php/node_info.php HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
Referer: {{BaseURL}}
```

