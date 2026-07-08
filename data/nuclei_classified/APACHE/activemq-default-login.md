# Vulnerability: Apache ActiveMQ Default Login
**Classification:** APACHE
**Source:** Nuclei Template (`activemq-default-login.yaml`)

## Description
Apache ActiveMQ default login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /admin/ HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

