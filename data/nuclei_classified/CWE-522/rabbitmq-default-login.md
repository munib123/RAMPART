# Vulnerability: RabbitMQ Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`rabbitmq-default-login.yaml`)

## Description
RabbitMQ default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /api/whoami HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Authorization: Basic {{base64(username + ':' + password)}}
```

