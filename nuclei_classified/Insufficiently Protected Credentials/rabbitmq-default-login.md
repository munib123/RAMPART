# Nuclei Template: RabbitMQ Default Login
**Template ID:** rabbitmq-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`rabbitmq-default-login.yaml`)

## Vulnerability Information & PoC

## Description
RabbitMQ default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
GET /api/whoami HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Authorization: Basic {{base64(username + ':' + password)}}
```

## References
- https://onlinehelp.coveo.com/en/ces/7.0/administrator/changing_the_rabbitmq_administrator_password.htm
