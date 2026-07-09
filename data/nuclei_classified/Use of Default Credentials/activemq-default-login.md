# Nuclei Template: Apache ActiveMQ Default Login
**Template ID:** activemq-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`activemq-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Apache ActiveMQ default login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
GET /admin/ HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

## References
- https://github.com/apache/activemq-artemis/
