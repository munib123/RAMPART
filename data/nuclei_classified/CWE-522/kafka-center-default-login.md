# Vulnerability: Apache Kafka Center Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`kafka-center-default-login.yaml`)

## Description
Apache Kafka Center default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login/system HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"name":"{{username}}","password":"{{password}}","checkbox":false}
```

