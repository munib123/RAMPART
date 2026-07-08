# Vulnerability: Apache ActiveMQ Artemis Console Default Login
**Classification:** APACHE
**Source:** Nuclei Template (`activemq-artemis-default-login.yaml`)

## Description
Detected Apache ActiveMQ Artemis console default login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/console/auth/login
```

