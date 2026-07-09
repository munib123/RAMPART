# Nuclei Template: Apache ActiveMQ Artemis Console Default Login
**Template ID:** activemq-artemis-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`activemq-artemis-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detected Apache ActiveMQ Artemis console default login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST {{BaseURL}}/console/auth/login
```

## References
- https://activemq.apache.org/components/artemis/documentation/latest/management-console.html
