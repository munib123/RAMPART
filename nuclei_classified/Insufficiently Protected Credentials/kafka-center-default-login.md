# Nuclei Template: Apache Kafka Center Default Login
**Template ID:** kafka-center-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`kafka-center-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Apache Kafka Center default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /login/system HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"name":"{{username}}","password":"{{password}}","checkbox":false}
```

## References
- https://developer.ibm.com/tutorials/kafka-authn-authz/
