# Nuclei Template: Apache Zeppelin - Unauthenticated Access
**Template ID:** apache-zeppelin-unauth
**Vulnerability Class:** Improper Authorization
**Severity:** High
**CWE:** CWE-285
**Source:** Nuclei Template (`apache-zeppelin-unauth.yaml`)

## Vulnerability Information & PoC

## Description
Apache Zeppelin server was able to be accessed because no authentication was required.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/api/security/ticket
```

## References
- https://www.adminxe.com/2172.html
