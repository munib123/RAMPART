# Nuclei Template: Apache Dubbo - Default Admin Discovery
**Template ID:** dubbo-admin-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`dubbo-admin-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Apache Dubbo default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/
```

## References
- https://www.cnblogs.com/wishwzp/p/9438658.html
