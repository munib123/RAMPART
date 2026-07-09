# Nuclei Template: Unauthenticated Spark REST API
**Template ID:** unauth-spark-api
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`unauth-spark-api.yaml`)

## Vulnerability Information & PoC

## Description
The Spark product's REST API interface allows access to unauthenticated users.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/v1/submissions
```

## Remediation
Restrict access the exposed API ports.

## References
- https://xz.aliyun.com/t/2490
