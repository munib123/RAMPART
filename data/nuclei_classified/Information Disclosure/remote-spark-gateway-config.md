# Nuclei Template: Remote Spark Gateway Configuration/Credentials - Exposure
**Template ID:** remote-spark-gateway-config
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`remote-spark-gateway-config.yaml`)

## Vulnerability Information & PoC

## Description
Remote Spark Gateway config found via /gateway.conf.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/gateway.conf
```

## References
- https://docs.sparkview.info/books/sparkview-admin-manual/page/31-gateway
