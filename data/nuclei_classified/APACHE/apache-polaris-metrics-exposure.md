# Vulnerability: Apache Polaris - Information Disclosure
**Classification:** APACHE
**Source:** Nuclei Template (`apache-polaris-metrics-exposure.yaml`)

## Description
Detects a Apache Polaris server, the interoperable, open source catalog for Apache Iceberg.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/q/metrics
```

