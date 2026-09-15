# Nuclei Template: MongoDB Exporter - Detect
**Template ID:** mongodb-exporter-metrics
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`mongodb-exporter-metrics.yaml`)

## Vulnerability Information & PoC

## Description
MongoDB exporter was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/metrics
```

## References
- https://github.com/percona/mongodb_exporter
