# Nuclei Template: Redis Exporter Metrics - Exposure
**Template ID:** redis-exporter-metrics
**Vulnerability Class:** Information Disclosure
**Severity:** Low
**CWE:** CWE-200
**Source:** Nuclei Template (`redis-exporter-metrics.yaml`)

## Vulnerability Information & PoC

## Description
Redis Exporter metrics endpoint is exposed.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/metrics
```

## References
- https://github.com/oliver006/redis_exporter
