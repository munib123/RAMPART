# Vulnerability: Redis Exporter Metrics - Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`redis-exporter-metrics.yaml`)

## Description
Redis Exporter metrics endpoint is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/metrics
```

