# Vulnerability: Postgres Exporter Metrics
**Classification:** POSTGRES
**Source:** Nuclei Template (`postgres-exporter-metrics.yaml`)

## Description
Postgres Exporter Metrics is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/metrics
```

