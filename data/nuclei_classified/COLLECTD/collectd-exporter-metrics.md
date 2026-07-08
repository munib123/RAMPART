# Vulnerability: Collectd Exporter Metrics
**Classification:** COLLECTD
**Source:** Nuclei Template (`collectd-exporter-metrics.yaml`)

## Description
Collectd Exporter Metrics is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/metrics
```

