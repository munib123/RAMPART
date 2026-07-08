# Vulnerability: Detect Haproxy Exporter
**Classification:** HAPROXY
**Source:** Nuclei Template (`haproxy-exporter-metrics.yaml`)

## Description
Haproxy metrics is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/metrics
```

