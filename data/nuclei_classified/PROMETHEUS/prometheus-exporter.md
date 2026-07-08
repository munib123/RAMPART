# Vulnerability: Prometheus exporter detect
**Classification:** PROMETHEUS
**Source:** Nuclei Template (`prometheus-exporter.yaml`)

## Description
Prometheus exporter detector

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

