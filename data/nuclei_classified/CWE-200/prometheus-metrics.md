# Vulnerability: Prometheus Metrics - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`prometheus-metrics.yaml`)

## Description
Prometheus metrics page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/metrics
GET {{BaseURL}}/api/metrics
```

