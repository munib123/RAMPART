# Nuclei Template: Prometheus Metrics - Detect
**Template ID:** prometheus-metrics
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`prometheus-metrics.yaml`)

## Vulnerability Information & PoC

## Description
Prometheus metrics page was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/metrics
GET {{BaseURL}}/api/metrics
```

## References
- https://github.com/prometheus/prometheus
- https://hackerone.com/reports/1026196
