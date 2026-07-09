# Nuclei Template: Grafana Metrics Endpoint - Information Disclosure
**Template ID:** grafana-metrics-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** Low
**CWE:** CWE-200
**Source:** Nuclei Template (`grafana-metrics-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Detected Grafana metrics endpoint exposed without authentication revealed sensitive infrastructure information, including version, edition, user counts, dashboard statistics, datasources, and database connection details.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/metrics
```

## References
- https://grafana.com/docs/grafana/latest/setup-grafana/set-up-grafana-monitoring/
- https://hackerone.com/reports/1448218
