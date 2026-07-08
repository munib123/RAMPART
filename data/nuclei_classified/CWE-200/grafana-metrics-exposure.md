# Vulnerability: Grafana Metrics Endpoint - Information Disclosure
**Classification:** CWE-200
**Source:** Nuclei Template (`grafana-metrics-exposure.yaml`)

## Description
Detected Grafana metrics endpoint exposed without authentication revealed sensitive infrastructure information, including version, edition, user counts, dashboard statistics, datasources, and database connection details.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/metrics
```

