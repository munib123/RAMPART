# Vulnerability: MySQL Exporter Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mysqld-exporter-metrics.yaml`)

## Description
MYSQL Exporter panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/metrics
```

