# Vulnerability: MongoDB Exporter - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mongodb-exporter-metrics.yaml`)

## Description
MongoDB exporter was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/metrics
```

