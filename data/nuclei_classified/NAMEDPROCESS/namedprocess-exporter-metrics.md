# Vulnerability: Named Process Exporter
**Classification:** NAMEDPROCESS
**Source:** Nuclei Template (`namedprocess-exporter-metrics.yaml`)

## Description
Named process exporter is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/metrics
```

