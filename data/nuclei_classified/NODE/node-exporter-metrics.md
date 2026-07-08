# Vulnerability: Detect Node Exporter Metrics
**Classification:** NODE
**Source:** Nuclei Template (`node-exporter-metrics.yaml`)

## Description
Information Disclosure of Garbage Collection

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/metrics
```

