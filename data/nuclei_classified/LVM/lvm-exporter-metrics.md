# Vulnerability: LVM Exporter Metrics
**Classification:** LVM
**Source:** Nuclei Template (`lvm-exporter-metrics.yaml`)

## Description
LVM Exporter Metrics is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/metrics
```

