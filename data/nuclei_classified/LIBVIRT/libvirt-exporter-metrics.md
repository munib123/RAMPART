# Vulnerability: Libvirt Exporter Metrics
**Classification:** LIBVIRT
**Source:** Nuclei Template (`libvirt-exporter-metrics.yaml`)

## Description
Libvirt Exporter is leaking metrics.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/metrics
```

