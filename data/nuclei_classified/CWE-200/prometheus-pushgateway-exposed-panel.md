# Vulnerability: Prometheus Pushgateway Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`prometheus-pushgateway-exposed-panel.yaml`)

## Description
Prometheus Pushgateway panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

