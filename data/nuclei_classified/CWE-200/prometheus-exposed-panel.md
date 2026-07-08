# Vulnerability: Prometheus Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`prometheus-exposed-panel.yaml`)

## Description
Prometheus panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/graph
GET {{BaseURL}}/prometheus/graph
```

