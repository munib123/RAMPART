# Vulnerability: Thanos Prometheus Setup - Exposure
**Classification:** THANOS
**Source:** Nuclei Template (`thanos-prometheus-exposure.yaml`)

## Description
Thanos graph endpoint was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/graph
GET {{BaseURL}}/classic/graph
```

