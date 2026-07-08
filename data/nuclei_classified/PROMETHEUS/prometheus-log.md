# Vulnerability: Exposed Prometheus
**Classification:** PROMETHEUS
**Source:** Nuclei Template (`prometheus-log.yaml`)

## Description
Prometheus instance is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/prometheus
GET {{BaseURL}}/actuator/prometheus
GET {{BaseURL}}/actuator/prometheus;%2f..%2f..%2f
```

